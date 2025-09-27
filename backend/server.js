const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const multer = require('multer');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const CRC32 = require('crc-32');
const cors = require('cors');
const bodyParser = require('body-parser');
const bcrypt = require('bcrypt');
const session = require('express-session');
const db = require('./db');

const APP_ROOT = __dirname;
const UPLOAD_ROOT = path.join(APP_ROOT, 'uploads');
if (!fs.existsSync(UPLOAD_ROOT)) fs.mkdirSync(UPLOAD_ROOT, { recursive: true });

const app = express();

// Add CORS middleware with credentials enabled
app.use(cors({
  origin: 'http://localhost:3000', // adjust to your frontend url
  credentials: true
}));

app.use(bodyParser.json({ limit: '200mb' }));
app.use(bodyParser.urlencoded({ extended: true }));

// Adjust session cookie for proper persistence and security
app.use(session({
  secret: 'lightshare-demo-secret',
  resave: false,
  saveUninitialized: false,
  cookie: {
    maxAge: 24 * 3600 * 1000,
    httpOnly: true,
    sameSite: 'lax'
  }
}));

app.use('/', express.static(path.join(__dirname, 'public')));

const server = http.createServer(app);
const io = new Server(server, { cors: { origin: "*", methods: ["GET","POST"] } });


const storage = multer.memoryStorage();
const upload = multer({ storage });


// In-memory stores
const WORKSPACES = {};   // room -> { creator, members:Set, transfers:Set, active }
const TRANSFERS = {};    // id -> info
const USERSOCK = {};     // username -> socketId
const ACK_TIMERS = {};   // transferId -> timeout


// ---------- helpers ----------
function ensureDir(d){ if(!fs.existsSync(d)) fs.mkdirSync(d, { recursive: true }); }


function encryptAesGcm(buffer){
  const key = crypto.randomBytes(32);
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const encrypted = Buffer.concat([cipher.update(buffer), cipher.final()]);
  const tag = cipher.getAuthTag();
  const payload = Buffer.concat([encrypted, tag]);
  return { payloadB64: payload.toString('base64'), keyB64: key.toString('base64'), ivB64: iv.toString('base64') };
}
function decryptAesGcm(payloadB64, keyB64, ivB64){
  const payload = Buffer.from(payloadB64, 'base64');
  const key = Buffer.from(keyB64, 'base64');
  const iv = Buffer.from(ivB64, 'base64');
  const tag = payload.slice(payload.length - 16);
  const encrypted = payload.slice(0, payload.length - 16);
  const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(encrypted), decipher.final()]);
}


// Hamming (7,4) encode/decode (kept your original logic)
function encodeNibbleTo7(n){
  const d0=(n>>0)&1,d1=(n>>1)&1,d2=(n>>2)&1,d3=(n>>3)&1;
  const p0=d0^d1^d3,p1=d0^d2^d3,p2=d1^d2^d3;
  const bits=[p0,p1,d0,p2,d1,d2,d3];
  let val=0; for(let i=0;i<bits.length;i++) val |= (bits[i] << (6-i));
  return val & 0x7F;
}
function hammingEncodeBuffer(buf){
  const out = Buffer.alloc(buf.length*2);
  for(let i=0;i<buf.length;i++){
    const b = buf[i];
    out[i*2] = encodeNibbleTo7((b>>4)&0xF);
    out[i*2+1] = encodeNibbleTo7(b&0xF);
  }
  return out;
}
function decode7ToNibble(val){
  const bits=[]; for(let i=6;i>=0;i--) bits.push((val>>i)&1);
  let [p0,p1,d0,p2,d1,d2,d3] = bits;
  const s0 = p0 ^ d0 ^ d1 ^ d3;
  const s1 = p1 ^ d0 ^ d2 ^ d3;
  const s2 = p2 ^ d1 ^ d2 ^ d3;
  const syndrome = (s0<<2)|(s1<<1)|s2;
  if(syndrome !== 0){
    const idx = syndrome - 1;
    bits[idx] = bits[idx] ^ 1;
    [p0,p1,d0,p2,d1,d2,d3] = bits;
  }
  return { nibble: (d3<<3)|(d2<<2)|(d1<<1)|d0 };
}
function hammingDecodeBuffer(encBuf){
  const out = Buffer.alloc(encBuf.length/2);
  for(let i=0;i<encBuf.length;i+=2){
    const hi = decode7ToNibble(encBuf[i] & 0x7F).nibble;
    const lo = decode7ToNibble(encBuf[i+1] & 0x7F).nibble;
    out[i/2] = (hi<<4) | lo;
  }
  return { data: out };
}


function mimeFor(meta){
  if(meta.ftype === 'pdf') return 'application/pdf';
  if(meta.ftype === 'image'){
    const ext = path.extname(meta.originalName||'').toLowerCase();
    if(ext==='.png') return 'image/png';
    if(ext==='.jpg' || ext==='.jpeg') return 'image/jpeg';
    return 'application/octet-stream';
  }
  if(meta.ftype === 'video') return 'video/mp4';
  return 'application/octet-stream';
}


// ACK timer / retransmit (kept your behavior)
function startAckTimer(id){
  clearAckTimer(id);
  ACK_TIMERS[id] = setTimeout(()=>{ console.log('ACK timeout, retransmit', id); retransmit(id); }, 2*60*1000);
}
function clearAckTimer(id){
  if(ACK_TIMERS[id]){ clearTimeout(ACK_TIMERS[id]); delete ACK_TIMERS[id]; }
}
function retransmit(id){
  const info = TRANSFERS[id]; if(!info) return;
  try{
    const original = fs.readFileSync(path.join(info.dir,'original.bin'));
    let processed = original;
    if(info.meta.ftype === 'image') processed = hammingEncodeBuffer(original);
    const enc = encryptAesGcm(processed);
    fs.writeFileSync(path.join(info.dir,'encrypted.b64'), enc.payloadB64);
    info.payloadB64 = enc.payloadB64; info.keyB64 = enc.keyB64; info.ivB64 = enc.ivB64;
    info.attempts = (info.attempts||0) + 1; info.status = 'retransmitted';
    // re-emit (if 'all' or to specific recipient)
    if(info.recipient === 'all') {
      io.to(info.room).emit('fileIncoming', { transferId: id, filename: info.meta.originalName, sender: info.sender, ftype: info.meta.ftype, room: info.room, recipient: 'all', retransmit: true });
    } else {
      if(USERSOCK[info.recipient]) io.to(USERSOCK[info.recipient]).emit('fileIncoming', { transferId: id, filename: info.meta.originalName, sender: info.sender, ftype: info.meta.ftype, room: info.room, recipient: info.recipient, retransmit: true });
    }
    if((info.attempts||0) < 6) startAckTimer(id);
  }catch(e){ console.error('retransmit error', e); }
}


// ---------- DB helpers ----------
function createUser(username, passwordHash){
  return new Promise((resolve,reject)=>{
    db.run('INSERT INTO users (username,password) VALUES (?,?)', [username,passwordHash], function(err){
      if(err) return reject(err);
      resolve({ id:this.lastID, username });
    });
  });
}
function findUser(username){
  return new Promise((resolve,reject)=>{
    db.get('SELECT id,username,password FROM users WHERE username=?', [username], (err,row)=>{
      if(err) return reject(err);
      resolve(row);
    });
  });
}


// backend/server.js
// ... your existing imports ...
// (same as you pasted, just showing modified signup/login)


app.post('/api/signup', async (req,res)=>{
  try{
    const { user, pass } = req.body;
    if(!user||!pass) return res.status(400).json({ error:'missing' });
    const existing = await findUser(user);
    if(existing) return res.status(400).json({ error:'exists' });
    const hash = await bcrypt.hash(pass, 10);
    await createUser(user, hash);
    req.session.user = user; // auto-login
    return res.json({ ok:true, user });
  }catch(e){
    console.error('signup err', e);
    return res.status(500).json({ error:'server' });
  }
});


app.post('/api/login', async (req,res)=>{
  try{
    const { user, pass } = req.body;
    if(!user||!pass) return res.status(400).json({ error:'missing' });
    const row = await findUser(user);
    if(!row) return res.status(400).json({ error:'no_user' });


    const stored = row.password || '';
    let ok = false;
    try {
      if(stored.startsWith('$2')) ok = await bcrypt.compare(pass, stored);
      else ok = (pass === stored);
    } catch(e) { ok = false; }


    if(!ok) return res.status(400).json({ error:'bad_pass' });
    req.session.user = user;
    return res.json({ ok:true, user });
  }catch(e){
    console.error('login err', e);
    return res.status(500).json({ error:'server' });
  }
});



function requireLogin(req,res,next){ if(req.session && req.session.user) return next(); return res.status(401).json({ error:'auth' }); }


// ---------- Workspace endpoints ----------
app.post('/api/create-workspace', requireLogin, (req,res)=>{
  const { name } = req.body; const creator = req.session.user;
  if(!name) return res.status(400).json({ error:'missing' });


  db.get('SELECT id FROM workspaces WHERE name=?', [name], (err,row)=>{
    if(err) return res.status(500).json({ error:'db_error' });
    if(row) return res.status(400).json({ error:'exists' });


    db.run('INSERT INTO workspaces (name,creator,active) VALUES (?,?,1)', [name,creator], function(err2){
      if(err2) return res.status(500).json({ error:'db_insert' });
      WORKSPACES[name] = { creator, members: new Set([creator]), transfers: new Set(), active:true };
      return res.json({ ok:true, name, creator, members:[creator], active:true });
    });
  });
});


app.post('/api/end-workspace', requireLogin, (req,res)=>{
  const { name } = req.body; const user = req.session.user;
  const ws = WORKSPACES[name];
  if(!ws) return res.status(404).json({ error:'no_room' });
  if(ws.creator !== user) return res.status(403).json({ error:'only_creator' });
  db.run('UPDATE workspaces SET active=0 WHERE name=?', [name]);
  io.to(name).emit('workspace_ended', { room: name });
  delete WORKSPACES[name];
  return res.json({ ok:true });
});


// fetch workspace info — never returns null members
app.get('/api/workspace/:name', requireLogin, (req,res)=>{
  const { name } = req.params;
  db.get('SELECT * FROM workspaces WHERE name=? AND active=1', [name], (err,row)=>{
    if(err) return res.status(500).json({ error:'db_error' });
    if(!row) return res.status(404).json({ error:'not_found' });


    const ws = WORKSPACES[name];
    return res.json({
      name: row.name,
      creator: row.creator,
      members: ws ? Array.from(ws.members) : [],
      active: !!row.active
    });
  });
});


// ---------- Upload endpoint ----------
app.post('/api/upload', requireLogin, upload.single('file'), (req,res)=>{
  try{
    const sender = req.session.user;
    const file = req.file;
    const { recipient = 'all', room, ftype, fname } = req.body;
    if(!file) return res.status(400).json({ error:'no file' });
    if(!room) return res.status(400).json({ error:'no room' });


    // check workspace exists & active in DB (so join/upload only if workspace created)
    db.get('SELECT id,active FROM workspaces WHERE name=?', [room], (err,row)=>{
      if(err) return res.status(500).json({ error:'db_error' });
      if(!row || !row.active) return res.status(400).json({ error:'no_room' });


      if(!WORKSPACES[room]) WORKSPACES[room] = { creator: sender, members: new Set([sender]), transfers: new Set(), active:true };


      const id = crypto.randomUUID();
      const dir = path.join(UPLOAD_ROOT, id); ensureDir(dir);
      fs.writeFileSync(path.join(dir,'original.bin'), file.buffer);


      let processed = file.buffer;
      const meta = { originalName: fname || file.originalname, ftype: ftype || path.extname(file.originalname).slice(1) || 'bin' };


      if(meta.ftype === 'pdf'){
        const signed = CRC32.buf(processed) >>> 0;
        meta.crc32 = signed.toString(16).padStart(8,'0');
      } else {
        meta.sha256 = crypto.createHash('sha256').update(processed).digest('hex');
        if(meta.ftype === 'image') processed = hammingEncodeBuffer(processed);
      }


      const enc = encryptAesGcm(processed);
      fs.writeFileSync(path.join(dir,'encrypted.b64'), enc.payloadB64);
      fs.writeFileSync(path.join(dir,'meta.json'), JSON.stringify({ originalName: meta.originalName, ftype: meta.ftype, meta }, null, 2));
      fs.writeFileSync(path.join(dir,'key.json'), JSON.stringify({ key: enc.keyB64, iv: enc.ivB64 }));


      TRANSFERS[id] = { id, dir, sender, recipient, room, meta, keyB64: enc.keyB64, ivB64: enc.ivB64, payloadB64: enc.payloadB64, attempts:0, status:'sent' };
      WORKSPACES[room].transfers.add(id);


      // Emit to either specific recipient (if exists) or to whole room when recipient === 'all'
      if(recipient === 'all') {
        io.to(room).emit('fileIncoming', { transferId: id, filename: meta.originalName, sender, ftype: meta.ftype, room, recipient: 'all' });
      } else {
        if(USERSOCK[recipient]) {
          io.to(USERSOCK[recipient]).emit('fileIncoming', { transferId: id, filename: meta.originalName, sender, ftype: meta.ftype, room, recipient });
        } else {
          // recipient offline -> still emit to room so receivers (when they join) can see? Keep simple: emit to room (they will ignore if not intended)
          io.to(room).emit('fileIncoming', { transferId: id, filename: meta.originalName, sender, ftype: meta.ftype, room, recipient });
        }
      }


      // notify sender of upload success
      const senderSid = USERSOCK[sender];
      if(senderSid) io.to(senderSid).emit('uploadSuccess', { transferId:id, filename:meta.originalName, room });


      // members update
      io.to(room).emit('workspace_members', { members: Array.from(WORKSPACES[room].members) });


      // start ack timer
      startAckTimer(id);


      return res.json({ ok:true, transferId:id, meta });
    });
  }catch(e){
    console.error('upload error', e); return res.status(500).json({ error:'server' });
  }
});


// ---------- Fetch endpoint ----------
app.get('/api/fetch/:id', requireLogin, (req,res)=>{
  try{
    const id = req.params.id;
    const info = TRANSFERS[id];
    if(!info) return res.status(404).json({ error:'not found' });


    // enforce access: sender or recipient (or 'all')
    const user = req.session.user;
    if(info.recipient && info.recipient !== 'all' && user !== info.recipient && user !== info.sender){
      return res.status(403).json({ error:'not_authorized' });
    }


    const payloadB64 = fs.readFileSync(path.join(info.dir,'encrypted.b64'), 'utf8').trim();
    let decrypted;
    try{
      decrypted = decryptAesGcm(payloadB64, info.keyB64, info.ivB64);
    }catch(e){
      console.error('decrypt failed', e);
      retransmit(id);
      return res.status(500).json({ error:'decrypt_failed_retransmitting' });
    }


    const meta = info.meta;
    let valid=false, originalBuf=null;


    if(meta.ftype === 'pdf'){
      originalBuf = decrypted;
      const crc = (CRC32.buf(originalBuf)>>>0).toString(16).padStart(8,'0');
      valid = (crc === meta.crc32);
    } else if(meta.ftype === 'image'){
      try{
        const decoded = hammingDecodeBuffer(decrypted);
        originalBuf = decoded.data;
        const hash = crypto.createHash('sha256').update(originalBuf).digest('hex');
        valid = (hash === meta.sha256);
      }catch(e){ console.error('hamming.decode error', e); valid=false; }
    } else {
      originalBuf = decrypted;
      const hash = crypto.createHash('sha256').update(originalBuf).digest('hex');
      valid = (hash === meta.sha256);
    }


    if(!valid){
      retransmit(id);
      return res.status(400).json({ error:'verification_failed_retransmitting' });
    }


    clearAckTimer(id);
    info.status = 'delivered';
    io.to(info.room).emit('delivered', { transferId: id, recipient: user });
    if(info.sender && USERSOCK[info.sender]) io.to(USERSOCK[info.sender]).emit('delivered', { transferId: id, recipient: user });


    const mime = mimeFor(meta);
    res.setHeader('Content-Disposition', `inline; filename="${meta.originalName}"`);
    res.setHeader('Content-Type', mime);
    return res.send(originalBuf);


  }catch(e){
    console.error('fetch error', e);
    return res.status(500).json({ error:'server' });
  }
});


// ---------- Verify endpoint ----------
app.post('/api/verify/:id', requireLogin, (req,res)=>{
  const id = req.params.id;
  const info = TRANSFERS[id];
  if(!info) return res.status(404).json({ error:'not_found' });
  const { valid } = req.body;
  if(!valid) retransmit(id);
  else {
    clearAckTimer(id);
    info.status = 'delivered';
    io.to(info.room).emit('delivered', { transferId: id });
    if(info.sender && USERSOCK[info.sender]) io.to(USERSOCK[info.sender]).emit('delivered', { transferId: id });
  }
  return res.json({ ok:true });
});


// ---------- Socket.IO ----------
io.on('connection', (socket)=>{
  console.log('socket connected', socket.id);


  socket.on('register', (username) => {
    if(!username) return;
    USERSOCK[username] = socket.id;
    socket.username = username;
    console.log('registered', username, socket.id);
  });


  socket.on('join_room', ({ room, username }) => {
    if(!room || !username) return;
    // Only allow joining if workspace exists & active in DB
    db.get('SELECT id,active FROM workspaces WHERE name=?', [room], (err,row)=>{
      if(err) { console.error('db err', err); socket.emit('join_failed', { reason: 'db_error' }); return; }
      if(!row || !row.active) { socket.emit('join_failed', { reason: 'no_room' }); return; }


      socket.join(room);
      if(!WORKSPACES[room]) WORKSPACES[room] = { creator: username, members: new Set([username]), transfers: new Set(), active:true };
      else WORKSPACES[room].members.add(username);
      io.to(room).emit('workspace_members', { members: Array.from(WORKSPACES[room].members) });
      socket.emit('room_joined', { room });
      console.log(username, 'joined', room);
    });
  });


  socket.on('leave_room', ({ room, username }) => {
    socket.leave(room);
    if(WORKSPACES[room]) { WORKSPACES[room].members.delete(username); io.to(room).emit('workspace_members', { members: Array.from(WORKSPACES[room].members) }); }
  });


  socket.on('disconnect', () => {
    for(const [u,sid] of Object.entries(USERSOCK)){ if(sid === socket.id) delete USERSOCK[u]; }
    console.log('socket disconnected', socket.id);
  });
});


// ---------- Start server ----------
const PORT = process.env.PORT || 3000;
server.listen(PORT, ()=>{ 
  console.log('Server listening on port', PORT);
  console.log('Open http://localhost:' + PORT + '/index.html');
});
