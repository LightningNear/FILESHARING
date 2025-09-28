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

// Dev-friendly CORS
app.use(cors({ origin: true, credentials: true }));

app.use(bodyParser.json({ limit: '200mb' }));
app.use(bodyParser.urlencoded({ extended: true }));

app.use(session({
  secret: 'lightshare-demo-secret',
  resave: false,
  saveUninitialized: false,
  cookie: { maxAge: 24*3600*1000, httpOnly: true, sameSite: 'lax' }
}));

app.use('/', express.static(path.join(__dirname, 'public')));

const server = http.createServer(app);
const io = new Server(server, {
  cors: { origin: (origin, cb) => cb(null, true), methods: ['GET','POST','DELETE'], credentials: true }
});

const storage = multer.memoryStorage();
const upload = multer({ storage });

// In-memory stores
const WORKSPACES = {};   // room -> { creator, members:Set(username), transfers:Set, active }
const TRANSFERS = {};    // id -> transfer info
const USERSOCK = {};     // username -> socketId
const SOCKET_ROOMS = {}; // socketId -> Set(room)
const ACK_TIMERS = {};   // transferId -> timeout

// Helpers
function ensureDir(d){ if(!fs.existsSync(d)) fs.mkdirSync(d, { recursive: true }); }
function normalizeName(name){
  if(!name) return '';
  const trimmed = (''+name).trim();
  return trimmed.split(':', 1)[0].trim().toLowerCase();
}
function encryptAesGcm(buffer){
  const key = crypto.randomBytes(32);
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const encrypted = Buffer.concat([cipher.update(buffer), cipher.final()]);
  const tag = cipher.getAuthTag();
  return { payloadB64: Buffer.concat([encrypted, tag]).toString('base64'), keyB64: key.toString('base64'), ivB64: iv.toString('base64') };
}
function decryptAesGcm(payloadB64, keyB64, ivB64){
  const payload = Buffer.from(payloadB64, 'base64');
  const key = Buffer.from(keyB64, 'base64');
  const iv = Buffer.from(ivB64, 'base64');
  const tag = payload.slice(payload.length-16);
  const encrypted = payload.slice(0, payload.length-16);
  const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(encrypted), decipher.final()]);
}

// Hamming 7,4 encode/decode
function encodeNibbleTo7(n){
  const d0=(n>>0)&1,d1=(n>>1)&1,d2=(n>>2)&1,d3=(n>>3)&1;
  const p0=d0^d1^d3,p1=d0^d2^d3,p2=d1^d2^d3;
  const bits=[p0,p1,d0,p2,d1,d2,d3];
  let val=0; for(let i=0;i<bits.length;i++) val|=(bits[i]<<(6-i));
  return val&0x7F;
}
function hammingEncodeBuffer(buf){
  const out=Buffer.alloc(buf.length*2);
  for(let i=0;i<buf.length;i++){
    const b=buf[i];
    out[i*2]=encodeNibbleTo7((b>>4)&0xF);
    out[i*2+1]=encodeNibbleTo7(b&0xF);
  }
  return out;
}
function decode7ToNibble(val){
  const bits=[]; for(let i=6;i>=0;i--) bits.push((val>>i)&1);
  let [p0,p1,d0,p2,d1,d2,d3]=bits;
  const s0=p0^d0^d1^d3, s1=p1^d0^d2^d3, s2=p2^d1^d2^d3;
  const syndrome=(s0<<2)|(s1<<1)|s2;
  if(syndrome!==0){ const idx=syndrome-1; bits[idx]^=1; [p0,p1,d0,p2,d1,d2,d3]=bits; }
  return { nibble:(d3<<3)|(d2<<2)|(d1<<1)|d0 };
}
function hammingDecodeBuffer(encBuf){
  const out=Buffer.alloc(encBuf.length/2);
  for(let i=0;i<encBuf.length;i+=2){
    const hi=decode7ToNibble(encBuf[i]&0x7F).nibble;
    const lo=decode7ToNibble(encBuf[i+1]&0x7F).nibble;
    out[i/2]=(hi<<4)|lo;
  }
  return { data: out };
}

function mimeFor(meta){
  if(meta.ftype==='pdf') return 'application/pdf';
  if(meta.ftype==='image'){
    const ext=path.extname(meta.originalName||'').toLowerCase();
    if(ext==='.png') return 'image/png';
    if(ext==='.jpg'||ext==='.jpeg') return 'image/jpeg';
    return 'application/octet-stream';
  }
  if(meta.ftype==='video') return 'video/mp4';
  return 'application/octet-stream';
}

// ACK timers
function startAckTimer(id){
  clearAckTimer(id);
  ACK_TIMERS[id]=setTimeout(()=>{ console.log('ACK timeout, retransmit',id); retransmit(id); }, 2*60*1000);
}
function clearAckTimer(id){ if(ACK_TIMERS[id]){ clearTimeout(ACK_TIMERS[id]); delete ACK_TIMERS[id]; } }
function retransmit(id){
  const info=TRANSFERS[id]; if(!info) return;
  try{
    const original=fs.readFileSync(path.join(info.dir,'original.bin'));
    let processed=original;
    if(info.meta.ftype==='image') processed=hammingEncodeBuffer(original);
    const enc=encryptAesGcm(processed);
    fs.writeFileSync(path.join(info.dir,'encrypted.b64'),enc.payloadB64);
    info.payloadB64=enc.payloadB64; info.keyB64=enc.keyB64; info.ivB64=enc.ivB64;
    info.attempts=(info.attempts||0)+1; info.status='retransmitted';
    if(info.recipient==='all') io.to(info.room).emit('fileIncoming',{ transferId:id, filename:info.meta.originalName, sender:info.sender, ftype:info.meta.ftype, room:info.room, recipient:'all', retransmit:true });
    else { if(USERSOCK[info.recipient]) io.to(USERSOCK[info.recipient]).emit('fileIncoming',{ transferId:id, filename:info.meta.originalName, sender:info.sender, ftype:info.meta.ftype, room:info.room, recipient:info.recipient, retransmit:true }); }
    if(info.attempts<6) startAckTimer(id);
  }catch(e){ console.error('retransmit error', e); }
}

// DB helpers
function createUser(username,passwordHash){ return new Promise((resolve,reject)=>{ db.run('INSERT INTO users (username,password) VALUES (?,?)',[username,passwordHash],function(err){ if(err) return reject(err); resolve({ id:this.lastID, username }); }); }); }
function findUser(username){ return new Promise((resolve,reject)=>{ db.get('SELECT id,username,password FROM users WHERE username=?',[username],(err,row)=>{ if(err) return reject(err); resolve(row); }); }); }

// Find active workspace
function findActiveWorkspace(name, cb){
  if(!name) return cb(null,null);
  const normalized=normalizeName(name);
  db.get('SELECT * FROM workspaces WHERE normalized_name=? AND active=1',[normalized],(err,row)=>{
    if(err) return cb(err);
    if(row) return cb(null,row);
    db.get('SELECT * FROM workspaces WHERE lower(name)=lower(?) AND active=1',[name],(err2,row2)=>{
      if(err2) return cb(err2);
      if(row2) return cb(null,row2);
      const main=name.split(':')[0];
      db.get('SELECT * FROM workspaces WHERE normalized_name=? AND active=1',[normalizeName(main)],(err3,row3)=>{ if(err3) return cb(err3); cb(null,row3||null); });
    });
  });
}

// Auth middleware
function requireLogin(req,res,next){ if(req.session && req.session.user) return next(); return res.status(401).json({ error:'auth' }); }

// Signup/Login
app.post('/api/signup', async (req,res)=>{
  try{
    const { user, pass } = req.body;
    if(!user||!pass) return res.status(400).json({ error:'missing' });
    const existing=await findUser(user);
    if(existing) return res.status(400).json({ error:'exists' });
    const hash=await bcrypt.hash(pass,10);
    await createUser(user,hash);
    req.session.user=user;
    return res.json({ ok:true, user });
  }catch(e){ console.error('signup err',e); return res.status(500).json({ error:'server' }); }
});
app.post('/api/login', async (req,res)=>{
  try{
    const { user, pass }=req.body;
    if(!user||!pass) return res.status(400).json({ error:'missing' });
    const row=await findUser(user);
    if(!row) return res.status(400).json({ error:'no_user' });
    let ok=false;
    try{ if(row.password.startsWith('$2')) ok=await bcrypt.compare(pass,row.password); else ok=(pass===row.password); }catch(e){ ok=false; }
    if(!ok) return res.status(400).json({ error:'bad_pass' });
    req.session.user=user;
    return res.json({ ok:true, user });
  }catch(e){ console.error('login err',e); return res.status(500).json({ error:'server' }); }
});

// Workspace create endpoint
app.post('/api/create-workspace', requireLogin, (req,res)=>{
  const { name }=req.body;
  const creator=req.session.user;
  if(!name) return res.status(400).json({ error:'missing' });
  const normalized=normalizeName(name);
  const now=Date.now();
  const sql=`
    INSERT INTO workspaces (name, normalized_name, creator, active, created_at)
    SELECT ?, ?, ?, 1, ? WHERE NOT EXISTS (SELECT 1 FROM workspaces WHERE normalized_name=? AND active=1)
  `;
  db.run(sql,[name,normalized,creator,now,normalized], function(err){
    if(err){ console.error(err); return res.status(500).json({ error:'db_insert' }); }
    if(this.changes===0) return res.status(400).json({ error:'name_taken' });
    db.get('SELECT * FROM workspaces WHERE id=?',[this.lastID],(err2,row)=>{
      const canonical=row?.name||name;
      WORKSPACES[canonical]={ creator: row?.creator||creator, members:new Set([creator]), transfers:new Set(), active:true };
      if(USERSOCK[creator]) io.to(USERSOCK[creator]).emit('workspace_created',{ name: canonical });
      return res.json({ ok:true, name: canonical, creator: row?.creator||creator, members:[creator], active:true });
    });
  });
});

// End workspace helper and API
function doEndWorkspaceByNameCaseInsensitive(name,user,cb){
  const normalized=normalizeName(name);
  db.get('SELECT * FROM workspaces WHERE (lower(name)=lower(?) OR normalized_name=?) AND active=1',[name,normalized],(err,row)=>{
    if(err) return cb(err);
    if(!row) return cb(null,{ ok:false, error:'workspace_not_found' });
    if(row.creator!==user) return cb(null,{ ok:false, error:'not_authorized' });
    const realName=row.name;
    db.run('UPDATE workspaces SET active=0 WHERE id=?',[row.id],(err2)=>{
      if(err2) return cb(err2);
      const ws=WORKSPACES[realName];
      if(ws){
        for(const tid of ws.transfers||[]){ const info=TRANSFERS[tid]; if(info){ try{ fs.rmSync(info.dir,{ recursive:true, force:true }); }catch(e){} delete TRANSFERS[tid]; } }
        delete WORKSPACES[realName];
      }
      io.to(realName).emit('workspace_ended',{ room: realName });
      return cb(null,{ ok:true });
    });
  });
}

app.post('/api/end-workspace', requireLogin, (req,res)=>{
  const { name }=req.body; const user=req.session.user;
  doEndWorkspaceByNameCaseInsensitive(name,user,(err,result)=>{
    if(err){ console.error(err); return res.status(500).json({ error:'server_error' }); }
    if(!result.ok) return res.status(400).json({ error:result.error });
    return res.json({ ok:true });
  });
});

app.delete('/api/workspace/:name', requireLogin, (req,res)=>{
  const name=req.params.name; const user=req.session.user;
  doEndWorkspaceByNameCaseInsensitive(name,user,(err,result)=>{
    if(err){ console.error(err); return res.status(500).json({ error:'server_error' }); }
    if(!result.ok) return res.status(400).json({ error:result.error });
    return res.json({ ok:true });
  });
});

app.get('/api/workspace/:name', requireLogin, (req,res)=>{
  const { name }=req.params;
  findActiveWorkspace(name,(err,row)=>{
    if(err) return res.status(500).json({ error:'db_error' });
    if(!row) return res.status(404).json({ error:'not_found' });
    const canonical=row.name;
    const ws=WORKSPACES[canonical];
    return res.json({ name: canonical, creator: row.creator, members: ws?Array.from(ws.members):[], active:!!row.active });
  });
});

// Socket.IO events
io.on('connection', socket => {
  console.log('Socket connected:', socket.id);

  socket.on('register', username => {
    if (!username) return;
    USERSOCK[username] = socket.id;
    SOCKET_ROOMS[socket.id] ||= new Set();
  });

  socket.on('join_room', async ({ room, username }) => {
    if (!room || !username) return;
    socket.join(room);
    SOCKET_ROOMS[socket.id] ||= new Set();
    SOCKET_ROOMS[socket.id].add(room);

    if (!WORKSPACES[room]) {
      db.get('SELECT * FROM workspaces WHERE name=? AND active=1', [room], (err, row) => {
        if (row) {
          WORKSPACES[room] = {
            creator: row.creator,
            members: new Set(),
            transfers: new Set(),
            active: true
          };
        }
        if (WORKSPACES[room]) {
          WORKSPACES[room].members.add(username);
          // Notify all clients in room of updated members
          io.to(room).emit('workspace_members', { members: Array.from(WORKSPACES[room].members) });
        }
      });
    } else {
      WORKSPACES[room].members.add(username);
      io.to(room).emit('workspace_members', { members: Array.from(WORKSPACES[room].members) });
    }
  });

  socket.on('leave_room', room => {
    if (!room) return;
    socket.leave(room);
    SOCKET_ROOMS[socket.id]?.delete(room);

    // Remove user by username mapping
    let usernameToRemove;
    for(const [user,sid] of Object.entries(USERSOCK)){
      if(sid === socket.id) usernameToRemove = user;
    }
    const ws = WORKSPACES[room];
    if (ws && usernameToRemove) {
      ws.members.delete(usernameToRemove);
      io.to(room).emit('workspace_members', { members: Array.from(ws.members) });
    }
  });

  socket.on('disconnect', () => {
    const rooms = SOCKET_ROOMS[socket.id];
    let usernameToRemove;
    for(const [user,sid] of Object.entries(USERSOCK)){
      if(sid === socket.id) usernameToRemove = user;
    }
    if (rooms) {
      for (const r of rooms) {
        const ws = WORKSPACES[r];
        if (ws && usernameToRemove) {
          ws.members.delete(usernameToRemove);
          io.to(r).emit('workspace_members', { members: Array.from(ws.members) });
        }
      }
      delete SOCKET_ROOMS[socket.id];
    }
    if(usernameToRemove) delete USERSOCK[usernameToRemove];
  });

  socket.on('ack', transferId => {
    clearAckTimer(transferId);
    const info = TRANSFERS[transferId];
    if (info) info.status = 'acknowledged';
  });
});

// File Upload endpoint
app.post('/api/upload', requireLogin, upload.single('file'), (req,res)=>{
  if(!req.file) return res.status(400).json({ error:'missing_file' });
  const { room, recipient } = req.body;
  if(!room) return res.status(400).json({ error:'missing_room' });

  const ws = WORKSPACES[room];
  if(!ws) return res.status(400).json({ error:'workspace_not_found' });

  const transferId = crypto.randomUUID();
  const dir = path.join(UPLOAD_ROOT, transferId);
  ensureDir(dir);
  const originalPath = path.join(dir, 'original.bin');
  fs.writeFileSync(originalPath, req.file.buffer);

  // Encode Hamming if image
  let processed = req.file.buffer;
  const ext = path.extname(req.file.originalname).toLowerCase();
  const ftype = ext.match(/\.(png|jpg|jpeg)$/) ? 'image' : req.file.mimetype.includes('pdf') ? 'pdf' : 'other';
  if(ftype==='image') processed = hammingEncodeBuffer(processed);

  const enc = encryptAesGcm(processed);
  fs.writeFileSync(path.join(dir,'encrypted.b64'), enc.payloadB64);

  const meta = { originalName:req.file.originalname, ftype };
  TRANSFERS[transferId] = {
    id: transferId,
    room,
    sender: req.session.user,
    recipient: recipient||'all',
    meta,
    dir,
    payloadB64: enc.payloadB64,
    keyB64: enc.keyB64,
    ivB64: enc.ivB64,
    status: 'pending',
    attempts: 1
  };
  ws.transfers.add(transferId);

  // Emit to recipient(s)
  if(TRANSFERS[transferId].recipient === 'all') {
    io.to(room).emit('fileIncoming', {
      transferId,
      filename: meta.originalName,
      sender: req.session.user,
      ftype: meta.ftype,
      room,
      recipient: 'all'
    });
  } else if(USERSOCK[recipient]) {
    io.to(USERSOCK[recipient]).emit('fileIncoming', {
      transferId,
      filename: meta.originalName,
      sender: req.session.user,
      ftype: meta.ftype,
      room,
      recipient
    });
  }

  startAckTimer(transferId);

  return res.json({ ok:true, transferId });
});

// File fetch/download endpoint - serve inline for view
app.get('/api/fetch/:transferId', requireLogin, (req,res)=>{
  const { transferId } = req.params;
  const info = TRANSFERS[transferId];
  if(!info) return res.status(404).json({ error:'not_found' });

  const { payloadB64, keyB64, ivB64, meta } = info;
  const buffer = decryptAesGcm(payloadB64, keyB64, ivB64);
  let final = buffer;
  if(meta.ftype==='image') final = hammingDecodeBuffer(buffer).data;

  res.setHeader('Content-Disposition', `inline; filename="${meta.originalName}"`);
  res.setHeader('Content-Type', mimeFor(meta));
  res.send(final);
});

// Start server
const PORT = process.env.PORT || 3000;
server.listen(PORT, () => console.log(`Server listening on port ${PORT}`));
