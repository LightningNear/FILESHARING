
Lightshare SQLite App - Combined Frontend + Backend
Run:
  cd backend
  npm install
  npm start
Open http://localhost:3000/index.html

Notes:
- SQLite DB file: backend/lightshare.db (auto-created)
- Users stored in users table (username, password hash)
- Workspaces are in-memory only and temporary
- Files are stored in backend/uploads/<transferId>/ during transfer
