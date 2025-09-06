// Veltrix backend — server.js (v2 with Email Verification)
// Run: npm init -y && npm i express express-session sqlite3 bcrypt multer cors nodemailer
// Then: node server.js

const path = require('path');
const fs = require('fs');
const express = require('express');
const session = require('express-session');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');
const multer = require('multer');
const cors = require('cors');
const nodemailer = require('nodemailer');
const crypto = require('crypto');

const app = express();
const DB_FILE = path.join(__dirname, '../veltrix.db');
const PUBLIC_DIR = path.join(__dirname, 'public');

// ---------- MIDDLEWARE ----------
app.use(cors({ origin: true, credentials: true }));
app.use(express.json({ limit: '2mb' }));
app.use(express.urlencoded({ extended: true }));
app.use('/public', express.static(PUBLIC_DIR));
app.use(session({
  secret: 'veltrix-secret',
  resave: false,
  saveUninitialized: false,
  cookie: { httpOnly: true, sameSite: 'lax', maxAge: 1000*60*60*24*7 }
}));

// file uploads (profile pictures)
const upload = multer({
  storage: multer.diskStorage({
    destination: (req, file, cb) => cb(null, path.join(PUBLIC_DIR, 'uploads')),
    filename: (req, file, cb) => {
      const ext = path.extname(file.originalname || '.jpg');
      cb(null, `pfp_${Date.now()}${ext}`);
    }
  })
});

// ---------- DB INIT ----------
const db = new sqlite3.Database(DB_FILE);
db.serialize(()=>{
  // Added is_verified, verification_token, and token_expires
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL,
    email TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    profile_pic TEXT DEFAULT 'default.jpg',
    is_admin INTEGER DEFAULT 0,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    is_verified INTEGER DEFAULT 0,
    verification_token TEXT,
    token_expires DATETIME
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS accounts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT NOT NULL,
    description TEXT,
    price REAL NOT NULL,
    instructions TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS account_credentials (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    account_id INTEGER NOT NULL,
    secret TEXT NOT NULL,
    sold INTEGER DEFAULT 0,
    FOREIGN KEY(account_id) REFERENCES accounts(id)
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS invoices (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    total REAL NOT NULL,
    status TEXT DEFAULT 'pending',
    delivery_text TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(user_id) REFERENCES users(id)
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS invoice_items (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    invoice_id INTEGER NOT NULL,
    account_id INTEGER NOT NULL,
    qty INTEGER NOT NULL,
    unit_price REAL NOT NULL,
    title_snapshot TEXT,
    FOREIGN KEY(invoice_id) REFERENCES invoices(id),
    FOREIGN KEY(account_id) REFERENCES accounts(id)
  )`);
});

// ---------- AUTO-MIGRATIONS ----------
function addColumnIfMissing(table, column, type, cb){
  db.all(`PRAGMA table_info(${table})`, (err, cols)=>{
    if(err) return cb && cb(err);
    const exists = cols.some(c=>c.name===column);
    if(!exists){
      db.run(`ALTER TABLE ${table} ADD COLUMN ${column} ${type}`, cb);
    } else { cb && cb(); }
  });
}
addColumnIfMissing('accounts','instructions','TEXT', ()=>{});
addColumnIfMissing('invoice_items','title_snapshot','TEXT', ()=>{});
// Added migrations for new user columns
addColumnIfMissing('users', 'is_verified', 'INTEGER DEFAULT 0', ()=>{});
addColumnIfMissing('users', 'verification_token', 'TEXT', ()=>{});
addColumnIfMissing('users', 'token_expires', 'DATETIME', ()=>{});

// ---------- EMAIL SETUP ----------
const transporter = nodemailer.createTransport({
    host: "smtp.office365.com",
    port: 587,
    secure: false, // TLS
    auth: {
        user: "noreply@veltrix.asia",
        pass: "QJ.')D21k5&U",
    },
});

async function sendVerificationEmail(email, username, token) {
  // IMPORTANT: Replace 'http://localhost:4000' with your actual domain in production
  const verificationLink = `http://localhost:4000/api/verify-email?token=${token}`;

  const mailOptions = {
    from: '"Veltrix Support" <noreply@veltrix.asia>',
    to: email,
    subject: 'Veltrix Account Verification',
    text: `Hi ${username},\n\nPlease verify your account by clicking the following link: ${verificationLink}\n\nThis link will expire in 1 hour.`,
    html: `
      <h2>Welcome to Veltrix!</h2>
      <p>Hi ${username},</p>
      <p>Thanks for signing up! Please click the button below to verify your email address.</p>
      <a href="${verificationLink}" style="background-color: #ff4655; color: white; padding: 14px 25px; text-align: center; text-decoration: none; display: inline-block; border-radius: 8px;">Verify Your Account</a>
      <p>This link will expire in 1 hour.</p>
    `
  };

  try {
    await transporter.sendMail(mailOptions);
    console.log(`Verification email sent to ${email}`);
  } catch (error) {
    console.error(`Error sending verification email to ${email}:`, error);
  }
}

// helpers
function requireAuth(req,res,next){ if(!req.session.user){ return res.status(401).json({error:'Not logged in'}); } next(); }
function requireAdmin(req,res,next){ if(!req.session.user || !req.session.user.is_admin){ return res.status(403).json({error:'Admin only'}); } next(); }

// ---------- AUTH ----------
app.post('/api/register', async (req,res)=>{
  const {username,email,password} = req.body;
  if(!username||!email||!password) return res.status(400).json({error:'Missing fields'});

  const hash = await bcrypt.hash(password, 10);
  const token = crypto.randomBytes(32).toString('hex');
  const expires = new Date(Date.now() + 3600000); // Token expires in 1 hour

  db.run(
    `INSERT INTO users (username, email, password, verification_token, token_expires) VALUES (?, ?, ?, ?, ?)`,
    [username, email, hash, token, expires], 
    function(err){
      if(err) {
        console.error("Registration DB Error:", err.message);
        return res.status(500).json({error:'Email already in use or DB error'});
      }
      
      sendVerificationEmail(email, username, token).catch(console.error);

      return res.status(201).json({ok:true, message: 'Registration successful. Please check your email to verify your account.'});
    }
  );
});

// NEW: Endpoint to handle email verification link
app.get('/api/verify-email', (req, res) => {
    const { token } = req.query;
    if (!token) {
        return res.status(400).send('Verification token is missing.');
    }

    db.get(`SELECT * FROM users WHERE verification_token = ? AND token_expires > ?`, [token, new Date()], (err, user) => {
        if (err || !user) {
            return res.status(400).send('<h1>Verification Failed</h1><p>This verification link is invalid or has expired.</p>');
        }

        db.run(`UPDATE users SET is_verified = 1, verification_token = NULL, token_expires = NULL WHERE id = ?`, [user.id], function(updateErr) {
            if (updateErr) {
                return res.status(500).send('An error occurred during verification.');
            }
            res.send('<h1>Email Verified!</h1><p>Your account has been successfully verified. You can now <a href="/">log in</a>.</p>');
        });
    });
});

app.post('/api/login', (req,res)=>{
  const {email,password} = req.body;
  db.get(`SELECT * FROM users WHERE email=?`, [email], async (err, user)=>{
    if(err||!user) return res.status(401).json({error:'Invalid credentials'});

    // Check if user is verified before allowing login
    if(user.is_verified !== 1) {
      return res.status(403).json({ error: 'Please verify your email before logging in.' });
    }

    const ok = await bcrypt.compare(password, user.password);
    if(!ok) return res.status(401).json({error:'Invalid credentials'});
    
    req.session.user = { id:user.id, email:user.email, username:user.username, is_admin: !!user.is_admin, profile_pic:user.profile_pic };
    res.json({ id:user.id, email:user.email, username:user.username, isAdmin: !!user.is_admin, profile_pic:user.profile_pic });
  });
});

app.post('/api/logout', (req,res)=>{
  req.session.destroy(()=>res.json({ok:true}));
});

app.get('/api/profile', (req,res)=>{
  const u=req.session.user;
  if(!u) return res.json({error:'Not logged in'});
  res.json({ id:u.id, email:u.email, username:u.username, isAdmin: !!u.is_admin, profile_pic:u.profile_pic, is_admin: !!u.is_admin });
});

app.post('/api/profile/avatar', requireAuth, upload.single('profilePic'), (req,res)=>{
  const file = req.file?.filename || 'default.jpg';
  db.run(`UPDATE users SET profile_pic=? WHERE id=?`, [file, req.session.user.id], function(err){
    if(err) return res.json({error:'DB error'});
    req.session.user.profile_pic = file;
    res.json({ok:true, file});
  });
});

// ---------- STORE (No changes below this line) ----------
// ... (rest of your existing code for Store, Checkout, Admin, etc.)
// The rest of your file remains unchanged.
// ---------- STORE ----------
app.get('/api/accounts', (req,res)=>{
    const q=`SELECT a.*, (SELECT COUNT(*) FROM account_credentials c WHERE c.account_id=a.id AND c.sold=0) as stock
             FROM accounts a WHERE 1=1 ORDER BY a.id DESC`;
    db.all(q, [], (err, rows)=>{
      if(err) return res.json([]);
      res.json(rows);
    });
  });
  
  app.post('/api/admin/accounts', requireAdmin, (req,res)=>{
    const {title, description, price, instructions} = req.body;
    if(!title || price==null || !instructions || instructions.trim()==='') return res.json({error:'Missing title/price/instructions'});
    db.run(`INSERT INTO accounts (title,description,price,instructions) VALUES (?,?,?,?)`, [title,description||'',price,instructions||''], function(err){
      if(err) return res.json({error:'DB error'});
      res.json({ok:true, id:this.lastID});
    });
  });
  
  app.put('/api/admin/accounts/:id', requireAdmin, (req,res)=>{
    const {title, description, price, instructions} = req.body;
    db.get(`SELECT * FROM accounts WHERE id=?`, [req.params.id], (err, row)=>{
      if(err || !row) return res.json({error:'Account not found'});
      const nt = title!==undefined?title:row.title;
      const nd = description!==undefined?description:row.description;
      const np = price!==undefined?price:row.price;
      const ni = (instructions!==undefined?instructions:row.instructions);
      if(!ni || ni.trim()===''){ return res.json({error:'Instructions required'}); }
      db.run(`UPDATE accounts SET title=?, description=?, price=?, instructions=? WHERE id=?`,
        [nt, nd, np, ni, req.params.id], function(e2){
          if(e2) return res.json({error:'DB error'});
          res.json({ok:true});
        });
    });
  });
  
  app.delete('/api/admin/accounts/:id', requireAdmin, (req,res)=>{
    const id = req.params.id;
    db.run(`DELETE FROM account_credentials WHERE account_id=? AND sold=0`, [id], function(err){
      if(err) return res.json({error:'DB error'});
      db.run(`DELETE FROM accounts WHERE id=?`, [id], function(err2){
        if(err2) return res.json({error:'DB error'});
        res.json({ok:true});
      });
    });
  });
  
  app.post('/api/admin/accounts/:id/credentials', requireAdmin, (req,res)=>{
    const id = req.params.id;
    const bulk = req.body.bulk || '';
    const lines = bulk.split(/\r?\n/).map(s=>s.trim()).filter(Boolean);
    const stmt = db.prepare(`INSERT INTO account_credentials (account_id,secret) VALUES (?,?)`);
    db.serialize(()=>{
      lines.forEach(line=>stmt.run([id,line]));
      stmt.finalize((err)=>{
        if(err) return res.json({error:'DB error'});
        res.json({ok:true, added:lines.length});
      });
    });
  });
  
  // ---------- CHECKOUT / INVOICES ----------
  app.post('/api/checkout', requireAuth, (req,res)=>{
    const items = (req.body.items||[]).filter(it=>it.account_id && it.qty>0);
    if(items.length===0) return res.json({error:'Empty cart'});
  
    const ids = items.map(i=>i.account_id);
    const placeholders = ids.map(()=>'?').join(',');
    db.all(`SELECT id, price, title FROM accounts WHERE id IN (${placeholders})`, ids, (err, rows)=>{
      if(err || rows.length===0) return res.json({error:'Invalid items'});
      const map = new Map(rows.map(r=>[r.id, r]));
      let total = 0;
      items.forEach(it=>{ const r=map.get(it.account_id); if(r){ total += r.price * it.qty; } });
      db.run(`INSERT INTO invoices (user_id,total,status) VALUES (?,?,?)`, [req.session.user.id, total, 'pending'], function(err2){
        if(err2) return res.json({error:'DB error'});
        const invId = this.lastID;
        const stmt = db.prepare(`INSERT INTO invoice_items (invoice_id,account_id,qty,unit_price,title_snapshot) VALUES (?,?,?,?,?)`);
        items.forEach(it=>{
          const r=map.get(it.account_id);
          if(r){ stmt.run([invId, it.account_id, it.qty, r.price, r.title]); }
        });
        stmt.finalize(()=>{
          res.json({ok:true, invoice_id:invId});
        });
      });
    });
  });
  
  // My invoices
  app.get('/api/my-invoices', requireAuth, (req, res) => {
    db.all(
      `SELECT * FROM invoices WHERE user_id=? ORDER BY id DESC`,
      [req.session.user.id],
      (err, invs) => {
        if (err) return res.json([]);
        const invIds = invs.map(i => i.id);
        if (invIds.length === 0) return res.json([]);
        const ph = invIds.map(() => '?').join(',');
  
        db.all(
          `SELECT ii.*, COALESCE(ii.title_snapshot, a.title) as title, a.instructions
           FROM invoice_items ii
           LEFT JOIN accounts a ON a.id = ii.account_id
           WHERE ii.invoice_id IN (${ph})`,
          invIds,
          (err2, items) => {
            if (err2) return res.json([]);
  
            const byInv = {};
            items.forEach(it => {
              (byInv[it.invoice_id] ||= []).push({
                account_id: it.account_id,
                qty: it.qty,
                unit_price: it.unit_price,
                title: it.title,
                title_snapshot: it.title_snapshot,
                instructions: it.instructions || null
              });
            });
  
            res.json(
              invs.map(i => ({
                ...i,
                items: byInv[i.id] || []
              }))
            );
          }
        );
      }
    );
  });
  
  // Admin view invoices
  app.get('/api/admin/invoices', requireAdmin, (req,res)=>{
    db.all(`SELECT i.*, u.email as user_email FROM invoices i JOIN users u ON u.id=i.user_id ORDER BY i.id DESC`, [], (err, invs)=>{
      if(err) return res.json([]);
      if(invs.length===0) return res.json([]);
      const ids = invs.map(i=>i.id);
      const ph = ids.map(()=>'?').join(',');
      db.all(`SELECT ii.*, COALESCE(ii.title_snapshot, a.title) as title, a.instructions FROM invoice_items ii LEFT JOIN accounts a ON a.id=ii.account_id WHERE ii.invoice_id IN (${ph})`, ids, (err2, items)=>{
        const byInv = {};
        items.forEach(it=>{ (byInv[it.invoice_id] ||= []).push({account_id:it.account_id, qty:it.qty, unit_price:it.unit_price, title:it.title, title_snapshot:it.title_snapshot}) });
        res.json(invs.map(i=>({ ...i, items: byInv[i.id] || [] })));
      });
    });
  });
  
  // Confirm invoice
  app.post('/api/admin/invoices/:id/confirm', requireAdmin, (req,res)=>{
    const invId = req.params.id;
    db.get(`SELECT * FROM invoices WHERE id=?`, [invId], (err, inv)=>{
      if(err||!inv) return res.json({error:'Invoice not found'});
      if(inv.status !== 'pending') return res.json({error:'Already processed'});
  
      db.all(`SELECT * FROM invoice_items WHERE invoice_id=?`, [invId], (err2, items)=>{
        if(err2) return res.json({error:'DB error'});
        const allocations = [];
        const processNext = (idx)=>{
          if(idx>=items.length){
            const deliveryText = allocations.map(a=>{
              let block = `# ${a.title}\n` + a.creds.map(c=>`• ${c}`).join('\n');
              if(a.instructions){ block += `\nInstructions: ${a.instructions}`; }
              return block;
            }).join('\n\n');
            db.run(`UPDATE invoices SET status='confirmed', delivery_text=? WHERE id=?`, [deliveryText, invId], function(errx){
              if(errx) return res.json({error:'DB error finalizing'});
              res.json({ok:true, delivery:deliveryText});
            });
            return;
          }
          const it = items[idx];
          db.all(`SELECT id, secret FROM account_credentials WHERE account_id=? AND sold=0 LIMIT ?`, [it.account_id, it.qty], (err3, creds)=>{
            if(err3) return res.json({error:'DB error'});
            if(!creds || creds.length < it.qty){
              return res.json({error:`Insufficient stock for account ${it.account_id}`});
            }
            const ids = creds.map(c=>c.id);
            db.run(`UPDATE account_credentials SET sold=1 WHERE id IN (${ids.map(()=>'?').join(',')})`, ids, function(err4){
              if(err4) return res.json({error:'DB error'});
              db.get(`SELECT title, instructions FROM accounts WHERE id=?`, [it.account_id], (e5,row)=>{
                allocations.push({title: (it.title_snapshot||row?.title||`Account #${it.account_id}`), instructions: row?.instructions || '', creds: creds.map(c=>c.secret)});
                processNext(idx+1);
              });
            });
          });
        };
        processNext(0);
      });
    });
  });
  
  app.post('/api/admin/invoices/:id/reject', requireAdmin, (req,res)=>{
    db.run(`UPDATE invoices SET status='rejected' WHERE id=? AND status='pending'`, [req.params.id], function(err){
      if(err) return res.json({error:'DB error'});
      res.json({ok:true});
    });
  });
  
  app.delete('/api/admin/invoices/:id', requireAdmin, (req,res)=>{
    const id = req.params.id;
    db.run(`DELETE FROM invoice_items WHERE invoice_id=?`, [id], function(err){
      if(err) return res.json({error:'DB error'});
      db.run(`DELETE FROM invoices WHERE id=?`, [id], function(err2){
        if(err2) return res.json({error:'DB error'});
        res.json({ok:true});
      });
    });
  });
  
  // ---------- CREDENTIALS ADMIN ----------
  app.delete('/api/admin/credentials/:id', requireAdmin, (req,res)=>{
    const id = req.params.id;
    db.get(`SELECT * FROM account_credentials WHERE id=?`, [id], (err,row)=>{
      if(err || !row) return res.json({error:'Credential not found'});
      if(row.sold){ return res.json({error:'Cannot delete sold credential'}); }
      db.run(`DELETE FROM account_credentials WHERE id=?`, [id], function(err2){
        if(err2) return res.json({error:'DB error'});
        res.json({ok:true});
      });
    });
  });
  
  app.get('/api/admin/accounts/:id/credentials', requireAdmin, (req,res)=>{
    db.all(`SELECT id, secret, sold FROM account_credentials WHERE account_id=? ORDER BY id DESC`, [req.params.id], (err, rows)=>{
      if(err) return res.json([]);
      res.json(rows);
    });
  });
  
  // ---------- USERS ADMIN ----------
  app.get('/api/admin/users', requireAdmin, (req,res)=>{
    db.all(`SELECT id,username,email,is_admin,profile_pic,created_at FROM users ORDER BY id DESC`,[],(err,rows)=>{
      if(err) return res.json([]);
      res.json(rows);
    });
  });
  
  app.post('/api/admin/users/:id/promote', requireAdmin, (req,res)=>{
    db.run(`UPDATE users SET is_admin=1 WHERE id=?`, [req.params.id], function(err){
      if(err) return res.json({error:'DB error'}); res.json({ok:true});
    });
  });
  
  app.post('/api/admin/users/:id/demote', requireAdmin, (req,res)=>{
    db.run(`UPDATE users SET is_admin=0 WHERE id=?`, [req.params.id], function(err){
      if(err) return res.json({error:'DB error'}); res.json({ok:true});
    });
  });
  
  // ---------- ACTIVITY ----------
  app.post('/api/admin/activity', requireAuth, (req,res)=>{
    const action = req.body.action || 'action';
    db.run(`INSERT INTO activity (user_id, action) VALUES (?, ?)`, [req.session.user.id, action]);
    res.json({ok:true});
  });
  
  app.get('/api/admin/activity', requireAdmin, (req,res)=>{
    db.all(`SELECT a.*, u.username, u.profile_pic FROM activity a LEFT JOIN users u ON u.id=a.user_id ORDER BY a.id DESC LIMIT 50`,[],(err,rows)=>{
      if(err) return res.json([]); res.json(rows);
    });
  });
  
  // ---------- STATIC PAGES ----------
  app.get('/', (req,res)=> res.sendFile(path.join(__dirname,'index.html')));
  app.get('/admin.html', (req,res)=> res.sendFile(path.join(__dirname,'admin.html')));
  
  // ---------- START ----------
  const PORT = process.env.PORT || 4000;
  app.listen(PORT, ()=>{
    console.log('Veltrix server running on http://localhost:'+PORT);
    if(!fs.existsSync(PUBLIC_DIR)){
      fs.mkdirSync(PUBLIC_DIR, { recursive:true });
    }
  });