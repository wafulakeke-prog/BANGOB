require("dotenv").config();
const express = require("express"), bcrypt = require("bcryptjs"), jwt = require("jsonwebtoken");
const Database = require("better-sqlite3"), rateLimit = require("express-rate-limit");
const E = process.env, db = new Database("bango.db");
const BASE = E.MPESA_ENV === "production" ? "https://api.safaricom.co.ke" : "https://sandbox.safaricom.co.ke";
const MIN_DEPOSIT = 20, MAX_DEPOSIT = 150000;

db.exec(`CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY, phone TEXT UNIQUE, hash TEXT, dob TEXT,
  balance INTEGER DEFAULT 0, created TEXT DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS deposits(id INTEGER PRIMARY KEY, user_id INTEGER, amount INTEGER,
  checkout_id TEXT UNIQUE, status TEXT DEFAULT 'PENDING', receipt TEXT UNIQUE, created TEXT DEFAULT CURRENT_TIMESTAMP);`);

const app = express();
app.use(express.json({ limit: "20kb" }));
app.use(express.static("public"));
const authLimit = rateLimit({ windowMs: 15 * 60 * 1000, max: 20 });

const msisdn = p => { p = String(p || "").replace(/\D/g, ""); if (/^0[17]\d{8}$/.test(p)) return "254" + p.slice(1); return /^254[17]\d{8}$/.test(p) ? p : null; };
const is18 = d => { const b = new Date(d); if (isNaN(b)) return false; const n = new Date(); let a = n.getFullYear() - b.getFullYear();
  if (n < new Date(n.getFullYear(), b.getMonth(), b.getDate())) a--; return a >= 18; };
const sign = u => jwt.sign({ id: u.id }, E.JWT_SECRET, { expiresIn: "7d" });
const auth = (req, res, next) => { try { req.uid = jwt.verify((req.headers.authorization || "").slice(7), E.JWT_SECRET).id; next(); }
  catch { res.status(401).json({ error: "Please sign in again." }); } };

app.post("/api/register", authLimit, (req, res) => {
  const phone = msisdn(req.body.phone), { password, dob } = req.body;
  if (!phone) return res.status(400).json({ error: "Enter a valid Safaricom number, e.g. 0712345678." });
  if (!password || password.length < 8) return res.status(400).json({ error: "Password must be at least 8 characters." });
  if (!is18(dob)) return res.status(400).json({ error: "You must be 18 or older to play." });
  try {
    const r = db.prepare("INSERT INTO users(phone,hash,dob) VALUES(?,?,?)").run(phone, bcrypt.hashSync(password, 12), dob);
    res.json({ token: sign({ id: r.lastInsertRowid }) });
  } catch { res.status(409).json({ error: "This number already has an account. Sign in instead." }); }
});

app.post("/api/login", authLimit, (req, res) => {
  const u = db.prepare("SELECT * FROM users WHERE phone=?").get(msisdn(req.body.phone));
  if (!u || !bcrypt.compareSync(String(req.body.password || ""), u.hash)) return res.status(401).json({ error: "Wrong phone number or password." });
  res.json({ token: sign(u) });
});

app.get("/api/me", auth, (req, res) => res.json(db.prepare("SELECT phone,balance FROM users WHERE id=?").get(req.uid)));

async function mpesaToken() {
  const r = await fetch(BASE + "/oauth/v1/generate?grant_type=client_credentials",
    { headers: { Authorization: "Basic " + Buffer.from(E.MPESA_KEY + ":" + E.MPESA_SECRET).toString("base64") } });
  return (await r.json()).access_token;
}

app.post("/api/deposit", auth, async (req, res) => {
  const amount = Math.floor(+req.body.amount), phone = msisdn(req.body.phone);
  if (!phone) return res.status(400).json({ error: "Enter a valid Safaricom number." });
  if (!(amount >= MIN_DEPOSIT && amount <= MAX_DEPOSIT)) return res.status(400).json({ error: `Deposit between ${MIN_DEPOSIT} and ${MAX_DEPOSIT} KES.` });
  try {
    const ts = new Date().toISOString().replace(/\D/g, "").slice(0, 14);
    const r = await fetch(BASE + "/mpesa/stkpush/v1/processrequest", {
      method: "POST",
      headers: { Authorization: "Bearer " + await mpesaToken(), "Content-Type": "application/json" },
      body: JSON.stringify({
        BusinessShortCode: E.MPESA_SHORTCODE, Timestamp: ts,
        Password: Buffer.from(E.MPESA_SHORTCODE + E.MPESA_PASSKEY + ts).toString("base64"),
        TransactionType: E.MPESA_TXN_TYPE || "CustomerPayBillOnline", Amount: amount, PartyA: phone,
        PartyB: E.MPESA_SHORTCODE, PhoneNumber: phone,
        CallBackURL: `${E.PUBLIC_URL}/api/mpesa/callback/${E.CALLBACK_SECRET}`,
        AccountReference: "BangoBets", TransactionDesc: "Deposit"
      })
    });
    const d = await r.json();
    if (d.ResponseCode !== "0") return res.status(502).json({ error: "M-Pesa could not send the prompt. Try again." });
    const ins = db.prepare("INSERT INTO deposits(user_id,amount,checkout_id) VALUES(?,?,?)").run(req.uid, amount, d.CheckoutRequestID);
    res.json({ id: ins.lastInsertRowid });
  } catch { res.status(502).json({ error: "Payment service is unavailable. Try again shortly." }); }
});

app.get("/api/deposit/:id", auth, (req, res) => {
  const d = db.prepare("SELECT status,amount FROM deposits WHERE id=? AND user_id=?").get(req.params.id, req.uid);
  d ? res.json(d) : res.status(404).json({ error: "Not found" });
});

// Safaricom calls this. Wallet is credited here only, never from the browser.
app.post("/api/mpesa/callback/:secret", (req, res) => {
  res.json({ ResultCode: 0, ResultDesc: "Accepted" });
  if (req.params.secret !== E.CALLBACK_SECRET) return;
  const cb = req.body && req.body.Body && req.body.Body.stkCallback; if (!cb) return;
  const d = db.prepare("SELECT * FROM deposits WHERE checkout_id=?").get(cb.CheckoutRequestID);
  if (!d || d.status !== "PENDING") return;
  if (cb.ResultCode !== 0) return void db.prepare("UPDATE deposits SET status='FAILED' WHERE id=?").run(d.id);
  const meta = Object.fromEntries((cb.CallbackMetadata.Item || []).map(i => [i.Name, i.Value]));
  if (Number(meta.Amount) !== d.amount) return void db.prepare("UPDATE deposits SET status='MISMATCH' WHERE id=?").run(d.id);
  db.transaction(() => {
    db.prepare("UPDATE deposits SET status='SUCCESS', receipt=? WHERE id=? AND status='PENDING'").run(meta.MpesaReceiptNumber, d.id);
    db.prepare("UPDATE users SET balance=balance+? WHERE id=?").run(d.amount, d.user_id);
  })();
});

app.listen(E.PORT || 3000, () => console.log("Bango Bets running"));
