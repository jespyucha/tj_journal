const dns = require('node:dns');
dns.setServers(['8.8.8.8', '1.1.1.1']);
require('dns').setDefaultResultOrder('ipv4first');

require('dotenv').config(); // This loads your secret MongoDB password from the .env file
const express = require('express');
const mongoose = require('mongoose');
const path = require('path');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cloudinary = require('cloudinary').v2;
const nodemailer = require('nodemailer');
const crypto = require('crypto');

const app = express();
const port = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'dev_secret_change_me';

cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET
});

// Middleware to parse JSON (allow screenshots)
app.use(express.json({ limit: '20mb' }));

// Tell the server to serve your frontend files from the 'public' folder
app.use(express.static(path.join(__dirname, 'public')));

// ─── MONGODB CONNECTION ──────────────────────────────────────────────
mongoose.connect(process.env.MONGO_URI)
  .then(() => console.log('✅ Connected successfully to MongoDB!'))
  .catch((err) => console.error('❌ Database connection error:', err));

// ─── DATABASE SCHEMA (What a trade looks like) ───────────────────────
// USER SCHEMA
const userSchema = new mongoose.Schema({
  email: { type: String, unique: true },
  passwordHash: String,
  resetTokenHash: String,
  resetTokenExp: Date,
  createdAt: { type: Date, default: Date.now }
});

const User = mongoose.model('User', userSchema);
const tradeSchema = new mongoose.Schema({
  userId: String,
  id: Number,
  date: String,
  asset: String,
  entryTime: String,
  exitTime: String,
  entryPrice: Number,
  exitPrice: Number,
  qty: Number,
  pnl: Number,
  netPnl: Number,
  fee: Number,
  result: String,
  direction: String,
  model: String,
  buyFillId: Number,
  sellFillId: Number,
  source: String
});

// Create the Trade model
const Trade = mongoose.model('Trade', tradeSchema);

// Journal schema
const journalSchema = new mongoose.Schema({
  userId: String,
  id: Number,
  date: String,
  asset: String,
  direction: String,
  confluences: [String],
  trend: String,
  reason: String,
  mgmt: String,
  plan: String,
  right: String,
  wrong: String,
  mistakes: [String],
  lesson: String,
  ratingSetup: Number,
  ratingExec: Number,
  ratingConf: Number,
  screenshot: String,
  screenshotName: String,
  screenshotId: String,
  sl: Number,
  tp: Number,
  rr: String
});

const Journal = mongoose.model('Journal', journalSchema);

// ─── ROUTES ──────────────────────────────────────────────────────────

// AUTH MIDDLEWARE
function auth(req, res, next) {
  const header = req.headers.authorization || '';
  const token = header.startsWith('Bearer ') ? header.slice(7) : null;
  if (!token) return res.status(401).json({ message: 'Unauthorized' });
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    req.userId = payload.userId;
    req.userEmail = payload.email;
    next();
  } catch (err) {
    return res.status(401).json({ message: 'Unauthorized' });
  }
}

// AUTH ROUTES
app.post('/api/auth/register', async (req, res) => {
  try {
    const { email, password } = req.body || {};
    if (!email || !password) return res.status(400).json({ message: 'Email and password required' });
    const existing = await User.findOne({ email });
    if (existing) return res.status(409).json({ message: 'Account already exists' });
    const passwordHash = await bcrypt.hash(password, 10);
    const user = await User.create({ email, passwordHash });
    const token = jwt.sign({ userId: user._id.toString(), email: user.email }, JWT_SECRET, { expiresIn: '7d' });
    res.json({ token, user: { id: user._id.toString(), email: user.email } });
  } catch (err) {
    console.error(err);
    res.status(500).send('Error registering');
  }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body || {};
    if (!email || !password) return res.status(400).json({ message: 'Email and password required' });
    const user = await User.findOne({ email });
    if (!user) return res.status(401).json({ message: 'Invalid credentials' });
    const ok = await bcrypt.compare(password, user.passwordHash);
    if (!ok) return res.status(401).json({ message: 'Invalid credentials' });
    const token = jwt.sign({ userId: user._id.toString(), email: user.email }, JWT_SECRET, { expiresIn: '7d' });
    res.json({ token, user: { id: user._id.toString(), email: user.email } });
  } catch (err) {
    console.error(err);
    res.status(500).send('Error logging in');
  }
});

app.get('/api/me', auth, async (req, res) => {
  res.json({ id: req.userId, email: req.userEmail });
});

// PASSWORD RESET (EMAIL)
app.post('/api/auth/request-reset', async (req, res) => {
  try {
    const { email } = req.body || {};
    if (!email) return res.json({ message: 'If account exists, email sent' });
    const user = await User.findOne({ email });
    if (!user) return res.json({ message: 'If account exists, email sent' });

    const token = crypto.randomBytes(32).toString('hex');
    const hash = crypto.createHash('sha256').update(token).digest('hex');
    user.resetTokenHash = hash;
    user.resetTokenExp = new Date(Date.now() + 1000 * 60 * 60);
    await user.save();

    const appUrl = process.env.APP_URL || `http://localhost:${port}`;
    const resetUrl = `${appUrl}/?reset_token=${token}`;

    if (process.env.SMTP_HOST && process.env.SMTP_USER && process.env.SMTP_PASS) {
      const transporter = nodemailer.createTransport({
        host: process.env.SMTP_HOST,
        port: parseInt(process.env.SMTP_PORT || '587'),
        secure: process.env.SMTP_SECURE === 'true',
        auth: { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS }
      });
      await transporter.sendMail({
        from: process.env.SMTP_FROM || process.env.SMTP_USER,
        to: email,
        subject: 'Reset your Trading Journal password',
        text: `Reset your password using this link: ${resetUrl}`
      });
    } else {
      console.log('Password reset link (SMTP not configured):', resetUrl);
    }

    res.json({ message: 'If account exists, email sent' });
  } catch (err) {
    console.error(err);
    res.status(500).send('Error requesting reset');
  }
});

app.post('/api/auth/reset', async (req, res) => {
  try {
    const { token, newPassword } = req.body || {};
    if (!token || !newPassword || newPassword.length < 8) {
      return res.status(400).json({ message: 'Invalid reset' });
    }
    const hash = crypto.createHash('sha256').update(token).digest('hex');
    const user = await User.findOne({ resetTokenHash: hash, resetTokenExp: { $gt: new Date() } });
    if (!user) return res.status(400).json({ message: 'Invalid or expired token' });
    user.passwordHash = await bcrypt.hash(newPassword, 10);
    user.resetTokenHash = null;
    user.resetTokenExp = null;
    await user.save();
    res.json({ message: 'Password updated' });
  } catch (err) {
    console.error(err);
    res.status(500).send('Error resetting password');
  }
});

// USER SETTINGS
app.post('/api/user/password', auth, async (req, res) => {
  try {
    const { currentPassword, newPassword } = req.body || {};
    if (!currentPassword || !newPassword || newPassword.length < 8) {
      return res.status(400).json({ message: 'Invalid password' });
    }
    const user = await User.findById(req.userId);
    if (!user) return res.status(404).json({ message: 'User not found' });
    const ok = await bcrypt.compare(currentPassword, user.passwordHash);
    if (!ok) return res.status(401).json({ message: 'Invalid credentials' });
    user.passwordHash = await bcrypt.hash(newPassword, 10);
    await user.save();
    res.json({ message: 'Password updated' });
  } catch (err) {
    console.error(err);
    res.status(500).send('Error updating password');
  }
});

app.post('/api/user/clear', auth, async (req, res) => {
  try {
    const journalsWithShots = await Journal.find({ userId: req.userId, screenshotId: { $exists: true, $ne: null, $ne: '' } }, { screenshotId: 1 });
    const shotIds = journalsWithShots.map(j => j.screenshotId).filter(Boolean);

    const trades = await Trade.deleteMany({ userId: req.userId });
    const journals = await Journal.deleteMany({ userId: req.userId });

    if (process.env.CLOUDINARY_CLOUD_NAME && process.env.CLOUDINARY_API_KEY && process.env.CLOUDINARY_API_SECRET) {
      await Promise.allSettled(shotIds.map(id => cloudinary.uploader.destroy(id, { invalidate: true })));
    }

    res.json({ trades: trades.deletedCount || 0, journals: journals.deletedCount || 0, screenshots: shotIds.length });
  } catch (err) {
    console.error(err);
    res.status(500).send('Error clearing data');
  }
});
app.post('/api/screenshots', auth, async (req, res) => {
  try {
    const { dataUrl, filename } = req.body || {};
    if (!dataUrl) return res.status(400).json({ message: 'No image provided' });
    if (!process.env.CLOUDINARY_CLOUD_NAME || !process.env.CLOUDINARY_API_KEY || !process.env.CLOUDINARY_API_SECRET) {
      return res.status(501).json({ message: 'Cloudinary not configured' });
    }
    const baseName = filename ? path.parse(filename).name.replace(/[^a-zA-Z0-9-_]/g,'') : 'screenshot';
    const result = await cloudinary.uploader.upload(dataUrl, {
      folder: `trading-journal/${req.userId}`,
      public_id: baseName + '-' + Date.now(),
      resource_type: 'image'
    });
    res.json({ url: result.secure_url, publicId: result.public_id });
  } catch (err) {
    console.error(err);
    res.status(500).send('Error uploading screenshot');
  }
});
app.post('/api/migrate/claim', auth, async (req, res) => {
  try {
    const legacyFilter = { $or: [ { userId: { $exists: false } }, { userId: null }, { userId: '' } ] };
    const tradeResult = await Trade.updateMany(legacyFilter, { $set: { userId: req.userId } });
    const journalResult = await Journal.updateMany(legacyFilter, { $set: { userId: req.userId } });
    res.json({ trades: tradeResult.modifiedCount || 0, journals: journalResult.modifiedCount || 0 });
  } catch (err) {
    console.error(err);
    res.status(500).send('Error claiming legacy data');
  }
});
// 1. GET route to fetch all trades from the database
app.get('/api/trades', auth, async (req, res) => {
  try {
    const trades = await Trade.find({ userId: req.userId }); // Fetches everything
    res.json(trades);
  } catch (err) {
    console.error(err);
    res.status(500).send('Error fetching trades');
  }
});

// 2. POST route to save a new trade to the database
app.post('/api/trades', auth, async (req, res) => {
  try {
    const data = req.body || {};
    data.userId = req.userId;
    if (data.id) {
      const saved = await Trade.findOneAndUpdate(
        { id: data.id, userId: req.userId },
        data,
        { upsert: true, new: true, setDefaultsOnInsert: true }
      );
      return res.status(200).json({ message: 'Trade saved!', trade: saved });
    }
    const newTrade = new Trade(data);
    await newTrade.save(); // Saves to MongoDB
    res.status(200).json({ message: 'Trade saved!', trade: newTrade });
  } catch (err) {
    console.error(err);
    res.status(500).send('Error saving trade');
  }
});

// 3. POST route to save many trades (bulk CSV import)
app.post('/api/trades/bulk', auth, async (req, res) => {
  try {
    const trades = req.body.trades;
    if (!Array.isArray(trades)) {
      return res.status(400).json({ message: 'Trades must be an array' });
    }
    const ops = trades.map(t => {
      t.userId = req.userId;
      if (t && t.id) {
        return {
          updateOne: {
            filter: { id: t.id, userId: req.userId },
            update: t,
            upsert: true
          }
        };
      }
      return { insertOne: { document: t } };
    });
    const result = await Trade.bulkWrite(ops, { ordered: true });
    res.status(200).json({ message: 'Trades saved!', count: result.insertedCount + result.upsertedCount + result.modifiedCount });
  } catch (err) {
    console.error(err);
    res.status(500).send('Error saving trades');
  }
});

// 4. PUT route to update a trade by id
app.put('/api/trades/:id', auth, async (req, res) => {
  try {
    const id = parseInt(req.params.id);
    const data = req.body || {};
    data.userId = req.userId;
    const saved = await Trade.findOneAndUpdate(
      { id, userId: req.userId },
      { ...data, id, userId: req.userId },
      { upsert: true, new: true, setDefaultsOnInsert: true }
    );
    res.status(200).json({ message: 'Trade updated!', trade: saved });
  } catch (err) {
    console.error(err);
    res.status(500).send('Error updating trade');
  }
});

// 5. DELETE route to remove a trade by id
app.delete('/api/trades/:id', auth, async (req, res) => {
  try {
    const id = parseInt(req.params.id);
    await Trade.deleteOne({ id, userId: req.userId });
    res.status(200).json({ message: 'Trade deleted!' });
  } catch (err) {
    console.error(err);
    res.status(500).send('Error deleting trade');
  }
});

// JOURNAL ROUTES
app.get('/api/journal', auth, async (req, res) => {
  try {
    const entries = await Journal.find({ userId: req.userId });
    res.json(entries);
  } catch (err) {
    console.error(err);
    res.status(500).send('Error fetching journal entries');
  }
});

app.put('/api/journal/:id', auth, async (req, res) => {
  try {
    const id = parseInt(req.params.id);
    const data = req.body || {};
    data.userId = req.userId;
    const saved = await Journal.findOneAndUpdate(
      { id, userId: req.userId },
      { ...data, id, userId: req.userId },
      { upsert: true, new: true, setDefaultsOnInsert: true }
    );
    res.status(200).json({ message: 'Journal saved!', entry: saved });
  } catch (err) {
    console.error(err);
    res.status(500).send('Error saving journal');
  }
});

app.delete('/api/journal/:id', auth, async (req, res) => {
  try {
    const id = parseInt(req.params.id);
    const entry = await Journal.findOne({ id, userId: req.userId });
    await Journal.deleteOne({ id, userId: req.userId });
    if (entry && entry.screenshotId && process.env.CLOUDINARY_CLOUD_NAME && process.env.CLOUDINARY_API_KEY && process.env.CLOUDINARY_API_SECRET) {
      await cloudinary.uploader.destroy(entry.screenshotId, { invalidate: true });
    }
    res.status(200).json({ message: 'Journal deleted!' });
  } catch (err) {
    console.error(err);
    res.status(500).send('Error deleting journal');
  }
});

// ─── START SERVER ────────────────────────────────────────────────────
app.listen(port, () => {
  console.log(`🚀 Server is running on http://localhost:${port}`);
});













