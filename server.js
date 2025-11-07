// server.js
const express = require('express');
const bodyParser = require('body-parser');
const admin = require('firebase-admin');
const bcrypt = require('bcryptjs');
const cors = require('cors');
const helmet = require('helmet');
const { RateLimiterMemory } = require('rate-limiter-flexible');

if (!process.env.FIREBASE_SERVICE_ACCOUNT) {
  console.error('Missing FIREBASE_SERVICE_ACCOUNT env var (JSON).');
  process.exit(1);
}

const serviceAccount = JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT);

admin.initializeApp({
  credential: admin.credential.cert(serviceAccount),
  databaseURL: process.env.FIREBASE_DATABASE_URL // set on Render
});

const db = admin.database();

const app = express();
app.use(helmet());
app.use(cors({ origin: process.env.ALLOWED_ORIGINS ? process.env.ALLOWED_ORIGINS.split(',') : true }));
app.use(bodyParser.json({ limit: '10kb' }));

const rateLimiter = new RateLimiterMemory({
  points: 5,
  duration: 60 * 5
});

async function verifyPassword(candidatePassword, storedHashOrPlain) {
  if (typeof storedHashOrPlain === 'string' && storedHashOrPlain.startsWith('$2')) {
    return bcrypt.compare(candidatePassword, storedHashOrPlain);
  }
  return candidatePassword === storedHashOrPlain;
}

app.post('/login', async (req, res) => {
  try {
    await rateLimiter.consume(req.ip);
  } catch (rlRejected) {
    return res.status(429).json({ error: 'Too many requests' });
  }

  const { username, password, anonymousUid } = req.body;
  if (!username || !password) return res.status(400).json({ error: 'Missing username/password' });

  try {
    const snap = await db.ref('oldUsers').orderByChild('username').equalTo(username).once('value');
    const val = snap.val();
    if (!val) return res.status(401).json({ error: 'Invalid credentials' });

    const key = Object.keys(val)[0];
    const userRecord = val[key];

    const ok = await verifyPassword(password, userRecord.password);
    if (!ok) return res.status(401).json({ error: 'Invalid credentials' });

    // Choose the firebase uid used for the authenticated session:
    // Use a stable mapping (e.g. legacy_{key})
    // If you want to preserve an existing anonymous UID, you can issue token with that UID (see security notes)
    const firebaseUid = `legacy_${key}`;

    // Optionally store mapping in DB (uncomment if desired)
    // await db.ref(`uidMap/${firebaseUid}`).set({ legacyKey: key, username });

    // Add optional custom claims if you want
    const additionalClaims = { legacy: true };

    const token = await admin.auth().createCustomToken(firebaseUid, additionalClaims);

    return res.json({ token });
  } catch (err) {
    console.error('Login error', err);
    return res.status(500).json({ error: 'Internal error' });
  }
});

const port = process.env.PORT || 10000;
app.listen(port, () => console.log(`Auth server listening on port ${port}`));
