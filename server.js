// server.js
const express = require('express');
const bodyParser = require('body-parser');
const admin = require('firebase-admin');
const bcrypt = require('bcryptjs');
const cors = require('cors');
const helmet = require('helmet');
const { RateLimiterMemory } = require('rate-limiter-flexible');

// =======================
// 1. FIRE BASE INIT
// =======================
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

// =======================
// 2. EXPRESS + MIDDLEWARE
// =======================
const app = express();
app.use(helmet());
app.use(
  cors({
    origin: process.env.ALLOWED_ORIGINS
      ? process.env.ALLOWED_ORIGINS.split(',')
      : true
  })
);
app.use(bodyParser.json({ limit: '10kb' }));

// =======================
// 3. RATE LIMITER (for /login)
// =======================
const rateLimiter = new RateLimiterMemory({
  points: 5, // 5 attempts
  duration: 60 * 5 // per 5 minutes
});

// =======================
// 4. SIMPLE PASSWORD VERIFY
// =======================
async function verifyPassword(candidatePassword, storedHashOrPlain) {
  if (typeof storedHashOrPlain === 'string' && storedHashOrPlain.startsWith('$2')) {
    // bcrypt hash
    return bcrypt.compare(candidatePassword, storedHashOrPlain);
  }
  // plain text fallback
  return candidatePassword === storedHashOrPlain;
}

// =======================
// 5. IN-MEMORY FCM TOKEN STORE
//    (For testing; later you can store in RTDB if you like)
// =======================
const tokens = new Set();

// =======================
// 6. HEALTH CHECK
// =======================
app.get('/', (req, res) => {
  res.json({ ok: true, message: 'Auth + FCM server running' });
});

// =======================
// 7. REGISTER FCM TOKEN
//    POST /register
//    Body: { "token": "FCM_TOKEN_HERE" }
// =======================
app.post('/register', (req, res) => {
  const { token } = req.body;
  console.log('POST /register body:', req.body);

  if (!token) {
    return res.status(400).json({ ok: false, error: 'Missing token' });
  }

  tokens.add(token);
  console.log('Current tokens:', Array.from(tokens));

  return res.json({ ok: true, token });
});

// =======================
// 8. SEND INCOMING CALL NOTIF
//    POST /send-call
//    Body: { "patientName": "...", "channelId": "..." }
// =======================
app.post('/send-call', async (req, res) => {
  try {
    const { patientName, channelId } = req.body;
    console.log('POST /send-call body:', req.body);

    if (!patientName || !channelId) {
      return res.status(400).json({
        ok: false,
        error: 'Missing patientName or channelId'
      });
    }

    const tokenList = Array.from(tokens);
    if (tokenList.length === 0) {
      return res.status(404).json({
        ok: false,
        error: 'No tokens registered'
      });
    }

    console.log('Sending call notification to tokens:', tokenList);

    const message = {
      tokens: tokenList,

      // This part makes Android show a notif even if app is terminated
      notification: {
        title: 'Incoming TeleRHU Call',
        body: `${patientName} is calling you`
      },

      android: {
        priority: 'high',
        notification: {
          sound: 'default',
          channelId: 'telerhu_calls' // you can create/use this channel on Android later
        }
      },

      // Data payload for Flutter to read when app opens
      data: {
        type: 'call',
        patientName: patientName,
        channelId: channelId
      }
    };

    const response = await admin.messaging().sendEachForMulticast(message);
    console.log('FCM sendEachForMulticast result:', response);

    return res.json({
      ok: true,
      successCount: response.successCount,
      failureCount: response.failureCount
    });
  } catch (err) {
    console.error('Error in /send-call:', err);
    return res.status(500).json({ ok: false, error: 'Internal error' });
  }
});

// =======================
// 9. LOGIN → CUSTOM TOKEN
//    POST /login
//    Body: { username, password, anonymousUid? }
// =======================
app.post('/login', async (req, res) => {
  try {
    await rateLimiter.consume(req.ip);
  } catch (rlRejected) {
    return res.status(429).json({ error: 'Too many requests' });
  }

  const { username, password, anonymousUid } = req.body;
  if (!username || !password) {
    return res.status(400).json({ error: 'Missing username/password' });
  }

  try {
    const snap = await db
      .ref('oldUsers')
      .orderByChild('username')
      .equalTo(username)
      .once('value');

    const val = snap.val();
    if (!val) return res.status(401).json({ error: 'Invalid credentials' });

    const key = Object.keys(val)[0];
    const userRecord = val[key];

    const ok = await verifyPassword(password, userRecord.password);
    if (!ok) return res.status(401).json({ error: 'Invalid credentials' });

    // Use a stable UID for Firebase Auth
    const firebaseUid = `legacy_${key}`;

    const additionalClaims = { legacy: true };
    const token = await admin.auth().createCustomToken(firebaseUid, additionalClaims);

    return res.json({ token });
  } catch (err) {
    console.error('Login error', err);
    return res.status(500).json({ error: 'Internal error' });
  }
});

// =======================
// 10. START SERVER
// =======================
const port = process.env.PORT || 10000;
app.listen(port, () => console.log(`Auth server listening on port ${port}`));
