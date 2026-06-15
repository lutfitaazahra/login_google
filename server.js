require('dotenv').config();

const express = require('express');
const session = require('express-session');
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const cors = require('cors');
const multer = require('multer');
const fs = require('fs');

const app = express();

// ==========================================
// ENVIRONMENT
// ==========================================
const FRONTEND_URL =
  process.env.FRONTEND_URL || 'http://localhost:3000';

const BACKEND_URL =
  process.env.BACKEND_URL || 'http://localhost:5000';

// ==========================================
// CORS
// ==========================================
app.use(cors({
  origin: FRONTEND_URL,
  credentials: true
}));

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// ==========================================
// SESSION
// ==========================================
if (process.env.NODE_ENV === 'production') {
  app.set('trust proxy', 1);
}

app.use(session({
  secret: process.env.SESSION_SECRET || 'secret',
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: process.env.NODE_ENV === 'production',
    httpOnly: true,
    sameSite:
      process.env.NODE_ENV === 'production'
        ? 'none'
        : 'lax'
  }
}));

// ==========================================
// PASSPORT
// ==========================================
app.use(passport.initialize());
app.use(passport.session());

passport.use(new GoogleStrategy(
  {
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: `${BACKEND_URL}/auth/google/callback`
  },
  (accessToken, refreshToken, profile, done) => {
    return done(null, profile);
  }
));

passport.serializeUser((user, done) => {
  done(null, user);
});

passport.deserializeUser((user, done) => {
  done(null, user);
});

// ==========================================
// AUTH CHECK
// ==========================================
function isLoggedIn(req, res, next) {
  if (req.isAuthenticated()) {
    return next();
  }

  return res.status(401).json({
    error: 'Silakan login terlebih dahulu.'
  });
}

// ==========================================
// MULTER (VERCEL SAFE)
// ==========================================
const uploadDir = '/tmp/uploads';

if (!fs.existsSync(uploadDir)) {
  fs.mkdirSync(uploadDir, { recursive: true });
}

const storage = multer.diskStorage({
  destination(req, file, cb) {
    cb(null, uploadDir);
  },

  filename(req, file, cb) {
    cb(null, `${Date.now()}-${file.originalname}`);
  }
});

const fileFilter = (req, file, cb) => {
  const allowedMimeTypes = [
    'image/jpeg',
    'image/png',
    'application/pdf'
  ];

  if (allowedMimeTypes.includes(file.mimetype)) {
    return cb(null, true);
  }

  cb(new Error(
    'Hanya JPG, PNG, dan PDF yang diperbolehkan.'
  ));
};

const upload = multer({
  storage,
  limits: {
    fileSize: 5 * 1024 * 1024
  },
  fileFilter
});

// ==========================================
// ROUTES
// ==========================================
app.get('/', (req, res) => {
  res.send('Backend Auth & Upload Siap Online!');
});

// GOOGLE LOGIN
app.get(
  '/auth/google',
  passport.authenticate('google', {
    scope: ['profile', 'email']
  })
);

// GOOGLE CALLBACK
app.get(
  '/auth/google/callback',
  passport.authenticate('google', {
    failureRedirect: `${FRONTEND_URL}/login?error=failed`
  }),
  (req, res) => {
    res.redirect(`${FRONTEND_URL}/dashboard`);
  }
);

// USER LOGIN STATUS
app.get('/auth/user', (req, res) => {
  if (req.isAuthenticated()) {
    return res.json({
      loggedIn: true,
      user: req.user
    });
  }

  res.json({
    loggedIn: false
  });
});

// PROTECTED ROUTE
app.get('/protected', isLoggedIn, (req, res) => {
  res.json({
    message: 'Berhasil mengakses protected route.',
    user: req.user
  });
});

// FILE UPLOAD
app.post(
  '/upload',
  upload.single('myFile'),
  (req, res) => {
    if (!req.file) {
      return res.status(400).json({
        error: 'Tidak ada file yang dipilih.'
      });
    }

    res.json({
      message: 'Upload berhasil.',
      filename: req.file.filename
    });
  },
  (error, req, res, next) => {
    res.status(400).json({
      error: error.message
    });
  }
);

// LOGOUT
app.get('/logout', (req, res, next) => {
  req.logout((err) => {
    if (err) {
      return next(err);
    }

    req.session.destroy(() => {
      res.redirect(FRONTEND_URL);
    });
  });
});

// ==========================================
// EXPORT UNTUK VERCEL
// ==========================================
module.exports = app;