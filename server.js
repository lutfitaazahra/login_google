require('dotenv').config(); // 1. WAJIB DI BARIS PALING ATAS
const express = require('express');
const session = require('express-session');
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const cors = require('cors');
const multer = require('multer');
const path = require('path');
const fs = require('fs');

const app = express();
const PORT = process.env.PORT || 5000; 

// Alamat Frontend: Jika online gunakan Vercel, jika offline gunakan localhost
const FRONTEND_URL = process.env.FRONTEND_URL || 'http://localhost:3000';
// Alamat Backend: Jika online gunakan domain hosting, jika offline gunakan localhost
const BACKEND_URL = process.env.BACKEND_URL || `http://localhost:${PORT}`;

// ==========================================
// CONFIGURASI CORS & MIDDLEWARE
// ==========================================
app.use(cors({
    origin: FRONTEND_URL, // Mengikuti alamat frontend secara dinamis
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization']
}));

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Pengaturan Proxy (Penting jika di-host di Render/Heroku agar cookie aman lewat HTTPS)
if (process.env.NODE_ENV === 'production') {
    app.set('trust proxy', 1);
}

app.use(session({
    secret: process.env.SESSION_SECRET || 'secret_fallback_key', 
    resave: false,
    saveUninitialized: false,
    cookie: {
        secure: process.env.NODE_ENV === 'production', // Otomatis true (HTTPS) jika online
        httpOnly: true,
        sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'lax' // 'none' wajib untuk cross-domain Vercel-Render
    }
}));

app.use(passport.initialize());
app.use(passport.session());

// ==========================================
// PASSPORT GOOGLE AUTH STRATEGY
// ==========================================
passport.use(new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID,         
    clientSecret: process.env.GOOGLE_CLIENT_SECRET, 
    callbackURL: `${BACKEND_URL}/auth/google/callback` // Dinamis mengikuti lokasi server
  },
  (accessToken, refreshToken, profile, done) => {
    return done(null, profile);
  }
));

passport.serializeUser((user, done) => done(null, user));
passport.deserializeUser((obj, done) => done(null, obj));

// Middleware cek login
function isLoggedIn(req, res, next) {
    if (req.isAuthenticated()) {
        return next();
    }
    return res.status(401).json({ error: 'Akses ditolak. Silakan login!' });
}

// ==========================================
// CONFIGURASI MULTER (UPLOAD FILE)
// ==========================================
const uploadDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadDir)){
    fs.mkdirSync(uploadDir, { recursive: true });
}

const storage = multer.diskStorage({
    destination: function (req, file, cb) {
        cb(null, uploadDir); 
    },
    filename: function (req, file, cb) {
        cb(null, Date.now() + '-' + file.originalname);
    }
});

const fileFilter = (req, file, cb) => {
    const allowedTypes = /jpeg|jpg|png|pdf/;
    const extname = allowedTypes.test(path.extname(file.originalname).toLowerCase());
    const mimetype = allowedTypes.test(file.mimetype);

    if (extname && mimetype) {
        return cb(null, true);
    } else {
        cb(new Error('Format tidak didukung! Hanya diperbolehkan JPG, PNG, dan PDF.'));
    }
};

const upload = multer({ 
    storage: storage,
    limits: { fileSize: 5 * 1024 * 1024 }, 
    fileFilter: fileFilter
});

// ==========================================
// ROUTING / ENDPOINTS API
// ==========================================
app.get('/', (req, res) => {
    res.send('Backend Auth & Upload Siap Online!');
});

app.get('/auth/google',
  passport.authenticate('google', { scope: ['profile', 'email'] })
);

app.get('/auth/google/callback', 
  passport.authenticate('google', { failureRedirect: `${FRONTEND_URL}/login?error=failed` }),
  (req, res) => {
    res.redirect(`${FRONTEND_URL}/dashboard`); // Otomatis mengarah ke Vercel jika online
  }
);

app.get('/auth/user', (req, res) => {
    if (req.isAuthenticated()) {
        res.json({ loggedIn: true, user: req.user });
    } else {
        res.json({ loggedIn: false });
    }
});

app.post('/upload', upload.single('myFile'), (req, res) => {
    if (!req.file) {
        return res.status(400).json({ error: 'Tidak ada file yang dipilih.' });
    }
    res.status(200).json({
        message: 'File berhasil diunggah dengan aman!',
        filename: req.file.filename,
        path: req.file.path
    });
}, (error, req, res, next) => {
    res.status(400).json({ error: error.message });
});

app.get('/logout', (req, res) => {
    req.logout((err) => {
        if (err) return next(err);
        res.redirect(`${FRONTEND_URL}/`);
    });
});

// ==========================================
// JALANKAN SERVER
// ==========================================
app.get('/logout', (req, res, next) => {
    req.logout((err) => {
        if (err) return next(err);

        res.redirect(`${FRONTEND_URL}/`);
    });
});

// WAJIB untuk Vercel
module.exports = app;