const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const path = require('path');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const { Pool } = require('pg');

const app = express();
const PORT = process.env.PORT || 3000;

// Railway/proxy arkasında çalışırken IP tespiti için
app.set('trust proxy', 1);

// PostgreSQL Bağlantısı
if (!process.env.DATABASE_URL) {
  console.error('❌ HATA: DATABASE_URL environment variable tanımlı değil!');
  console.error('Railway üzerinde PostgreSQL servisi ekleyip DATABASE_URL değişkenini ayarlayın.');
  process.exit(1);
}

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL.includes('localhost') || process.env.DATABASE_URL.includes('127.0.0.1')
    ? false
    : { rejectUnauthorized: false },
  connectionTimeoutMillis: 8000,
  idleTimeoutMillis: 20000,
  max: 3  // Railway free tier için düşük tut
});

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  validate: { xForwardedForHeader: false }
});

// Middleware
app.use(helmet({
  contentSecurityPolicy: false,
  crossOriginEmbedderPolicy: false
}));
app.use(cors({
  origin: [
    'https://www.pro-bul.online',
    'https://pro-bul.online',
    'https://pro-bul-server-production.up.railway.app',
    /\.railway\.app$/
  ],
  credentials: true
}));
// Genel istekler için küçük limit
app.use((req, res, next) => {
  // Fotoğraf yükleme route'larına 2MB, diğerlerine 100KB
  const photoRoutes = ['/api/register', '/api/profile/'];
  const isPhotoRoute = photoRoutes.some(r => req.path.startsWith(r));
  express.json({ limit: isPhotoRoute ? '2mb' : '100kb' })(req, res, next);
});
app.use(limiter);
app.use(express.static('public'));

// OTP store - otomatik temizlik ile
const otpStore = new Map();
// 10 dakikada bir süresi dolmuş OTP'leri temizle
setInterval(() => {
  const now = Date.now();
  for (const [key, val] of otpStore.entries()) {
    if (val.expires < now) otpStore.delete(key);
  }
}, 10 * 60 * 1000);

// Veritabanı tablolarını oluştur
async function initDatabase() {
  try {
    // Users tablosu
    await pool.query(`
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        name VARCHAR(100) NOT NULL,
        email VARCHAR(255) UNIQUE NOT NULL,
        phone VARCHAR(20),
        password VARCHAR(255) NOT NULL,
        profile_photo TEXT,
        bio TEXT,
        location VARCHAR(255),
        favorite_sports TEXT[],
        is_admin BOOLEAN DEFAULT false,
        is_online BOOLEAN DEFAULT false,
        last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // Listings tablosu
    await pool.query(`
      CREATE TABLE IF NOT EXISTS listings (
        id SERIAL PRIMARY KEY,
        user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
        sport VARCHAR(50) NOT NULL,
        location VARCHAR(255) NOT NULL,
        latitude DECIMAL(10, 8),
        longitude DECIMAL(11, 8),
        date DATE NOT NULL,
        time VARCHAR(10) NOT NULL,
        duration INTEGER NOT NULL,
        player_count INTEGER NOT NULL,
        current_players INTEGER DEFAULT 1,
        skill_level VARCHAR(50) NOT NULL,
        description TEXT,
        notes TEXT,
        status VARCHAR(20) DEFAULT 'active',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // Messages tablosu
    await pool.query(`
      CREATE TABLE IF NOT EXISTS messages (
        id SERIAL PRIMARY KEY,
        sender_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
        receiver_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
        listing_id INTEGER REFERENCES listings(id) ON DELETE SET NULL,
        message TEXT NOT NULL,
        is_read BOOLEAN DEFAULT false,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // Listing participants tablosu
    await pool.query(`
      CREATE TABLE IF NOT EXISTS listing_participants (
        id SERIAL PRIMARY KEY,
        listing_id INTEGER REFERENCES listings(id) ON DELETE CASCADE,
        user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
        joined_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        UNIQUE(listing_id, user_id)
      )
    `);

    // Notifications tablosu
    await pool.query(`
      CREATE TABLE IF NOT EXISTS notifications (
        id SERIAL PRIMARY KEY,
        user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
        type VARCHAR(50) NOT NULL,
        title VARCHAR(255) NOT NULL,
        message TEXT NOT NULL,
        link VARCHAR(255),
        is_read BOOLEAN DEFAULT false,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // Arkadaşlık sistemi
    await pool.query(`
      CREATE TABLE IF NOT EXISTS friendships (
        id SERIAL PRIMARY KEY,
        requester_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
        addressee_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
        status VARCHAR(20) DEFAULT 'pending',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        UNIQUE(requester_id, addressee_id)
      )
    `);

    // Admin logs tablosu
    await pool.query(`
      CREATE TABLE IF NOT EXISTS admin_logs (
        id SERIAL PRIMARY KEY,
        admin_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
        action VARCHAR(100) NOT NULL,
        target_type VARCHAR(50),
        target_id INTEGER,
        details TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // İlk admin kullanıcısını oluştur (varsa güncelle)
    const adminEmail = process.env.ADMIN_EMAIL || 'admin@probul.com';
    const adminPassword = process.env.ADMIN_PASSWORD || 'admin123';
    const hashedPassword = await bcrypt.hash(adminPassword, 10);

    await pool.query(`
      INSERT INTO users (name, email, password, is_admin)
      VALUES ($1, $2, $3, true)
      ON CONFLICT (email) 
      DO UPDATE SET is_admin = true
    `, ['Admin', adminEmail, hashedPassword]);

    console.log('✅ Veritabanı tabloları hazır');
    console.log(`👤 Admin: ${adminEmail} / ${adminPassword}`);
    return true;
  } catch (error) {
    console.error('❌ Veritabanı init hatası:', error.message);
    return false;
  }
}

// Resend HTTP API ile email gönder (SMTP yerine, port sorunu olmaz)
async function sendEmail(to, subject, html) {
  const response = await fetch('https://api.resend.com/emails', {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${process.env.RESEND_API_KEY}`,
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({
      from: process.env.EMAIL_FROM || 'onboarding@resend.dev',
      to,
      subject,
      html
    })
  });

  const data = await response.json();

  if (!response.ok) {
    throw new Error(data.message || 'Email gönderilemedi');
  }

  return data;
}

// Bildirim gönderme helper
async function createNotification(userId, type, title, message, link = null) {
  try {
    await pool.query(
      `INSERT INTO notifications (user_id, type, title, message, link) 
       VALUES ($1, $2, $3, $4, $5)`,
      [userId, type, title, message, link]
    );
  } catch (error) {
    console.error('Bildirim oluşturma hatası:', error);
  }
}

// Admin log helper
async function logAdminAction(adminId, action, targetType, targetId, details) {
  try {
    await pool.query(
      `INSERT INTO admin_logs (admin_id, action, target_type, target_id, details) 
       VALUES ($1, $2, $3, $4, $5)`,
      [adminId, action, targetType, targetId, details]
    );
  } catch (error) {
    console.error('Admin log hatası:', error);
  }
}

// ============================================
// OTP ENDPOINTs
// ============================================

app.post('/api/send-otp', async (req, res) => {
  try {
    const { email, fullName, phone, password, photo } = req.body;
    
    if (!email) {
      return res.status(400).json({ error: 'E-posta adresi gerekli' });
    }

    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    
    // Kayıt verilerini OTP ile birlikte sakla
    otpStore.set(email, {
      code: otp,
      expires: Date.now() + 5 * 60 * 1000,
      pendingUser: { fullName, phone, password, photo }
    });

    try {
      await sendEmail(
        email,
        'Pro-Bul Doğrulama Kodu',
        `<h2>Doğrulama Kodunuz</h2>
          <p>Pro-Bul hesabınızı doğrulamak için aşağıdaki kodu kullanın:</p>
          <h1 style="color: #ff6b35; font-size: 32px; letter-spacing: 5px;">${otp}</h1>
          <p>Bu kod 5 dakika geçerlidir.</p>`
      );

      res.json({ success: true, ok: true, message: 'Doğrulama kodu gönderildi' });
    } catch (emailError) {
      console.error('[send-otp] Email hatası:', emailError.message);
      res.status(500).json({ 
        error: 'E-posta gönderilemedi',
        details: emailError.message 
      });
    }
  } catch (error) {
    console.error('[send-otp] Hata:', error);
    res.status(500).json({ error: 'Sunucu hatası' });
  }
});

app.post('/api/verify-otp', async (req, res) => {
  try {
    const { email, otp, code } = req.body;
    const otpCode = otp || code;
    
    const stored = otpStore.get(email);
    
    if (!stored) {
      return res.status(400).json({ error: 'Doğrulama kodu bulunamadı' });
    }
    
    if (Date.now() > stored.expires) {
      otpStore.delete(email);
      return res.status(400).json({ error: 'Doğrulama kodu süresi doldu' });
    }
    
    if (stored.code !== otpCode) {
      return res.status(400).json({ error: 'Geçersiz doğrulama kodu' });
    }
    
    const pendingUser = stored.pendingUser;
    otpStore.delete(email);

    // Kayıt verisi varsa kullanıcıyı oluştur
    if (pendingUser && pendingUser.password) {
      try {
        const existing = await pool.query('SELECT id FROM users WHERE email = $1', [email]);
        if (existing.rows.length > 0) {
          return res.json({ success: true, ok: true, message: 'Kullanıcı zaten kayıtlı' });
        }
        const hashedPassword = await bcrypt.hash(pendingUser.password, 10);
        const result = await pool.query(
          `INSERT INTO users (name, email, phone, password, profile_photo) 
           VALUES ($1, $2, $3, $4, $5) 
           RETURNING id, name, email, phone, profile_photo, is_admin`,
          [pendingUser.fullName || email.split('@')[0], email, pendingUser.phone || null, 
           hashedPassword, pendingUser.photo || null]
        );
        const user = result.rows[0];
        await pool.query(
          `INSERT INTO notifications (user_id, type, title, message, link) VALUES ($1, $2, $3, $4, $5)`,
          [user.id, 'welcome', 'Hoş Geldin!', "Pro-Bul'a katıldığın için teşekkürler!", '/']
        );
        return res.json({ 
          success: true, ok: true, message: 'Kayıt ve doğrulama başarılı',
          user: { id: user.id, name: user.name, fullName: user.name, email: user.email, 
                  phone: user.phone, profilePhoto: user.profile_photo, isAdmin: user.is_admin }
        });
      } catch (regError) {
        console.error('[verify-otp] Kayıt hatası:', regError.message);
        return res.status(500).json({ error: 'Kayıt tamamlanamadı: ' + regError.message });
      }
    }

    res.json({ success: true, ok: true, message: 'Doğrulama başarılı' });
  } catch (error) {
    console.error('[verify-otp] Hata:', error);
    res.status(500).json({ error: 'Sunucu hatası' });
  }
});

app.post('/api/resend-otp', async (req, res) => {
  try {
    const { email } = req.body;
    if (!email) return res.status(400).json({ success: false, error: 'Email gerekli' });

    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    otpStore.set(email, { code: otp, expires: Date.now() + 5 * 60 * 1000 });

    await sendEmail(
      email,
      'Pro-Bul Doğrulama Kodu',
      `<h2>Yeni Doğrulama Kodunuz</h2>
        <p>Pro-Bul hesabınızı doğrulamak için aşağıdaki kodu kullanın:</p>
        <h1 style="color: #ff6b35; font-size: 32px; letter-spacing: 5px;">${otp}</h1>
        <p>Bu kod 5 dakika geçerlidir.</p>`
    );

    res.json({ success: true, ok: true, message: 'Yeni kod gönderildi' });
  } catch (error) {
    console.error('[resend-otp] Hata:', error.message);
    res.status(500).json({ success: false, error: 'Kod gönderilemedi' });
  }
});

// ============================================
// AUTH ENDPOINTs
// ============================================

app.post('/api/register', async (req, res) => {
  try {
    const { name, email, phone, password, profilePhoto } = req.body;

    const existing = await pool.query('SELECT id FROM users WHERE email = $1', [email]);
    if (existing.rows.length > 0) {
      return res.status(400).json({ error: 'Bu e-posta zaten kayıtlı' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    // Base64 fotoğrafı DB'ye yazma - sadece URL kabul et (bellek tasarrufu)
    let photoToSave = null;
    if (profilePhoto && !profilePhoto.startsWith('data:')) {
      photoToSave = profilePhoto; // URL ise kaydet
    }
    // Base64 ise sil - çok büyük, OOM yapıyor

    const result = await pool.query(
      `INSERT INTO users (name, email, phone, password, profile_photo) 
       VALUES ($1, $2, $3, $4, $5) 
       RETURNING id, name, email, phone, profile_photo, is_admin`,
      [name, email, phone, hashedPassword, photoToSave]
    );

    const user = result.rows[0];

    // Hoş geldin bildirimi
    await createNotification(
      user.id,
      'welcome',
      'Hoş Geldin!',
      'Pro-Bul\'a katıldığın için teşekkürler! İlk ilanını oluşturabilirsin.',
      '/'
    );

    res.json({
      success: true,
      ok: true,
      message: 'Kayıt başarılı',
      user: {
        id: user.id,
        name: user.name,
        fullName: user.name,
        email: user.email,
        phone: user.phone,
        profilePhoto: user.profile_photo,
        isAdmin: user.is_admin
      }
    });
  } catch (error) {
    console.error('[register] Hata:', error);
    res.status(500).json({ error: 'Kayıt sırasında hata oluştu' });
  }
});

app.post('/api/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    const result = await pool.query('SELECT id, name, email, phone, password, profile_photo, is_admin, bio, location, favorite_sports FROM users WHERE email = $1', [email]);
    
    if (result.rows.length === 0) {
      return res.status(401).json({ error: 'E-posta veya şifre hatalı' });
    }

    const user = result.rows[0];
    const validPassword = await bcrypt.compare(password, user.password);
    
    if (!validPassword) {
      return res.status(401).json({ error: 'E-posta veya şifre hatalı' });
    }

    await pool.query(
      'UPDATE users SET is_online = true, last_seen = CURRENT_TIMESTAMP WHERE id = $1',
      [user.id]
    );

    res.json({
      success: true,
      ok: true,
      message: 'Giriş başarılı',
      user: {
        id: user.id,
        name: user.name,
        fullName: user.name,
        email: user.email,
        phone: user.phone,
        profilePhoto: user.profile_photo,
        isAdmin: user.is_admin,
        bio: user.bio,
        location: user.location,
        favoriteSports: user.favorite_sports
      }
    });
  } catch (error) {
    console.error('[login] Hata:', error);
    res.status(500).json({ error: 'Giriş sırasında hata oluştu' });
  }
});

app.post('/api/logout', async (req, res) => {
  try {
    const { userId } = req.body;
    
    await pool.query(
      'UPDATE users SET is_online = false, last_seen = CURRENT_TIMESTAMP WHERE id = $1',
      [userId]
    );

    res.json({ success: true, message: 'Çıkış yapıldı' });
  } catch (error) {
    console.error('[logout] Hata:', error);
    res.status(500).json({ error: 'Çıkış sırasında hata oluştu' });
  }
});

// ============================================
// PROFILE ENDPOINTs
// ============================================

app.get('/api/profile/:userId', async (req, res) => {
  try {
    const { userId } = req.params;
    
    const result = await pool.query(
      `SELECT id, name, email, phone, profile_photo, bio, location, 
              favorite_sports, is_admin, created_at
       FROM users WHERE id = $1`,
      [userId]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Kullanıcı bulunamadı' });
    }

    const user = result.rows[0];

    // Kullanıcının ilanlarını getir
    const listings = await pool.query(
      'SELECT * FROM listings WHERE user_id = $1 ORDER BY created_at DESC',
      [userId]
    );

    res.json({
      success: true,
      profile: {
        id: user.id,
        name: user.name,
        email: user.email,
        phone: user.phone,
        profilePhoto: user.profile_photo,
        bio: user.bio,
        location: user.location,
        favoriteSports: user.favorite_sports,
        isAdmin: user.is_admin,
        createdAt: user.created_at,
        listings: listings.rows
      }
    });
  } catch (error) {
    console.error('[get-profile] Hata:', error);
    res.status(500).json({ error: 'Profil getirilemedi' });
  }
});

app.put('/api/profile/:userId', async (req, res) => {
  try {
    const { userId } = req.params;
    const { name, phone, profilePhoto, bio, location, favoriteSports } = req.body;
    // Base64 fotoğrafı DB'ye yazma
    const safePhoto = profilePhoto && !profilePhoto.startsWith('data:') ? profilePhoto : undefined;

    const result = await pool.query(
      `UPDATE users 
       SET name = $1, phone = $2, profile_photo = $3, bio = $4, 
           location = $5, favorite_sports = $6
       WHERE id = $7
       RETURNING id, name, email, phone, profile_photo, bio, location, favorite_sports`,
      [name, phone, safePhoto !== undefined ? safePhoto : null, bio, location, favoriteSports, userId]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Kullanıcı bulunamadı' });
    }

    res.json({
      success: true,
      message: 'Profil güncellendi',
      user: result.rows[0]
    });
  } catch (error) {
    console.error('[update-profile] Hata:', error);
    res.status(500).json({ error: 'Profil güncellenemedi' });
  }
});

// ============================================
// LISTING ENDPOINTs
// ============================================

app.post('/api/listings', async (req, res) => {
  try {
    const { 
      userId, sport, location, latitude, longitude, date, time, 
      duration, playerCount, skillLevel, description, notes 
    } = req.body;

    const result = await pool.query(
      `INSERT INTO listings 
       (user_id, sport, location, latitude, longitude, date, time, duration, 
        player_count, skill_level, description, notes) 
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12) 
       RETURNING *`,
      [userId, sport, location, latitude || null, longitude || null, date, time, 
       duration, playerCount, skillLevel, description, notes || '']
    );

    const listing = result.rows[0];

    // İlanı oluşturan kişiyi otomatik katılımcı yap
    await pool.query(
      'INSERT INTO listing_participants (listing_id, user_id) VALUES ($1, $2)',
      [listing.id, userId]
    );

    // Kullanıcı bilgilerini al
    const userResult = await pool.query('SELECT name, profile_photo FROM users WHERE id = $1', [userId]);
    const user = userResult.rows[0];

    res.json({
      success: true,
      message: 'İlan başarıyla oluşturuldu',
      listing: {
        ...listing,
        userName: user.name,
        userPhoto: user.profile_photo
      }
    });
  } catch (error) {
    console.error('[create-listing] Hata:', error);
    res.status(500).json({ error: 'İlan oluşturulurken hata oluştu' });
  }
});

app.get('/api/listings', async (req, res) => {
  try {
    const { sport, location, date } = req.query;

    let query = `
      SELECT 
        l.*,
        u.name as user_name,
        u.profile_photo as user_photo
      FROM listings l
      JOIN users u ON l.user_id = u.id
      WHERE l.status = 'active'
    `;
    const params = [];
    let paramIndex = 1;

    if (sport && sport !== 'all') {
      query += ` AND l.sport = $${paramIndex}`;
      params.push(sport);
      paramIndex++;
    }

    if (location) {
      query += ` AND l.location ILIKE $${paramIndex}`;
      params.push(`%${location}%`);
      paramIndex++;
    }

    if (date) {
      query += ` AND l.date = $${paramIndex}`;
      params.push(date);
      paramIndex++;
    }

    query += ' ORDER BY l.created_at DESC';

    const result = await pool.query(query, params);

    res.json({
      success: true,
      listings: result.rows.map(row => ({
        id: row.id,
        userId: row.user_id,
        userName: row.user_name,
        userPhoto: row.user_photo,
        sport: row.sport,
        location: row.location,
        latitude: row.latitude,
        longitude: row.longitude,
        date: row.date,
        time: row.time,
        duration: row.duration,
        playerCount: row.player_count,
        currentPlayers: row.current_players,
        skillLevel: row.skill_level,
        description: row.description,
        notes: row.notes,
        status: row.status,
        createdAt: row.created_at,
        updatedAt: row.updated_at
      }))
    });
  } catch (error) {
    console.error('[get-listings] Hata:', error);
    res.status(500).json({ error: 'İlanlar getirilirken hata oluştu' });
  }
});

app.get('/api/listings/:id', async (req, res) => {
  try {
    const { id } = req.params;

    const result = await pool.query(
      `SELECT l.*, u.name as user_name, u.profile_photo as user_photo
       FROM listings l
       JOIN users u ON l.user_id = u.id
       WHERE l.id = $1`,
      [id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'İlan bulunamadı' });
    }

    res.json({
      success: true,
      listing: result.rows[0]
    });
  } catch (error) {
    console.error('[get-listing] Hata:', error);
    res.status(500).json({ error: 'İlan getirilemedi' });
  }
});

app.put('/api/listings/:id', async (req, res) => {
  try {
    const { id } = req.params;
    const { userId, sport, location, latitude, longitude, date, time, duration, playerCount, skillLevel, description, notes } = req.body;

    // İlanın sahibi mi kontrol et
    const ownerCheck = await pool.query(
      'SELECT user_id FROM listings WHERE id = $1',
      [id]
    );

    if (ownerCheck.rows.length === 0) {
      return res.status(404).json({ error: 'İlan bulunamadı' });
    }

    if (ownerCheck.rows[0].user_id !== userId) {
      return res.status(403).json({ error: 'Bu ilanı düzenleme yetkiniz yok' });
    }

    const result = await pool.query(
      `UPDATE listings 
       SET sport = $1, location = $2, latitude = $3, longitude = $4, 
           date = $5, time = $6, duration = $7, player_count = $8, 
           skill_level = $9, description = $10, notes = $11, updated_at = CURRENT_TIMESTAMP
       WHERE id = $12
       RETURNING *`,
      [sport, location, latitude, longitude, date, time, duration, playerCount, skillLevel, description, notes, id]
    );

    res.json({
      success: true,
      message: 'İlan güncellendi',
      listing: result.rows[0]
    });
  } catch (error) {
    console.error('[update-listing] Hata:', error);
    res.status(500).json({ error: 'İlan güncellenemedi' });
  }
});

app.delete('/api/listings/:id', async (req, res) => {
  try {
    const { id } = req.params;
    const { userId } = req.body;

    // İlanın sahibi mi kontrol et
    const ownerCheck = await pool.query(
      'SELECT user_id FROM listings WHERE id = $1',
      [id]
    );

    if (ownerCheck.rows.length === 0) {
      return res.status(404).json({ error: 'İlan bulunamadı' });
    }

    if (ownerCheck.rows[0].user_id !== userId) {
      return res.status(403).json({ error: 'Bu ilanı silme yetkiniz yok' });
    }

    await pool.query('DELETE FROM listings WHERE id = $1', [id]);

    res.json({
      success: true,
      message: 'İlan silindi'
    });
  } catch (error) {
    console.error('[delete-listing] Hata:', error);
    res.status(500).json({ error: 'İlan silinemedi' });
  }
});

app.post('/api/listings/:id/join', async (req, res) => {
  try {
    const { id } = req.params;
    const { userId } = req.body;

    const listingResult = await pool.query('SELECT id, user_id, sport, location, latitude, longitude, date, time, player_count, current_players, skill_level, description, notes, status FROM listings WHERE id = $1', [id]);
    
    if (listingResult.rows.length === 0) {
      return res.status(404).json({ error: 'İlan bulunamadı' });
    }

    const listing = listingResult.rows[0];

    if (listing.current_players >= listing.player_count) {
      return res.status(400).json({ error: 'İlan dolu' });
    }

    // Zaten katılmış mı kontrol et
    const existingParticipant = await pool.query(
      'SELECT id FROM listing_participants WHERE listing_id = $1 AND user_id = $2',
      [id, userId]
    );

    if (existingParticipant.rows.length > 0) {
      return res.status(400).json({ error: 'Bu ilana zaten katıldınız' });
    }

    // Katılımcı ekle
    await pool.query(
      'INSERT INTO listing_participants (listing_id, user_id) VALUES ($1, $2)',
      [id, userId]
    );

    // Katılımcı sayısını artır
    const newCount = listing.current_players + 1;
    const newStatus = newCount >= listing.player_count ? 'full' : 'active';

    await pool.query(
      'UPDATE listings SET current_players = $1, status = $2 WHERE id = $3',
      [newCount, newStatus, id]
    );

    // İlan sahibine bildirim gönder
    const joinerResult = await pool.query('SELECT name FROM users WHERE id = $1', [userId]);
    const joinerName = joinerResult.rows[0].name;

    await createNotification(
      listing.user_id,
      'listing_join',
      'Yeni Katılımcı!',
      `${joinerName} ilanınıza katıldı.`,
      `/listings/${id}`
    );

    const updatedListing = await pool.query('SELECT id, user_id, sport, location, date, time, player_count, current_players, status FROM listings WHERE id = $1', [id]);

    res.json({
      success: true,
      message: 'İlana başarıyla katıldınız',
      listing: updatedListing.rows[0]
    });
  } catch (error) {
    console.error('[join-listing] Hata:', error);
    res.status(500).json({ error: 'İlana katılırken hata oluştu' });
  }
});


// ============================================
// USERS ENDPOINTs
// ============================================

// Tüm kullanıcıları listele (arama için)
app.get('/api/users', async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT id, name, email, profile_photo, location, bio, favorite_sports, 
              is_online, last_seen, created_at
       FROM users 
       WHERE is_admin = false
       ORDER BY is_online DESC, last_seen DESC`
    );
    res.json({ success: true, users: result.rows });
  } catch (error) {
    console.error('[get-users] Hata:', error);
    res.status(500).json({ error: 'Kullanıcılar getirilemedi' });
  }
});

// Bir ilana katılan kullanıcıları getir
app.get('/api/listings/:id/participants', async (req, res) => {
  try {
    const { id } = req.params;
    const result = await pool.query(
      `SELECT u.id, u.name, u.profile_photo, u.location, u.is_online
       FROM listing_participants lp
       JOIN users u ON lp.user_id = u.id
       WHERE lp.listing_id = $1`,
      [id]
    );
    res.json({ success: true, participants: result.rows });
  } catch (error) {
    console.error('[get-participants] Hata:', error);
    res.status(500).json({ error: 'Katılımcılar getirilemedi' });
  }
});

// Kullanıcının katıldığı ilanlardaki diğer kullanıcılar (arkadaşlar)
app.get('/api/users/:userId/friends', async (req, res) => {
  try {
    const { userId } = req.params;
    const result = await pool.query(
      `SELECT DISTINCT u.id, u.name, u.profile_photo, u.location, u.is_online, u.last_seen
       FROM listing_participants lp1
       JOIN listing_participants lp2 ON lp1.listing_id = lp2.listing_id
       JOIN users u ON lp2.user_id = u.id
       WHERE lp1.user_id = $1 AND lp2.user_id != $1
       ORDER BY u.is_online DESC, u.last_seen DESC
       LIMIT 20`,
      [userId]
    );
    res.json({ success: true, friends: result.rows });
  } catch (error) {
    console.error('[get-friends] Hata:', error);
    res.status(500).json({ error: 'Arkadaşlar getirilemedi' });
  }
});

// Kullanıcının istatistiklerini getir
app.get('/api/users/:userId/stats', async (req, res) => {
  try {
    const { userId } = req.params;
    
    const gamesJoined = await pool.query(
      'SELECT COUNT(*) as count FROM listing_participants WHERE user_id = $1',
      [userId]
    );
    const gamesCreated = await pool.query(
      'SELECT COUNT(*) as count FROM listings WHERE user_id = $1',
      [userId]
    );
    const friends = await pool.query(
      `SELECT COUNT(DISTINCT lp2.user_id) as count
       FROM listing_participants lp1
       JOIN listing_participants lp2 ON lp1.listing_id = lp2.listing_id
       WHERE lp1.user_id = $1 AND lp2.user_id != $1`,
      [userId]
    );

    res.json({
      success: true,
      stats: {
        gamesJoined: parseInt(gamesJoined.rows[0].count),
        gamesCreated: parseInt(gamesCreated.rows[0].count),
        friends: parseInt(friends.rows[0].count)
      }
    });
  } catch (error) {
    console.error('[user-stats] Hata:', error);
    res.status(500).json({ error: 'İstatistikler getirilemedi' });
  }
});

// Kullanıcı konumunu güncelle
app.put('/api/users/:userId/location', async (req, res) => {
  try {
    const { userId } = req.params;
    const { latitude, longitude, locationName } = req.body;
    
    await pool.query(
      'UPDATE users SET location = $1 WHERE id = $2',
      [locationName || `${latitude},${longitude}`, userId]
    );
    
    res.json({ success: true, message: 'Konum güncellendi' });
  } catch (error) {
    console.error('[update-location] Hata:', error);
    res.status(500).json({ error: 'Konum güncellenemedi' });
  }
});

// ============================================
// MESSAGING ENDPOINTs
// ============================================

app.post('/api/messages', async (req, res) => {
  try {
    const { senderId, receiverId, message, listingId } = req.body;

    if (!senderId || !receiverId || !message) {
      return res.status(400).json({ error: 'Gerekli alanlar eksik' });
    }

    const result = await pool.query(
      `INSERT INTO messages (sender_id, receiver_id, message, listing_id) 
       VALUES ($1, $2, $3, $4) 
       RETURNING *`,
      [senderId, receiverId, message, listingId || null]
    );

    // Alıcıya bildirim gönder
    const senderResult = await pool.query('SELECT name FROM users WHERE id = $1', [senderId]);
    const senderName = senderResult.rows[0].name;

    await createNotification(
      receiverId,
      'new_message',
      'Yeni Mesaj',
      `${senderName} size mesaj gönderdi.`,
      '/messages.html'
    );

    res.json({
      success: true,
      message: 'Mesaj gönderildi',
      data: result.rows[0]
    });
  } catch (error) {
    console.error('[send-message] Hata:', error);
    res.status(500).json({ error: 'Mesaj gönderilemedi' });
  }
});

app.get('/api/messages/:userId/:otherUserId', async (req, res) => {
  try {
    const { userId, otherUserId } = req.params;

    const result = await pool.query(
      `SELECT m.*, 
              s.name as sender_name, 
              s.profile_photo as sender_photo,
              r.name as receiver_name,
              r.profile_photo as receiver_photo
       FROM messages m
       JOIN users s ON m.sender_id = s.id
       JOIN users r ON m.receiver_id = r.id
       WHERE (m.sender_id = $1 AND m.receiver_id = $2) 
          OR (m.sender_id = $2 AND m.receiver_id = $1)
       ORDER BY m.created_at ASC`,
      [userId, otherUserId]
    );

    // Okunmamış mesajları okundu olarak işaretle
    await pool.query(
      `UPDATE messages 
       SET is_read = true 
       WHERE sender_id = $1 AND receiver_id = $2 AND is_read = false`,
      [otherUserId, userId]
    );

    res.json({
      success: true,
      messages: result.rows
    });
  } catch (error) {
    console.error('[get-messages] Hata:', error);
    res.status(500).json({ error: 'Mesajlar getirilemedi' });
  }
});

app.get('/api/conversations/:userId', async (req, res) => {
  try {
    const { userId } = req.params;

    const result = await pool.query(
      `WITH ranked_messages AS (
        SELECT 
          CASE 
            WHEN sender_id = $1 THEN receiver_id 
            ELSE sender_id 
          END as other_user_id,
          message,
          created_at,
          is_read,
          ROW_NUMBER() OVER (
            PARTITION BY CASE 
              WHEN sender_id = $1 THEN receiver_id 
              ELSE sender_id 
            END 
            ORDER BY created_at DESC
          ) as rn
        FROM messages
        WHERE sender_id = $1 OR receiver_id = $1
      )
      SELECT 
        rm.other_user_id,
        u.name as other_user_name,
        u.profile_photo as other_user_photo,
        u.is_online,
        rm.message as last_message,
        rm.created_at as last_message_time,
        (SELECT COUNT(*) 
         FROM messages 
         WHERE sender_id = rm.other_user_id 
           AND receiver_id = $1 
           AND is_read = false
        ) as unread_count
      FROM ranked_messages rm
      JOIN users u ON rm.other_user_id = u.id
      WHERE rm.rn = 1
      ORDER BY rm.created_at DESC`,
      [userId]
    );

    res.json({
      success: true,
      conversations: result.rows
    });
  } catch (error) {
    console.error('[get-conversations] Hata:', error);
    res.status(500).json({ error: 'Konuşmalar getirilemedi' });
  }
});

app.get('/api/messages/unread/:userId', async (req, res) => {
  try {
    const { userId } = req.params;

    const result = await pool.query(
      'SELECT COUNT(*) as count FROM messages WHERE receiver_id = $1 AND is_read = false',
      [userId]
    );

    res.json({
      success: true,
      count: parseInt(result.rows[0].count)
    });
  } catch (error) {
    console.error('[unread-count] Hata:', error);
    res.status(500).json({ error: 'Sayı getirilemedi' });
  }
});

// ============================================
// NOTIFICATIONS ENDPOINTs
// ============================================

app.get('/api/notifications/:userId', async (req, res) => {
  try {
    const { userId } = req.params;

    const result = await pool.query(
      `SELECT * FROM notifications 
       WHERE user_id = $1 
       ORDER BY created_at DESC 
       LIMIT 50`,
      [userId]
    );

    res.json({
      success: true,
      notifications: result.rows
    });
  } catch (error) {
    console.error('[get-notifications] Hata:', error);
    res.status(500).json({ error: 'Bildirimler getirilemedi' });
  }
});

app.put('/api/notifications/:id/read', async (req, res) => {
  try {
    const { id } = req.params;

    await pool.query(
      'UPDATE notifications SET is_read = true WHERE id = $1',
      [id]
    );

    res.json({
      success: true,
      message: 'Bildirim okundu olarak işaretlendi'
    });
  } catch (error) {
    console.error('[mark-notification-read] Hata:', error);
    res.status(500).json({ error: 'Bildirim güncellenemedi' });
  }
});

app.get('/api/notifications/unread/:userId', async (req, res) => {
  try {
    const { userId } = req.params;

    const result = await pool.query(
      'SELECT COUNT(*) as count FROM notifications WHERE user_id = $1 AND is_read = false',
      [userId]
    );

    res.json({
      success: true,
      count: parseInt(result.rows[0].count)
    });
  } catch (error) {
    console.error('[unread-notifications] Hata:', error);
    res.status(500).json({ error: 'Sayı getirilemedi' });
  }
});

// ============================================
// ADMIN ENDPOINTs
// ============================================

// Admin kontrolü middleware
function requireAdmin(req, res, next) {
  const adminId = req.body.adminId || req.query.adminId;
  
  if (!adminId) {
    return res.status(401).json({ error: 'Yetkisiz erişim' });
  }

  pool.query('SELECT is_admin FROM users WHERE id = $1', [adminId])
    .then(result => {
      if (result.rows.length === 0 || !result.rows[0].is_admin) {
        return res.status(403).json({ error: 'Admin yetkisi gerekli' });
      }
      next();
    })
    .catch(err => {
      console.error('Admin kontrol hatası:', err);
      res.status(500).json({ error: 'Sunucu hatası' });
    });
}

// Admin dashboard istatistikleri
app.get('/api/admin/stats', requireAdmin, async (req, res) => {
  try {
    const stats = await pool.query(`
      SELECT 
        (SELECT COUNT(*) FROM users) as total_users,
        (SELECT COUNT(*) FROM users WHERE is_online = true) as online_users,
        (SELECT COUNT(*) FROM listings) as total_listings,
        (SELECT COUNT(*) FROM listings WHERE status = 'active') as active_listings,
        (SELECT COUNT(*) FROM messages) as total_messages,
        (SELECT COUNT(*) FROM notifications) as total_notifications
    `);

    const recentUsers = await pool.query(
      'SELECT id, name, email, created_at FROM users ORDER BY created_at DESC LIMIT 10'
    );

    const recentListings = await pool.query(
      `SELECT l.*, u.name as user_name 
       FROM listings l 
       JOIN users u ON l.user_id = u.id 
       ORDER BY l.created_at DESC LIMIT 10`
    );

    res.json({
      success: true,
      stats: stats.rows[0],
      recentUsers: recentUsers.rows,
      recentListings: recentListings.rows
    });
  } catch (error) {
    console.error('[admin-stats] Hata:', error);
    res.status(500).json({ error: 'İstatistikler getirilemedi' });
  }
});

// Tüm kullanıcıları listele
app.get('/api/admin/users', requireAdmin, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT id, name, email, phone, is_admin, is_online, created_at, last_seen
       FROM users 
       ORDER BY created_at DESC`
    );

    res.json({
      success: true,
      users: result.rows
    });
  } catch (error) {
    console.error('[admin-users] Hata:', error);
    res.status(500).json({ error: 'Kullanıcılar getirilemedi' });
  }
});

// Kullanıcı sil
app.delete('/api/admin/users/:id', requireAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    const { adminId } = req.body;

    await pool.query('DELETE FROM users WHERE id = $1', [id]);
    await logAdminAction(adminId, 'DELETE_USER', 'user', id, 'Kullanıcı silindi');

    res.json({
      success: true,
      message: 'Kullanıcı silindi'
    });
  } catch (error) {
    console.error('[admin-delete-user] Hata:', error);
    res.status(500).json({ error: 'Kullanıcı silinemedi' });
  }
});

// Tüm ilanları listele
app.get('/api/admin/listings', requireAdmin, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT l.*, u.name as user_name, u.email as user_email
       FROM listings l
       JOIN users u ON l.user_id = u.id
       ORDER BY l.created_at DESC`
    );

    res.json({
      success: true,
      listings: result.rows
    });
  } catch (error) {
    console.error('[admin-listings] Hata:', error);
    res.status(500).json({ error: 'İlanlar getirilemedi' });
  }
});

// İlan sil (admin)
app.delete('/api/admin/listings/:id', requireAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    const { adminId } = req.body;

    await pool.query('DELETE FROM listings WHERE id = $1', [id]);
    await logAdminAction(adminId, 'DELETE_LISTING', 'listing', id, 'İlan silindi');

    res.json({
      success: true,
      message: 'İlan silindi'
    });
  } catch (error) {
    console.error('[admin-delete-listing] Hata:', error);
    res.status(500).json({ error: 'İlan silinemedi' });
  }
});

// İlan düzenle (admin)
app.put('/api/admin/listings/:id', requireAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    const { adminId, status } = req.body;

    await pool.query(
      'UPDATE listings SET status = $1, updated_at = CURRENT_TIMESTAMP WHERE id = $2',
      [status, id]
    );

    await logAdminAction(adminId, 'UPDATE_LISTING', 'listing', id, `Durum: ${status}`);

    res.json({
      success: true,
      message: 'İlan güncellendi'
    });
  } catch (error) {
    console.error('[admin-update-listing] Hata:', error);
    res.status(500).json({ error: 'İlan güncellenemedi' });
  }
});

// Admin logları
app.get('/api/admin/logs', requireAdmin, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT al.*, u.name as admin_name
       FROM admin_logs al
       LEFT JOIN users u ON al.admin_id = u.id
       ORDER BY al.created_at DESC
       LIMIT 100`
    );

    res.json({
      success: true,
      logs: result.rows
    });
  } catch (error) {
    console.error('[admin-logs] Hata:', error);
    res.status(500).json({ error: 'Loglar getirilemedi' });
  }
});

// ============================================
// ŞİFRE SIFIRLAMA ENDPOINTLERİ
// ============================================

app.post('/api/forgot-password', async (req, res) => {
  try {
    const { email } = req.body;
    if (!email) return res.status(400).json({ success: false, error: 'Email gerekli' });

    const result = await pool.query('SELECT id FROM users WHERE email = $1', [email]);
    if (result.rows.length === 0) {
      // Güvenlik için kullanıcı bulunamasa da başarılı döndür
      return res.json({ success: true, ok: true, message: 'Kod gönderildi' });
    }

    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    otpStore.set('reset_' + email, {
      code: otp,
      expires: Date.now() + 5 * 60 * 1000
    });

    try {
      await sendEmail(
        email,
        'Pro-Bul Şifre Sıfırlama',
        `<h2>Şifre Sıfırlama Kodunuz</h2>
          <p>Şifrenizi sıfırlamak için aşağıdaki kodu kullanın:</p>
          <h1 style="color: #ff6b35; font-size: 32px; letter-spacing: 5px;">${otp}</h1>
          <p>Bu kod 5 dakika geçerlidir.</p>`
      );
    } catch(emailErr) {
      console.error('[forgot-password] Email gönderilemedi:', emailErr.message);
      // Email gönderilemese de devam et, kullanıcıya hata gösterme
    }

    res.json({ success: true, ok: true, message: 'Sıfırlama kodu gönderildi' });
  } catch (error) {
    console.error('[forgot-password] Hata:', error.message);
    res.status(500).json({ success: false, error: 'Kod gönderilemedi' });
  }
});

app.post('/api/reset-password', async (req, res) => {
  try {
    const { email, code, newPassword } = req.body;
    if (!email || !code || !newPassword) {
      return res.status(400).json({ success: false, error: 'Tüm alanlar gerekli' });
    }

    const stored = otpStore.get('reset_' + email);
    if (!stored) return res.status(400).json({ success: false, error: 'Kod bulunamadı veya süresi doldu' });
    if (Date.now() > stored.expires) {
      otpStore.delete('reset_' + email);
      return res.status(400).json({ success: false, error: 'Kodun süresi doldu' });
    }
    if (stored.code !== code) {
      return res.status(400).json({ success: false, error: 'Geçersiz kod' });
    }

    otpStore.delete('reset_' + email);
    const hashedPassword = await bcrypt.hash(newPassword, 10);
    await pool.query('UPDATE users SET password = $1 WHERE email = $2', [hashedPassword, email]);

    res.json({ success: true, ok: true, message: 'Şifre güncellendi' });
  } catch (error) {
    console.error('[reset-password] Hata:', error.message);
    res.status(500).json({ success: false, error: 'Şifre güncellenemedi' });
  }
});

// ============================================
// STATS ENDPOINT
// ============================================

app.get('/api/stats', async (req, res) => {
  try {
    const onlineUsers = await pool.query('SELECT COUNT(*) FROM users WHERE is_online = true');
    const activeListings = await pool.query('SELECT COUNT(*) FROM listings WHERE status = $1', ['active']);
    const totalUsers = await pool.query('SELECT COUNT(*) FROM users');

    res.json({
      onlineUsers: parseInt(onlineUsers.rows[0].count),
      activeListings: parseInt(activeListings.rows[0].count),
      totalUsers: parseInt(totalUsers.rows[0].count)
    });
  } catch (error) {
    console.error('[stats] Hata:', error);
    res.status(500).json({ error: 'İstatistikler getirilemedi' });
  }
});


// ============================================================
// HEARTBEAT & ONLINE STATUS
// ============================================================
app.post('/api/users/:userId/heartbeat', async (req, res) => {
  try {
    const { userId } = req.params;
    await pool.query(
      "UPDATE users SET is_online = true, last_seen = CURRENT_TIMESTAMP WHERE id = $1",
      [userId]
    );
    res.json({ success: true });
  } catch (e) { res.status(500).json({ error: 'Heartbeat hatası' }); }
});

app.post('/api/users/:userId/offline', async (req, res) => {
  try {
    const { userId } = req.params;
    await pool.query(
      "UPDATE users SET is_online = false, last_seen = CURRENT_TIMESTAMP WHERE id = $1",
      [userId]
    );
    res.json({ success: true });
  } catch (e) { res.status(500).json({ error: 'Offline hatası' }); }
});

// 5 dakikadır heartbeat göndermeyen kullanıcıları offline yap (her dakika)
setInterval(async () => {
  try {
    await pool.query(
      "UPDATE users SET is_online = false WHERE is_online = true AND last_seen < NOW() - INTERVAL '5 minutes'"
    );
  } catch(e) {}
}, 60 * 1000);

// ============================================================
// KULLANICI ARAMA
// ============================================================
app.get('/api/users/search', async (req, res) => {
  try {
    const { q, userId } = req.query;
    if (!q || q.trim().length < 2) return res.json({ success: true, users: [] });
    const result = await pool.query(
      `SELECT id, name, profile_photo, location, is_online
       FROM users 
       WHERE (LOWER(name) LIKE LOWER($1) OR LOWER(email) LIKE LOWER($1))
         AND id != $2 AND is_admin = false
       ORDER BY is_online DESC, name ASC
       LIMIT 10`,
      ['%' + q.trim() + '%', userId || 0]
    );
    res.json({ success: true, users: result.rows });
  } catch (error) {
    console.error('[user-search] Hata:', error);
    res.status(500).json({ error: 'Arama hatası' });
  }
});

// ============================================================
// ARKADAŞLIK SİSTEMİ
// ============================================================

// Arkadaş listesi (kabul edilmiş)
app.get('/api/users/:userId/friendlist', async (req, res) => {
  try {
    const { userId } = req.params;
    const result = await pool.query(
      `SELECT u.id, u.name, u.profile_photo, u.location, u.is_online, u.last_seen, f.id as friendship_id
       FROM friendships f
       JOIN users u ON (
         CASE WHEN f.requester_id = $1 THEN f.addressee_id ELSE f.requester_id END = u.id
       )
       WHERE (f.requester_id = $1 OR f.addressee_id = $1) AND f.status = 'accepted'
       ORDER BY u.is_online DESC, u.name ASC`,
      [userId]
    );
    res.json({ success: true, friends: result.rows });
  } catch (error) {
    console.error('[friendlist] Hata:', error);
    res.status(500).json({ error: 'Arkadaşlar getirilemedi' });
  }
});

// Gelen arkadaşlık istekleri
app.get('/api/users/:userId/friend-requests', async (req, res) => {
  try {
    const { userId } = req.params;
    const result = await pool.query(
      `SELECT f.id as friendship_id, f.requester_id, f.created_at,
              u.id, u.name, u.profile_photo, u.location, u.is_online
       FROM friendships f
       JOIN users u ON f.requester_id = u.id
       WHERE f.addressee_id = $1 AND f.status = 'pending'
       ORDER BY f.created_at DESC`,
      [userId]
    );
    res.json({ success: true, requests: result.rows });
  } catch (error) {
    console.error('[friend-requests] Hata:', error);
    res.status(500).json({ error: 'İstekler getirilemedi' });
  }
});

// Arkadaşlık isteği gönder
app.post('/api/users/:userId/friend-request', async (req, res) => {
  try {
    const { userId } = req.params;
    const { targetId } = req.body;
    if (!targetId) return res.status(400).json({ error: 'Hedef kullanıcı gerekli' });
    const existing = await pool.query(
      'SELECT id, status FROM friendships WHERE (requester_id=$1 AND addressee_id=$2) OR (requester_id=$2 AND addressee_id=$1)',
      [userId, targetId]
    );
    if (existing.rows.length > 0) {
      const fr = existing.rows[0];
      if (fr.status === 'accepted') return res.json({ success: false, error: 'Zaten arkadaşsınız' });
      if (fr.status === 'pending') return res.json({ success: false, error: 'İstek zaten gönderildi' });
      // Rejected ise tekrar gönder
      await pool.query("UPDATE friendships SET status='pending', requester_id=$1, addressee_id=$2, updated_at=NOW() WHERE id=$3", [userId, targetId, fr.id]);
      return res.json({ success: true, message: 'İstek gönderildi' });
    }
    await pool.query(
      "INSERT INTO friendships (requester_id, addressee_id, status) VALUES ($1, $2, 'pending')",
      [userId, targetId]
    );
    const senderName = await pool.query('SELECT name FROM users WHERE id=$1', [userId]);
    await createNotification(targetId, 'friend_request', 'Arkadaşlık İsteği',
      (senderName.rows[0]?.name || 'Birisi') + ' sana arkadaşlık isteği gönderdi.', null);
    res.json({ success: true, message: 'İstek gönderildi' });
  } catch (error) {
    console.error('[friend-request] Hata:', error);
    res.status(500).json({ error: 'İstek gönderilemedi' });
  }
});

// Arkadaşlık isteği kabul/reddet
app.put('/api/friendships/:friendshipId', async (req, res) => {
  try {
    const { friendshipId } = req.params;
    const { action, userId } = req.body;
    const fr = await pool.query('SELECT * FROM friendships WHERE id=$1', [friendshipId]);
    if (!fr.rows.length) return res.status(404).json({ error: 'İstek bulunamadı' });
    if (fr.rows[0].addressee_id != userId) return res.status(403).json({ error: 'Yetki yok' });
    const newStatus = action === 'accept' ? 'accepted' : 'rejected';
    await pool.query('UPDATE friendships SET status=$1, updated_at=NOW() WHERE id=$2', [newStatus, friendshipId]);
    if (action === 'accept') {
      const addrName = await pool.query('SELECT name FROM users WHERE id=$1', [userId]);
      await createNotification(fr.rows[0].requester_id, 'friend_accepted', 'Arkadaşlık Kabul Edildi',
        (addrName.rows[0]?.name || 'Birisi') + ' arkadaşlık isteğini kabul etti.', null);
    }
    res.json({ success: true, status: newStatus });
  } catch (error) {
    console.error('[friendship-update] Hata:', error);
    res.status(500).json({ error: 'Güncelleme hatası' });
  }
});

// Arkadaşlıktan çıkar
app.delete('/api/friendships/:friendshipId', async (req, res) => {
  try {
    const { friendshipId } = req.params;
    const { userId } = req.body;
    const fr = await pool.query('SELECT * FROM friendships WHERE id=$1', [friendshipId]);
    if (!fr.rows.length) return res.status(404).json({ error: 'İlişki bulunamadı' });
    if (fr.rows[0].requester_id != userId && fr.rows[0].addressee_id != userId) {
      return res.status(403).json({ error: 'Yetki yok' });
    }
    await pool.query('DELETE FROM friendships WHERE id=$1', [friendshipId]);
    res.json({ success: true });
  } catch (error) {
    console.error('[friendship-delete] Hata:', error);
    res.status(500).json({ error: 'Silme hatası' });
  }
});

// ============================================
// SUNUCU BAŞLAT
// ============================================

app.listen(PORT, async () => {
  console.log(`🚀 Sunucu başlatıldı: Port ${PORT}`);
  
  const dbOk = await initDatabase();
  
  if (dbOk) {
    try {
      const stats = await pool.query(`
        SELECT 
          (SELECT COUNT(*) FROM users) as users,
          (SELECT COUNT(*) FROM listings) as listings,
          (SELECT COUNT(*) FROM messages) as messages,
          (SELECT COUNT(*) FROM notifications) as notifications
      `);
      
      console.log(`
╔═══════════════════════════════════════╗
║   🏆 PRO-BUL SERVER ÇALIŞIYOR 🏆     ║
╚═══════════════════════════════════════╝
  
📍 Port: ${PORT}
🗄️  Database: PostgreSQL ✅
👥 Kullanıcılar: ${stats.rows[0].users}
📢 İlanlar: ${stats.rows[0].listings}
💬 Mesajlar: ${stats.rows[0].messages}
🔔 Bildirimler: ${stats.rows[0].notifications}

🔒 Güvenlik: Aktif
👨‍💼 Admin Panel: Aktif
📍 Harita: Destekleniyor

✅ TAM ÖZELLİKLİ PLATFORM HAZIR!
      `);
    } catch (statsErr) {
      console.error('⚠️ İstatistikler okunamadı:', statsErr.message);
    }
  } else {
    console.error('⚠️ Veritabanına bağlanılamadı. Sunucu çalışıyor ama DB bağlantısı yok.');
    console.error('   DATABASE_URL değişkenini kontrol edin.');
  }
});

// Graceful shutdown
process.on('SIGTERM', async () => {
  console.log('🛑 Sunucu kapatılıyor...');
  await pool.end();
  process.exit(0);
});
