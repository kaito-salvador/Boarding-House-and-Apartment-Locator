// Backend: server.js (complete updated version)
require('dotenv').config();
const express = require('express');
const mysql = require('mysql2/promise');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const cors = require('cors');

const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'change_this_secret';
const DB_HOST = process.env.DB_HOST || '127.0.0.1';
const DB_USER = process.env.DB_USER || 'root';
const DB_PASS = process.env.DB_PASS || '';
const DB_NAME = process.env.DB_NAME || 'locator_app2';

const app = express();
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Serve frontend and uploads
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));
app.use(express.static(path.join(__dirname, 'public')));

// Ensure uploads folder
const UPLOAD_DIR = path.join(__dirname, 'uploads');
if (!fs.existsSync(UPLOAD_DIR)) fs.mkdirSync(UPLOAD_DIR);

// Multer for multiple image uploads
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, UPLOAD_DIR),
  filename: (req, file, cb) => {
    const ext = path.extname(file.originalname);
    cb(null, Date.now() + '-' + Math.random().toString(36).slice(2, 8) + ext);
  }
});
const upload = multer({ storage });

// Database initialization
let pool;
(async function init() {
  try {
    pool = await mysql.createPool({
      host: DB_HOST,
      user: DB_USER,
      password: DB_PASS,
      database: DB_NAME,
      waitForConnections: true,
      connectionLimit: 10,
      decimalNumbers: true
    });

    // Tables (existing)
    await pool.execute(`
      CREATE TABLE IF NOT EXISTS users (
        id INT AUTO_INCREMENT PRIMARY KEY,
        username VARCHAR(128) NOT NULL UNIQUE,
        password VARCHAR(255) NOT NULL,
        role ENUM('renter','owner','admin') NOT NULL DEFAULT 'renter',
        full_name VARCHAR(128),
        phone VARCHAR(32),
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);
    await pool.execute(`
      CREATE TABLE IF NOT EXISTS listings (
        id INT AUTO_INCREMENT PRIMARY KEY,
        owner_id INT NOT NULL,
        title VARCHAR(255) NOT NULL,
        description TEXT,
        price DECIMAL(10,2) NOT NULL,
        address VARCHAR(255) NOT NULL,
        barangay VARCHAR(128) NOT NULL,
        latitude DECIMAL(10,7) NOT NULL,
        longitude DECIMAL(10,7) NOT NULL,
        type ENUM('apartment', 'boarding_house') NOT NULL,
        image VARCHAR(512),
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (owner_id) REFERENCES users(id) ON DELETE CASCADE
      )
    `);
    await pool.execute(`
      CREATE TABLE IF NOT EXISTS listing_images (
        id INT AUTO_INCREMENT PRIMARY KEY,
        listing_id INT NOT NULL,
        image_url VARCHAR(512) NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (listing_id) REFERENCES listings(id) ON DELETE CASCADE
      )
    `);
    await pool.execute(`
      CREATE TABLE IF NOT EXISTS reviews (
        id INT AUTO_INCREMENT PRIMARY KEY,
        listing_id INT NOT NULL,
        renter_id INT NOT NULL,
        rating TINYINT NOT NULL,
        comment TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (listing_id) REFERENCES listings(id) ON DELETE CASCADE,
        FOREIGN KEY (renter_id) REFERENCES users(id) ON DELETE CASCADE
      )
    `);
    await pool.execute(`
      CREATE TABLE IF NOT EXISTS favorites (
        id INT AUTO_INCREMENT PRIMARY KEY,
        renter_id INT NOT NULL,
        listing_id INT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        UNIQUE KEY (renter_id, listing_id),
        FOREIGN KEY (renter_id) REFERENCES users(id) ON DELETE CASCADE,
        FOREIGN KEY (listing_id) REFERENCES listings(id) ON DELETE CASCADE
      )
    `);
    await pool.execute(`
      CREATE TABLE IF NOT EXISTS bookings (
        id INT AUTO_INCREMENT PRIMARY KEY,
        listing_id INT NOT NULL,
        renter_id INT NOT NULL,
        owner_id INT NOT NULL,
        start_date DATE NOT NULL,
        end_date DATE NOT NULL,
        status ENUM('pending','approved','rejected','cancelled') NOT NULL DEFAULT 'pending',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (listing_id) REFERENCES listings(id) ON DELETE CASCADE,
        FOREIGN KEY (renter_id) REFERENCES users(id) ON DELETE CASCADE,
        FOREIGN KEY (owner_id) REFERENCES users(id) ON DELETE CASCADE
      )
    `);

    console.log('✅ MySQL connected and tables ready for DB:', DB_NAME);

    app.listen(PORT, () => {
      console.log(`🚀 Server running on http://localhost:${PORT}`);
    });
  } catch (err) {
    console.error('Fatal DB error', err);
    process.exit(1);
  }
})();

// Auth middleware
function authMiddleware(req, res, next) {
  const auth = req.headers.authorization;
  if (!auth) return res.status(401).json({ error: 'Missing Authorization header' });
  const parts = auth.split(' ');
  if (parts.length !== 2 || parts[0] !== 'Bearer') return res.status(401).json({ error: 'Malformed token' });
  const token = parts[1];
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    req.user = payload;
    next();
  } catch (err) {
    return res.status(401).json({ error: 'Invalid or expired token' });
  }
}

// Routes
app.get('/api/ping', (req, res) => res.json({ ok: true }));

app.post('/api/register', async (req, res) => {
  try {
    const { username, password, role } = req.body;
    if (!username || !password) return res.status(400).json({ error: 'username & password required' });
    const [rows] = await pool.execute('SELECT id FROM users WHERE username = ?', [username]);
    if (rows.length) return res.status(409).json({ error: 'Username already exists' });

    const hash = await bcrypt.hash(password, 10);
    const [result] = await pool.execute(
      'INSERT INTO users (username, password, role) VALUES (?, ?, ?)',
      [username, hash, role || 'renter']
    );
    const userId = result.insertId;
    const token = jwt.sign({ id: userId, username, role: role || 'renter' }, JWT_SECRET, { expiresIn: '7d' });
    return res.json({ token, user: { id: userId, username, role: role || 'renter' } });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password) return res.status(400).json({ error: 'username & password required' });

    const [rows] = await pool.execute('SELECT id, username, password, role FROM users WHERE username = ?', [username]);
    const user = rows[0];
    if (!user) return res.status(401).json({ error: 'Invalid credentials' });

    const ok = await bcrypt.compare(password, user.password);
    if (!ok) return res.status(401).json({ error: 'Invalid credentials' });

    const token = jwt.sign({ id: user.id, username: user.username, role: user.role }, JWT_SECRET, { expiresIn: '7d' });
    return res.json({ token, user: { id: user.id, username: user.username, role: user.role } });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: 'Server error' });
  }
});

app.get('/api/me', authMiddleware, async (req, res) => {
  try {
    const { id } = req.user;
    const [rows] = await pool.execute('SELECT id, username, role, full_name, phone, created_at FROM users WHERE id = ?', [id]);
    if (!rows[0]) return res.status(404).json({ error: 'User not found' });
    res.json(rows[0]);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error' });
  }
});

app.put('/api/me', authMiddleware, async (req, res) => {
  try {
    const { id } = req.user;
    const { full_name, phone, password } = req.body;
    if (password) {
      const hash = await bcrypt.hash(password, 10);
      await pool.execute('UPDATE users SET full_name = ?, phone = ?, password = ? WHERE id = ?', [full_name || null, phone || null, hash, id]);
    } else {
      await pool.execute('UPDATE users SET full_name = ?, phone = ? WHERE id = ?', [full_name || null, phone || null, id]);
    }
    const [rows] = await pool.execute('SELECT id, username, role, full_name, phone, created_at FROM users WHERE id = ?', [id]);
    res.json(rows[0]);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error' });
  }
});

app.get('/api/listings', async (req, res) => {
  try {
    const { barangay, type, min_price, max_price } = req.query;
    let sql = `SELECT l.*, u.username as owner_name,
                IFNULL(GROUP_CONCAT(DISTINCT li.image_url), '') as images,
                IFNULL(ROUND(AVG(r.rating),2),0) as avg_rating,
                COUNT(DISTINCT r.id) as review_count
               FROM listings l
               JOIN users u ON l.owner_id = u.id
               LEFT JOIN listing_images li ON li.listing_id = l.id
               LEFT JOIN reviews r ON r.listing_id = l.id
               WHERE 1=1`;
    const params = [];
    if (barangay) {
      sql += ' AND LOWER(l.barangay) LIKE ?';
      params.push('%' + barangay.toLowerCase() + '%');
    }
    if (type) {
      sql += ' AND l.type = ?';
      params.push(type);
    }
    if (min_price) {
      sql += ' AND l.price >= ?';
      params.push(Number(min_price));
    }
    if (max_price) {
      sql += ' AND l.price <= ?';
      params.push(Number(max_price));
    }
    sql += ' GROUP BY l.id ORDER BY l.created_at DESC';
    const [rows] = await pool.execute(sql, params);

    let favs = new Set();
    try {
      const auth = (req.headers.authorization || '').split(' ');
      if (auth.length === 2 && auth[0] === 'Bearer') {
        const payload = jwt.verify(auth[1], JWT_SECRET);
        const [favRows] = await pool.execute('SELECT listing_id FROM favorites WHERE renter_id = ?', [payload.id]);
        favRows.forEach(f => favs.add(f.listing_id));
      }
    } catch (e) { /* ignore */ }

    const out = rows.map(r => ({
      id: r.id,
      owner_id: r.owner_id,
      owner_name: r.owner_name,
      title: r.title,
      description: r.description,
      price: Number(r.price),
      address: r.address,
      barangay: r.barangay,
      latitude: Number(r.latitude),
      longitude: Number(r.longitude),
      type: r.type,
      image: r.image,
      images: r.images ? r.images.split(',') : (r.image ? [r.image] : []),
      avg_rating: Number(r.avg_rating || 0),
      review_count: Number(r.review_count || 0),
      is_favorited: favs.has(r.id)
    }));
    res.json(out);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'DB error' });
  }
});

app.get('/api/listings/:id', async (req, res) => {
  try {
    const id = req.params.id;
    const [rows] = await pool.execute(`
      SELECT l.*, u.username as owner_name,
             IFNULL(GROUP_CONCAT(DISTINCT li.image_url), '') as images,
             IFNULL(ROUND(AVG(r.rating),2),0) as avg_rating,
             COUNT(DISTINCT r.id) as review_count
      FROM listings l
      JOIN users u ON l.owner_id = u.id
      LEFT JOIN listing_images li ON li.listing_id = l.id
      LEFT JOIN reviews r ON r.listing_id = l.id
      WHERE l.id = ?
      GROUP BY l.id
    `, [id]);
    if (!rows[0]) return res.status(404).json({ error: 'Not found' });
    const r = rows[0];

    const [revRows] = await pool.execute('SELECT r.*, u.username FROM reviews r JOIN users u ON r.renter_id = u.id WHERE r.listing_id = ? ORDER BY r.created_at DESC', [id]);

    let is_favorited = false;
    try {
      const auth = (req.headers.authorization || '').split(' ');
      if (auth.length === 2 && auth[0] === 'Bearer') {
        const payload = jwt.verify(auth[1], JWT_SECRET);
        const [fr] = await pool.execute('SELECT 1 FROM favorites WHERE renter_id = ? AND listing_id = ?', [payload.id, id]);
        is_favorited = fr.length > 0;
      }
    } catch (e) {}

    res.json({
      id: r.id,
      owner_id: r.owner_id,
      owner_name: r.owner_name,
      title: r.title,
      description: r.description,
      price: Number(r.price),
      address: r.address,
      barangay: r.barangay,
      latitude: Number(r.latitude),
      longitude: Number(r.longitude),
      type: r.type,
      image: r.image,
      images: r.images ? r.images.split(',') : (r.image ? [r.image] : []),
      avg_rating: Number(r.avg_rating || 0),
      review_count: Number(r.review_count || 0),
      reviews: revRows.map(rv => ({ id: rv.id, renter_id: rv.renter_id, username: rv.username, rating: rv.rating, comment: rv.comment, created_at: rv.created_at })),
      is_favorited
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'DB error' });
  }
});

app.post('/api/listings', authMiddleware, upload.array('images', 5), async (req, res) => {
  try {
    const user = req.user;
    if (user.role !== 'owner') return res.status(403).json({ error: 'Only owners can add listings' });

    const { title, description, price, address, barangay, latitude, longitude, type } = req.body;
    if (!title || !price || !address || !barangay || !latitude || !longitude || !type) {
      return res.status(400).json({ error: 'All fields are required' });
    }

    const [result] = await pool.execute(
      `INSERT INTO listings 
      (owner_id, title, description, price, address, barangay, latitude, longitude, type)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [user.id, title, description || null, price, address, barangay, latitude, longitude, type]
    );
    const listingId = result.insertId;

    // Handle multiple images
    if (req.files && req.files.length) {
      const imagePromises = req.files.map(file =>
        pool.execute('INSERT INTO listing_images (listing_id, image_url) VALUES (?, ?)', [listingId, `/uploads/${file.filename}`])
      );
      await Promise.all(imagePromises);
    }

    res.status(201).json({ message: 'Listing added successfully', listingId });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error while adding listing' });
  }
});

app.patch('/api/listings/:id', authMiddleware, upload.array('images', 5), async (req, res) => {
  try {
    const user = req.user;
    const id = req.params.id;
    const [rows] = await pool.execute('SELECT owner_id FROM listings WHERE id = ?', [id]);
    if (!rows[0]) return res.status(404).json({ error: 'Listing not found' });
    if (user.role !== 'admin' && rows[0].owner_id !== user.id) return res.status(403).json({ error: 'Forbidden' });

    const { title, description, price, address, barangay, latitude, longitude, type } = req.body;
    await pool.execute(
      `UPDATE listings SET title=?, description=?, price=?, address=?, barangay=?, latitude=?, longitude=?, type=?
       WHERE id=?`,
      [title, description || null, price, address, barangay, latitude, longitude, type, id]
    );

    // Add new images if provided
    if (req.files && req.files.length) {
      const imagePromises = req.files.map(file =>
        pool.execute('INSERT INTO listing_images (listing_id, image_url) VALUES (?, ?)', [id, `/uploads/${file.filename}`])
      );
      await Promise.all(imagePromises);
    }

    res.json({ message: 'Listing updated successfully' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error while updating listing' });
  }
});

app.get('/api/listings/:id/booked_dates', authMiddleware, async (req, res) => {
  try {
    const id = req.params.id;
    const [rows] = await pool.execute(
      'SELECT start_date as `from`, end_date as `to` FROM bookings WHERE listing_id = ? AND status = "approved"',
      [id]
    );
    res.json(rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error' });
  }
});

app.delete('/api/listings/:id', authMiddleware, async (req, res) => {
  try {
    const id = req.params.id;
    const user = req.user;
    const [rows] = await pool.execute('SELECT * FROM listings WHERE id = ?', [id]);
    if (!rows[0]) return res.status(404).json({ error: 'Not found' });
    const listing = rows[0];
    if (user.role !== 'admin' && listing.owner_id !== user.id) return res.status(403).json({ error: 'Forbidden' });

    // Delete images from disk
    const [imgs] = await pool.execute('SELECT image_url FROM listing_images WHERE listing_id = ?', [id]);
    for (const im of imgs) {
      const fp = path.join(__dirname, im.image_url);
      if (fs.existsSync(fp)) {
        try { fs.unlinkSync(fp); } catch (e) { /* ignore */ }
      }
    }

    await pool.execute('DELETE FROM listings WHERE id = ?', [id]);
    res.json({ ok: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/listings/:id/favorite', authMiddleware, async (req, res) => {
  try {
    const userId = req.user.id;
    const listingId = req.params.id;
    const [rows] = await pool.execute('SELECT 1 FROM favorites WHERE renter_id = ? AND listing_id = ?', [userId, listingId]);
    if (rows.length) {
      await pool.execute('DELETE FROM favorites WHERE renter_id = ? AND listing_id = ?', [userId, listingId]);
      return res.json({ favorited: false });
    } else {
      await pool.execute('INSERT INTO favorites (renter_id, listing_id) VALUES (?,?)', [userId, listingId]);
      return res.json({ favorited: true });
    }
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error' });
  }
});

app.get('/api/favorites', authMiddleware, async (req, res) => {
  try {
    const userId = req.user.id;
    const [rows] = await pool.execute(`
      SELECT l.*, u.username as owner_name, IFNULL(GROUP_CONCAT(DISTINCT li.image_url), '') as images
      FROM favorites f
      JOIN listings l ON f.listing_id = l.id
      JOIN users u ON l.owner_id = u.id
      LEFT JOIN listing_images li ON li.listing_id = l.id
      WHERE f.renter_id = ?
      GROUP BY l.id
      ORDER BY f.created_at DESC
    `, [userId]);
    const out = rows.map(r => ({
      id: r.id,
      owner_id: r.owner_id,
      owner_name: r.owner_name,
      title: r.title,
      description: r.description,
      price: Number(r.price),
      address: r.address,
      barangay: r.barangay,
      latitude: Number(r.latitude),
      longitude: Number(r.longitude),
      type: r.type,
      images: r.images ? r.images.split(',') : (r.image ? [r.image] : [])
    }));
    res.json(out);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/listings/:id/reviews', authMiddleware, async (req, res) => {
  try {
    const userId = req.user.id;
    const listingId = req.params.id;
    const { rating, comment } = req.body;
    const r = Number(rating);
    if (!r || r < 1 || r > 5) return res.status(400).json({ error: 'rating 1-5 required' });

    await pool.execute('INSERT INTO reviews (listing_id, renter_id, rating, comment) VALUES (?,?,?,?)', [listingId, userId, r, comment || null]);
    res.json({ ok: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/bookings', authMiddleware, async (req, res) => {
  try {
    const user = req.user;
    if (user.role !== 'renter') return res.status(403).json({ error: 'Only renters can create bookings' });

    const { listing_id, start_date, end_date } = req.body;
    if (!listing_id || !start_date || !end_date) return res.status(400).json({ error: 'Missing fields' });
    if (new Date(start_date) > new Date(end_date)) return res.status(400).json({ error: 'Invalid dates' });

    // Check for overlaps
    const [overlaps] = await pool.execute(
      `SELECT 1 FROM bookings WHERE listing_id = ? AND status = 'approved' 
       AND NOT (end_date < ? OR start_date > ?)`,
      [listing_id, start_date, end_date]
    );
    if (overlaps.length) return res.status(400).json({ error: 'Dates overlap with existing booking' });

    const [rows] = await pool.execute('SELECT owner_id, title FROM listings WHERE id = ?', [listing_id]);
    if (!rows[0]) return res.status(404).json({ error: 'Listing not found' });
    const owner_id = rows[0].owner_id;
    const listing_title = rows[0].title;

    const [result] = await pool.execute('INSERT INTO bookings (listing_id, renter_id, owner_id, start_date, end_date) VALUES (?,?,?,?,?)', [listing_id, user.id, owner_id, start_date, end_date]);
    res.json({ id: result.insertId, listing_title });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error' });
  }
});

app.get('/api/bookings', authMiddleware, async (req, res) => {
  try {
    const user = req.user;
    let sql = `SELECT b.*, l.title as listing_title, l.type as listing_type, ru.username as renter_name, ou.username as owner_name
               FROM bookings b
               JOIN listings l ON b.listing_id = l.id
               JOIN users ru ON b.renter_id = ru.id
               JOIN users ou ON b.owner_id = ou.id`;
    const params = [];
    if (user.role === 'renter') {
      sql += ' WHERE b.renter_id = ?';
      params.push(user.id);
    } else if (user.role === 'owner') {
      sql += ' WHERE b.owner_id = ?';
      params.push(user.id);
    }
    sql += ' ORDER BY b.created_at DESC';
    const [rows] = await pool.execute(sql, params);
    res.json(rows.map(r => ({
      id: r.id,
      listing_id: r.listing_id,
      listing_title: r.listing_title,
      listing_type: r.listing_type,
      renter_id: r.renter_id,
      renter_name: r.renter_name,
      owner_id: r.owner_id,
      owner_name: r.owner_name,
      start_date: r.start_date,
      end_date: r.end_date,
      status: r.status,
      created_at: r.created_at
    })));
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error' });
  }
});

app.patch('/api/bookings/:id', authMiddleware, async (req, res) => {
  try {
    const user = req.user;
    const id = req.params.id;
    const { action } = req.body;
    if (!action) return res.status(400).json({ error: 'action required' });

    const [rows] = await pool.execute('SELECT * FROM bookings WHERE id = ?', [id]);
    if (!rows[0]) return res.status(404).json({ error: 'Booking not found' });
    const booking = rows[0];

    if (action === 'approve' || action === 'reject') {
      if (user.role !== 'owner' && user.role !== 'admin') return res.status(403).json({ error: 'Only owner/admin can approve/reject' });
      if (user.role !== 'admin' && booking.owner_id !== user.id) return res.status(403).json({ error: 'Forbidden' });
      const newStatus = action === 'approve' ? 'approved' : 'rejected';
      await pool.execute('UPDATE bookings SET status = ? WHERE id = ?', [newStatus, id]);
      return res.json({ ok: true });
    } else if (action === 'cancel') {
      if (user.role === 'renter' && booking.renter_id !== user.id) return res.status(403).json({ error: 'Forbidden' });
      if (user.role === 'owner' && booking.owner_id !== user.id) return res.status(403).json({ error: 'Forbidden' });
      await pool.execute('UPDATE bookings SET status = ? WHERE id = ?', ['cancelled', id]);
      return res.json({ ok: true });
    } else {
      return res.status(400).json({ error: 'Unknown action' });
    }
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error' });
  }
});

app.get('/api/my/listings', authMiddleware, async (req, res) => {
  try {
    const user = req.user;
    if (!user || user.role !== 'owner') return res.status(403).json({ error: 'Only owners' });
    const [rows] = await pool.execute(`
      SELECT l.*, IFNULL(GROUP_CONCAT(DISTINCT li.image_url), '') as images
      FROM listings l
      LEFT JOIN listing_images li ON li.listing_id = l.id
      WHERE l.owner_id = ?
      GROUP BY l.id
      ORDER BY l.created_at DESC
    `, [user.id]);
    const out = rows.map(r => ({
      id: r.id,
      title: r.title,
      description: r.description,
      price: Number(r.price),
      address: r.address,
      barangay: r.barangay,
      latitude: Number(r.latitude),
      longitude: Number(r.longitude),
      type: r.type,
      images: r.images ? r.images.split(',') : (r.image ? [r.image] : [])
    }));
    res.json(out);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error' });
  }
});

app.use((req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});