require('dotenv').config();
const express = require('express');
const session = require('express-session');
const pgSession = require('connect-pg-simple')(session);
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const path = require('path');

const app = express();
app.set('trust proxy', 1); // Trust first proxy (Railway)
const PORT = process.env.PORT || 3000;

// Database connection
const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
});

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));

// Session configuration
app.use(session({
    store: new pgSession({
        pool: pool,
        tableName: 'sessions'
    }),
    secret: process.env.SESSION_SECRET || 'your-secret-key-change-in-production',
    resave: false,
    saveUninitialized: false,
    cookie: {
        maxAge: 24 * 60 * 60 * 1000,
        secure: process.env.NODE_ENV === 'production'
    }
}));

// Auth middleware
const requireAuth = (req, res, next) => {
    if (!req.session.userId) return res.redirect('/login');
    next();
};

const requireAdmin = async (req, res, next) => {
    if (!req.session.userId) return res.redirect('/login');
    try {
        const result = await pool.query('SELECT is_admin FROM users WHERE id = $1', [req.session.userId]);
        if (!result.rows[0]?.is_admin) return res.status(403).send('Admin access required');
        next();
    } catch (err) { res.status(500).send('Server error'); }
};

function generateApiKey() { return 'app_' + crypto.randomBytes(32).toString('hex'); }

// Page Routes
app.get('/login', (req, res) => {
    if (req.session.userId) return res.redirect('/');
    res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

app.get('/', requireAuth, (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Auth API
app.post('/api/login', async (req, res) => {
    const { email, password } = req.body;
    try {
        const result = await pool.query('SELECT id, email, password_hash, name, is_admin, is_active FROM users WHERE email = $1', [email.toLowerCase()]);
        if (result.rows.length === 0) return res.status(401).json({ error: 'Invalid credentials' });
        const user = result.rows[0];
        if (!user.is_active) return res.status(401).json({ error: 'Account is deactivated' });
        const validPassword = await bcrypt.compare(password, user.password_hash);
        if (!validPassword) return res.status(401).json({ error: 'Invalid credentials' });
        await pool.query('UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = $1', [user.id]);
        req.session.userId = user.id;
        req.session.isAdmin = user.is_admin;
        res.json({ success: true, user: { id: user.id, name: user.name, email: user.email, is_admin: user.is_admin } });
    } catch (err) { console.error('Login error:', err); res.status(500).json({ error: 'Server error' }); }
});

app.post('/api/logout', (req, res) => { req.session.destroy(); res.json({ success: true }); });

app.get('/api/me', requireAuth, async (req, res) => {
    try {
        const result = await pool.query('SELECT id, email, name, is_admin FROM users WHERE id = $1', [req.session.userId]);
        res.json(result.rows[0]);
    } catch (err) { res.status(500).json({ error: 'Server error' }); }
});

// User Management
app.get('/api/users', requireAdmin, async (req, res) => {
    try {
        const result = await pool.query(`SELECT u.id, u.email, u.name, u.is_admin, u.is_active, u.created_at, u.last_login, COUNT(uaa.app_id) as app_count FROM users u LEFT JOIN user_app_access uaa ON u.id = uaa.user_id GROUP BY u.id ORDER BY u.name`);
        res.json(result.rows);
    } catch (err) { res.status(500).json({ error: 'Server error' }); }
});

app.post('/api/users', requireAdmin, async (req, res) => {
    const { email, password, name, is_admin } = req.body;
    if (!email || !password || !name) return res.status(400).json({ error: 'Email, password, and name are required' });
    try {
        const passwordHash = await bcrypt.hash(password, 10);
        const result = await pool.query('INSERT INTO users (email, password_hash, name, is_admin) VALUES ($1, $2, $3, $4) RETURNING id, email, name, is_admin, is_active, created_at', [email.toLowerCase(), passwordHash, name, is_admin || false]);
        res.json(result.rows[0]);
    } catch (err) {
        if (err.code === '23505') return res.status(400).json({ error: 'Email already exists' });
        res.status(500).json({ error: 'Server error' });
    }
});

app.put('/api/users/:id', requireAdmin, async (req, res) => {
    const { id } = req.params;
    const { email, password, name, is_admin, is_active } = req.body;
    try {
        let query, params;
        if (password) {
            const passwordHash = await bcrypt.hash(password, 10);
            query = 'UPDATE users SET email = $1, password_hash = $2, name = $3, is_admin = $4, is_active = $5, updated_at = CURRENT_TIMESTAMP WHERE id = $6 RETURNING id, email, name, is_admin, is_active';
            params = [email.toLowerCase(), passwordHash, name, is_admin, is_active, id];
        } else {
            query = 'UPDATE users SET email = $1, name = $2, is_admin = $3, is_active = $4, updated_at = CURRENT_TIMESTAMP WHERE id = $5 RETURNING id, email, name, is_admin, is_active';
            params = [email.toLowerCase(), name, is_admin, is_active, id];
        }
        const result = await pool.query(query, params);
        if (result.rows.length === 0) return res.status(404).json({ error: 'User not found' });
        res.json(result.rows[0]);
    } catch (err) {
        if (err.code === '23505') return res.status(400).json({ error: 'Email already exists' });
        res.status(500).json({ error: 'Server error' });
    }
});

app.delete('/api/users/:id', requireAdmin, async (req, res) => {
    const { id } = req.params;
    if (parseInt(id) === req.session.userId) return res.status(400).json({ error: 'Cannot delete your own account' });
    try {
        const result = await pool.query('DELETE FROM users WHERE id = $1 RETURNING id', [id]);
        if (result.rows.length === 0) return res.status(404).json({ error: 'User not found' });
        res.json({ success: true });
    } catch (err) { res.status(500).json({ error: 'Server error' }); }
});

// App Management
app.get('/api/apps', requireAdmin, async (req, res) => {
    try {
        const result = await pool.query(`SELECT a.*, COUNT(uaa.user_id) as user_count FROM apps a LEFT JOIN user_app_access uaa ON a.id = uaa.app_id GROUP BY a.id ORDER BY a.name`);
        res.json(result.rows);
    } catch (err) { res.status(500).json({ error: 'Server error' }); }
});

app.post('/api/apps', requireAdmin, async (req, res) => {
    const { name, slug, description, url } = req.body;
    if (!name || !slug) return res.status(400).json({ error: 'Name and slug are required' });
    const apiKey = generateApiKey();
    try {
        const result = await pool.query('INSERT INTO apps (name, slug, description, url, api_key) VALUES ($1, $2, $3, $4, $5) RETURNING *', [name, slug.toLowerCase(), description, url, apiKey]);
        res.json(result.rows[0]);
    } catch (err) {
        if (err.code === '23505') return res.status(400).json({ error: 'Slug already exists' });
        res.status(500).json({ error: 'Server error' });
    }
});

app.put('/api/apps/:id', requireAdmin, async (req, res) => {
    const { id } = req.params;
    const { name, slug, description, url, is_active } = req.body;
    try {
        const result = await pool.query('UPDATE apps SET name = $1, slug = $2, description = $3, url = $4, is_active = $5, updated_at = CURRENT_TIMESTAMP WHERE id = $6 RETURNING *', [name, slug.toLowerCase(), description, url, is_active, id]);
        if (result.rows.length === 0) return res.status(404).json({ error: 'App not found' });
        res.json(result.rows[0]);
    } catch (err) {
        if (err.code === '23505') return res.status(400).json({ error: 'Slug already exists' });
        res.status(500).json({ error: 'Server error' });
    }
});

app.post('/api/apps/:id/regenerate-key', requireAdmin, async (req, res) => {
    const { id } = req.params;
    const newApiKey = generateApiKey();
    try {
        const result = await pool.query('UPDATE apps SET api_key = $1, updated_at = CURRENT_TIMESTAMP WHERE id = $2 RETURNING *', [newApiKey, id]);
        if (result.rows.length === 0) return res.status(404).json({ error: 'App not found' });
        res.json(result.rows[0]);
    } catch (err) { res.status(500).json({ error: 'Server error' }); }
});

app.delete('/api/apps/:id', requireAdmin, async (req, res) => {
    const { id } = req.params;
    try {
        const result = await pool.query('DELETE FROM apps WHERE id = $1 RETURNING id', [id]);
        if (result.rows.length === 0) return res.status(404).json({ error: 'App not found' });
        res.json({ success: true });
    } catch (err) { res.status(500).json({ error: 'Server error' }); }
});

// Access Control
app.get('/api/users/:id/access', requireAdmin, async (req, res) => {
    const { id } = req.params;
    try {
        const result = await pool.query(`SELECT a.id, a.name, a.slug, CASE WHEN uaa.id IS NOT NULL THEN true ELSE false END as has_access FROM apps a LEFT JOIN user_app_access uaa ON a.id = uaa.app_id AND uaa.user_id = $1 WHERE a.is_active = true ORDER BY a.name`, [id]);
        res.json(result.rows);
    } catch (err) { res.status(500).json({ error: 'Server error' }); }
});

app.put('/api/users/:id/access', requireAdmin, async (req, res) => {
    const { id } = req.params;
    const { app_ids } = req.body;
    try {
        await pool.query('BEGIN');
        await pool.query('DELETE FROM user_app_access WHERE user_id = $1', [id]);
        if (app_ids && app_ids.length > 0) {
            const values = app_ids.map((appId, index) => `($1, $${index + 2}, $${app_ids.length + 2})`).join(', ');
            await pool.query(`INSERT INTO user_app_access (user_id, app_id, granted_by) VALUES ${values}`, [id, ...app_ids, req.session.userId]);
        }
        await pool.query('COMMIT');
        res.json({ success: true });
    } catch (err) { await pool.query('ROLLBACK'); res.status(500).json({ error: 'Server error' }); }
});

app.get('/api/apps/:id/users', requireAdmin, async (req, res) => {
    const { id } = req.params;
    try {
        const result = await pool.query(`SELECT u.id, u.name, u.email, CASE WHEN uaa.id IS NOT NULL THEN true ELSE false END as has_access FROM users u LEFT JOIN user_app_access uaa ON u.id = uaa.user_id AND uaa.app_id = $1 WHERE u.is_active = true ORDER BY u.name`, [id]);
        res.json(result.rows);
    } catch (err) { res.status(500).json({ error: 'Server error' }); }
});

// External Auth API
app.post('/api/auth/verify', async (req, res) => {
    const { email, password, app_slug } = req.body;
    const apiKey = req.headers['x-api-key'];
    if (!apiKey) return res.status(401).json({ error: 'API key required' });
    try {
        const appResult = await pool.query('SELECT id, slug FROM apps WHERE api_key = $1 AND is_active = true', [apiKey]);
        if (appResult.rows.length === 0) return res.status(401).json({ error: 'Invalid API key' });
        const app = appResult.rows[0];
        if (app_slug && app.slug !== app_slug) return res.status(401).json({ error: 'API key does not match app' });
        const userResult = await pool.query('SELECT id, email, password_hash, name, is_active FROM users WHERE email = $1', [email.toLowerCase()]);
        if (userResult.rows.length === 0) return res.status(401).json({ error: 'Invalid credentials' });
        const user = userResult.rows[0];
        if (!user.is_active) return res.status(401).json({ error: 'Account is deactivated' });
        const validPassword = await bcrypt.compare(password, user.password_hash);
        if (!validPassword) return res.status(401).json({ error: 'Invalid credentials' });
        const accessResult = await pool.query('SELECT id FROM user_app_access WHERE user_id = $1 AND app_id = $2', [user.id, app.id]);
        if (accessResult.rows.length === 0) return res.status(403).json({ error: 'User does not have access to this app' });
        await pool.query('UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = $1', [user.id]);
        res.json({ success: true, user: { id: user.id, email: user.email, name: user.name } });
    } catch (err) { res.status(500).json({ error: 'Server error' }); }
});

app.get('/api/auth/check-access', async (req, res) => {
    const { user_id, app_slug } = req.query;
    const apiKey = req.headers['x-api-key'];
    if (!apiKey) return res.status(401).json({ error: 'API key required' });
    try {
        const result = await pool.query(`SELECT u.id, u.email, u.name FROM users u JOIN user_app_access uaa ON u.id = uaa.user_id JOIN apps a ON uaa.app_id = a.id WHERE u.id = $1 AND a.slug = $2 AND a.api_key = $3 AND u.is_active = true AND a.is_active = true`, [user_id, app_slug, apiKey]);
        if (result.rows.length === 0) return res.status(403).json({ error: 'Access denied' });
        res.json({ success: true, user: result.rows[0] });
    } catch (err) { res.status(500).json({ error: 'Server error' }); }
});

// Stats
app.get('/api/stats', requireAdmin, async (req, res) => {
    try {
        const stats = await pool.query(`SELECT (SELECT COUNT(*) FROM users WHERE is_active = true) as total_users, (SELECT COUNT(*) FROM apps WHERE is_active = true) as total_apps, (SELECT COUNT(*) FROM user_app_access) as total_assignments, (SELECT COUNT(*) FROM users WHERE last_login > NOW() - INTERVAL '7 days') as active_users_week`);
        res.json(stats.rows[0]);
    } catch (err) { res.status(500).json({ error: 'Server error' }); }
});

app.listen(PORT, () => { console.log(`Admin Panel running on port ${PORT}`); });
