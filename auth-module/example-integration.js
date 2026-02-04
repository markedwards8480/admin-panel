/**
 * EXAMPLE: How to integrate central auth into your existing app
 *
 * This shows how to modify an existing Express app (like product-catalog)
 * to use the central admin panel for authentication.
 */

require('dotenv').config();
const express = require('express');
const { Pool } = require('pg');

// ========== STEP 1: Import the central auth module ==========
const { setupAuth, requireAuth, getCurrentUser } = require('./central-auth');

const app = express();
const PORT = process.env.PORT || 3000;

// Database (your app's own database)
const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
});

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static('public'));

// ========== STEP 2: Setup auth (MUST be before your routes) ==========
setupAuth(app);

// ========== STEP 3: Protect your routes with requireAuth ==========

// Public routes (no auth needed)
app.get('/health', (req, res) => {
    res.json({ status: 'ok' });
});

// Protected routes - use requireAuth middleware
app.get('/', requireAuth, async (req, res) => {
    // req.user contains { id, email, name } from central auth
    const user = req.user;

    res.send(`
        <h1>Welcome, ${user.name}!</h1>
        <p>You're logged in as ${user.email}</p>
        <a href="/logout">Logout</a>
    `);
});

// Protected API routes
app.get('/api/products', requireAuth, async (req, res) => {
    try {
        const result = await pool.query('SELECT * FROM products ORDER BY name');
        res.json(result.rows);
    } catch (err) {
        res.status(500).json({ error: 'Server error' });
    }
});

// ========== Your existing routes go here ==========
// Just add requireAuth middleware to protect them

app.listen(PORT, () => {
    console.log(`App running on port ${PORT}`);
});

/**
 * REQUIRED ENVIRONMENT VARIABLES:
 *
 * # Your existing env vars
 * DATABASE_URL=postgresql://...
 * PORT=3000
 *
 * # New vars for central auth
 * ADMIN_PANEL_URL=https://your-admin-panel.railway.app
 * APP_API_KEY=app_abc123...  (from admin panel when you add this app)
 * APP_SLUG=product-catalog   (must match what you set in admin panel)
 * APP_NAME=Product Catalog   (displayed on login page)
 * SESSION_SECRET=random-string-here
 */
