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

// ============================================
// DATABASE AUTO-INITIALIZATION
// ============================================
async function initializeDatabase() {
    console.log('Checking database initialization...');

    try {
        // Check if users table exists
        const tableCheck = await pool.query(`
            SELECT EXISTS (
                SELECT FROM information_schema.tables
                WHERE table_name = 'users'
            );
        `);

        if (tableCheck.rows[0].exists) {
            console.log('Database already initialized.');
            
            // Check and add missing columns to existing tables
            console.log('Checking for missing columns in existing tables...');
            
            // Add description column to apps table if it doesn't exist
            const descriptionColumnCheck = await pool.query(`
                SELECT EXISTS (
                    SELECT FROM information_schema.columns 
                    WHERE table_name = 'apps' AND column_name = 'description'
                );
            `);
            
            if (!descriptionColumnCheck.rows[0].exists) {
                console.log('Adding missing description column to apps table...');
                await pool.query('ALTER TABLE apps ADD COLUMN description TEXT');
                console.log('Description column added successfully.');
            }
            
            return;
        }

        console.log('Initializing database tables...');

        // Create tables
        await pool.query(`
            CREATE TABLE IF NOT EXISTS users (
                id SERIAL PRIMARY KEY,
                email VARCHAR(255) UNIQUE NOT NULL,
                password_hash VARCHAR(255) NOT NULL,
                name VARCHAR(255) NOT NULL,
                is_admin BOOLEAN DEFAULT FALSE,
                is_active BOOLEAN DEFAULT TRUE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_login TIMESTAMP
            );

            CREATE TABLE IF NOT EXISTS apps (
                id SERIAL PRIMARY KEY,
                name VARCHAR(255) NOT NULL,
                slug VARCHAR(100) UNIQUE NOT NULL,
                description TEXT,
                url VARCHAR(500),
                api_key VARCHAR(255) UNIQUE NOT NULL,
                is_active BOOLEAN DEFAULT TRUE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );

            CREATE TABLE IF NOT EXISTS user_app_access (
                id SERIAL PRIMARY KEY,
                user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
                app_id INTEGER REFERENCES apps(id) ON DELETE CASCADE,
                granted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                granted_by INTEGER REFERENCES users(id),
                UNIQUE(user_id, app_id)
            );

            CREATE TABLE IF NOT EXISTS sessions (
                sid VARCHAR(255) PRIMARY KEY,
                sess JSON NOT NULL,
                expire TIMESTAMP NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_sessions_expire ON sessions(expire);
            CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
            CREATE INDEX IF NOT EXISTS idx_apps_slug ON apps(slug);
            CREATE INDEX IF NOT EXISTS idx_apps_api_key ON apps(api_key);
            CREATE INDEX IF NOT EXISTS idx_user_app_access_user ON user_app_access(user_id);
            CREATE INDEX IF NOT EXISTS idx_user_app_access_app ON user_app_access(app_id);
        `);

        console.log('Tables created successfully.');

        // Create admin user if credentials are provided
        const adminEmail = process.env.ADMIN_EMAIL;
        const adminPassword = process.env.ADMIN_PASSWORD;
        const adminName = process.env.ADMIN_NAME || 'Admin';

        if (adminEmail && adminPassword) {
            const existingAdmin = await pool.query('SELECT id FROM users WHERE email = $1', [adminEmail.toLowerCase()]);

            if (existingAdmin.rows.length === 0) {
                const passwordHash = await bcrypt.hash(adminPassword, 10);
                await pool.query(
                    'INSERT INTO users (email, password_hash, name, is_admin) VALUES ($1, $2, $3, true)',
                    [adminEmail.toLowerCase(), passwordHash, adminName]
                );
                console.log(`Admin user created: ${adminEmail}`);
            } else {
                console.log('Admin user already exists.');
            }
        } else {
            console.log('Warning: ADMIN_EMAIL or ADMIN_PASSWORD not set. No admin user created.');
        }

        console.log('Database initialization complete!');
    } catch (err) {
        console.error('Database initialization error:', err);
        throw err;
    }
}

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
        maxAge: 24 * 60 * 60 * 1000, // 24 hours
        secure: process.env.NODE_ENV === 'production'
    }
}));

// Auth middleware
const requireAuth = (req, res, next) => {
    if (!req.session.userId) {
        return res.redirect('/login');
    }
    next();
};

const requireAdmin = async (req, res, next) => {
    if (!req.session.userId) {
        return res.redirect('/login');
    }
    try {
        const result = await pool.query('SELECT is_admin FROM users WHERE id = $1', [req.session.userId]);
        if (!result.rows[0]?.is_admin) {
            return res.status(403).send('Admin access required');
        }
        next();
    } catch (err) {
        res.status(500).send('Server error');
    }
};

// Generate API key for apps
function generateApiKey() {
    return 'app_' + crypto.randomBytes(32).toString('hex');
}

// ============================================
// PAGE ROUTES
// ============================================

// Login page
app.get('/login', (req, res) => {
    if (req.session.userId) {
        return res.redirect('/');
    }
    res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

// Main dashboard (protected)
app.get('/', requireAuth, (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// ============================================
// AUTH API ROUTES
// ============================================

// Login
app.post('/api/login', async (req, res) => {
    const { email, password } = req.body;

    try {
        const result = await pool.query(
            'SELECT id, email, password_hash, name, is_admin, is_active FROM users WHERE email = $1',
            [email.toLowerCase()]
        );

        if (result.rows.length === 0) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }

        const user = result.rows[0];

        if (!user.is_active) {
            return res.status(401).json({ error: 'Account is deactivated' });
        }

        const validPassword = await bcrypt.compare(password, user.password_hash);
        if (!validPassword) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }

        // Update last login
        await pool.query('UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = $1', [user.id]);

        req.session.userId = user.id;
        req.session.isAdmin = user.is_admin;

        res.json({ success: true, user: { id: user.id, name: user.name, email: user.email, is_admin: user.is_admin } });
    } catch (err) {
        console.error('Login error:', err);
        res.status(500).json({ error: 'Server error' });
    }
});

// Logout
app.post('/api/logout', (req, res) => {
    req.session.destroy();
    res.json({ success: true });
});

// Get current user
app.get('/api/me', requireAuth, async (req, res) => {
    try {
        const result = await pool.query(
            'SELECT id, email, name, is_admin FROM users WHERE id = $1',
            [req.session.userId]
        );
        res.json(result.rows[0]);
    } catch (err) {
        res.status(500).json({ error: 'Server error' });
    }
});

// ============================================
// USER MANAGEMENT API ROUTES
// ============================================

// Get all users
app.get('/api/users', requireAdmin, async (req, res) => {
    try {
        const result = await pool.query(`
            SELECT u.id, u.email, u.name, u.is_admin, u.is_active, u.created_at, u.last_login,
                   COUNT(uaa.app_id) as app_count
            FROM users u
            LEFT JOIN user_app_access uaa ON u.id = uaa.user_id
            GROUP BY u.id
            ORDER BY u.name
        `);
        res.json(result.rows);
    } catch (err) {
        console.error('Get users error:', err);
        res.status(500).json({ error: 'Server error' });
    }
});

// Create user
app.post('/api/users', requireAdmin, async (req, res) => {
    const { email, password, name, is_admin } = req.body;

    if (!email || !password || !name) {
        return res.status(400).json({ error: 'Email, password, and name are required' });
    }

    try {
        const passwordHash = await bcrypt.hash(password, 10);
        const result = await pool.query(
            'INSERT INTO users (email, password_hash, name, is_admin) VALUES ($1, $2, $3, $4) RETURNING id, email, name, is_admin, is_active, created_at',
            [email.toLowerCase(), passwordHash, name, is_admin || false]
        );
        res.json(result.rows[0]);
    } catch (err) {
        if (err.code === '23505') { // Unique violation
            return res.status(400).json({ error: 'Email already exists' });
        }
        console.error('Create user error:', err);
        res.status(500).json({ error: 'Server error' });
    }
});

// Update user
app.put('/api/users/:id', requireAdmin, async (req, res) => {
    const { id } = req.params;
    const { email, password, name, is_admin, is_active } = req.body;

    try {
        let query, params;

        if (password) {
            const passwordHash = await bcrypt.hash(password, 10);
            query = `UPDATE users SET email = $1, password_hash = $2, name = $3, is_admin = $4, is_active = $5, updated_at = CURRENT_TIMESTAMP
                     WHERE id = $6 RETURNING id, email, name, is_admin, is_active`;
            params = [email.toLowerCase(), passwordHash, name, is_admin, is_active, id];
        } else {
            query = `UPDATE users SET email = $1, name = $2, is_admin = $3, is_active = $4, updated_at = CURRENT_TIMESTAMP
                     WHERE id = $5 RETURNING id, email, name, is_admin, is_active`;
            params = [email.toLowerCase(), name, is_admin, is_active, id];
        }

        const result = await pool.query(query, params);

        if (result.rows.length === 0) {
            return res.status(404).json({ error: 'User not found' });
        }

        res.json(result.rows[0]);
    } catch (err) {
        if (err.code === '23505') {
            return res.status(400).json({ error: 'Email already exists' });
        }
        console.error('Update user error:', err);
        res.status(500).json({ error: 'Server error' });
    }
});

// Delete user
app.delete('/api/users/:id', requireAdmin, async (req, res) => {
    const { id } = req.params;

    // Prevent deleting yourself
    if (parseInt(id) === req.session.userId) {
        return res.status(400).json({ error: 'Cannot delete your own account' });
    }

    try {
        const result = await pool.query('DELETE FROM users WHERE id = $1 RETURNING id', [id]);

        if (result.rows.length === 0) {
            return res.status(404).json({ error: 'User not found' });
        }

        res.json({ success: true });
    } catch (err) {
        console.error('Delete user error:', err);
        res.status(500).json({ error: 'Server error' });
    }
});

// ============================================
// APP MANAGEMENT API ROUTES
// ============================================

// Get all apps
app.get('/api/apps', requireAdmin, async (req, res) => {
    try {
        const result = await pool.query(`
            SELECT a.*, COUNT(uaa.user_id) as user_count
            FROM apps a
            LEFT JOIN user_app_access uaa ON a.id = uaa.app_id
            GROUP BY a.id
            ORDER BY a.name
        `);
        res.json(result.rows);
    } catch (err) {
        console.error('Get apps error:', err);
        res.status(500).json({ error: 'Server error' });
    }
});

// Create app
app.post('/api/apps', requireAdmin, async (req, res) => {
    const { name, slug, description, url, is_active } = req.body;

    if (!name || !slug) {
        return res.status(400).json({ error: 'Name and slug are required' });
    }

    const apiKey = generateApiKey();

    try {
        const result = await pool.query(
            'INSERT INTO apps (name, slug, description, url, api_key, is_active) VALUES ($1, $2, $3, $4, $5, $6) RETURNING *',
            [name, slug.toLowerCase(), description, url, apiKey, is_active !== undefined ? is_active : true]
        );
        res.json(result.rows[0]);
    } catch (err) {
        if (err.code === '23505') {
            return res.status(400).json({ error: 'Slug already exists' });
        }
        console.error('Create app error:', err.message, err.stack);
        res.status(500).json({ error: 'Server error', details: process.env.NODE_ENV === 'development' ? err.message : undefined });
    }
});

// Update app
app.put('/api/apps/:id', requireAdmin, async (req, res) => {
    const { id } = req.params;
    const { name, slug, description, url, is_active } = req.body;

    try {
        const result = await pool.query(
            `UPDATE apps SET name = $1, slug = $2, description = $3, url = $4, is_active = $5, updated_at = CURRENT_TIMESTAMP
             WHERE id = $6 RETURNING *`,
            [name, slug.toLowerCase(), description, url, is_active, id]
        );

        if (result.rows.length === 0) {
            return res.status(404).json({ error: 'App not found' });
        }

        res.json(result.rows[0]);
    } catch (err) {
        if (err.code === '23505') {
            return res.status(400).json({ error: 'Slug already exists' });
        }
        console.error('Update app error:', err);
        res.status(500).json({ error: 'Server error' });
    }
});

// Regenerate app API key
app.post('/api/apps/:id/regenerate-key', requireAdmin, async (req, res) => {
    const { id } = req.params;
    const newApiKey = generateApiKey();

    try {
        const result = await pool.query(
            'UPDATE apps SET api_key = $1, updated_at = CURRENT_TIMESTAMP WHERE id = $2 RETURNING *',
            [newApiKey, id]
        );

        if (result.rows.length === 0) {
            return res.status(404).json({ error: 'App not found' });
        }

        res.json(result.rows[0]);
    } catch (err) {
        console.error('Regenerate key error:', err);
        res.status(500).json({ error: 'Server error' });
    }
});

// Delete app
app.delete('/api/apps/:id', requireAdmin, async (req, res) => {
    const { id } = req.params;

    try {
        const result = await pool.query('DELETE FROM apps WHERE id = $1 RETURNING id', [id]);

        if (result.rows.length === 0) {
            return res.status(404).json({ error: 'App not found' });
        }

        res.json({ success: true });
    } catch (err) {
        console.error('Delete app error:', err);
        res.status(500).json({ error: 'Server error' });
    }
});

// ============================================
// RAILWAY API INTEGRATION
// ============================================

// Sync apps from Railway
app.post('/api/railway/sync', requireAdmin, async (req, res) => {
    const railwayToken = process.env.RAILWAY_API_TOKEN;
    if (!railwayToken) {
        return res.status(400).json({ error: 'Railway API token not configured. Add RAILWAY_API_TOKEN to environment variables.' });
    }

    try {
        const query = `
            query {
                me {
                    projects {
                        edges {
                            node {
                                id
                                name
                                services {
                                    edges {
                                        node {
                                            id
                                            name
                                            serviceInstances {
                                                edges {
                                                    node {
                                                        domains {
                                                            serviceDomains {
                                                                domain
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        `;

        const response = await fetch('https://backboard.railway.com/graphql/v2', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${railwayToken}`
            },
            body: JSON.stringify({ query })
        });

        const data = await response.json();

        if (data.errors) {
            return res.status(400).json({ error: 'Railway API error: ' + data.errors[0].message });
        }

        const projects = data.data?.me?.projects?.edges || [];
        let synced = 0;
        let skipped = 0;

        for (const projectEdge of projects) {
            const project = projectEdge.node;
            const services = project.services?.edges || [];

            for (const serviceEdge of services) {
                const service = serviceEdge.node;
                const serviceName = service.name;
                const slug = serviceName.toLowerCase().replace(/[^a-z0-9]+/g, '-');

                // Get the domain URL
                let url = '';
                const instances = service.serviceInstances?.edges || [];
                if (instances.length > 0) {
                    const domains = instances[0].node?.domains?.serviceDomains || [];
                    if (domains.length > 0) {
                        url = 'https://' + domains[0].domain;
                    }
                }

                // Check if app already exists
                const existing = await pool.query('SELECT id FROM apps WHERE slug = $1', [slug]);

                if (existing.rows.length === 0) {
                    // Insert new app
                    const apiKey = generateApiKey();
                    await pool.query(
                        'INSERT INTO apps (name, slug, description, url, api_key) VALUES ($1, $2, $3, $4, $5)',
                        [serviceName, slug, `Synced from Railway project: ${project.name}`, url, apiKey]
                    );
                    synced++;
                } else {
                    // Update URL if changed
                    await pool.query(
                        'UPDATE apps SET url = $1, updated_at = CURRENT_TIMESTAMP WHERE slug = $2',
                        [url, slug]
                    );
                    skipped++;
                }
            }
        }

        res.json({
            success: true,
            message: `Sync complete. Added ${synced} new apps, updated ${skipped} existing apps.`,
            synced,
            skipped
        });
    } catch (err) {
        console.error('Railway sync error:', err);
        res.status(500).json({ error: 'Failed to sync with Railway: ' + err.message });
    }
});

// Check Railway API connection status
app.get('/api/railway/status', requireAdmin, async (req, res) => {
    const railwayToken = process.env.RAILWAY_API_TOKEN;
    if (!railwayToken) {
        return res.json({ connected: false, message: 'Railway API token not configured' });
    }

    try {
        const response = await fetch('https://backboard.railway.com/graphql/v2', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${railwayToken}`
            },
            body: JSON.stringify({ query: '{ me { email } }' })
        });

        const data = await response.json();
        if (data.errors) {
            return res.json({ connected: false, message: 'Invalid token' });
        }

        res.json({ connected: true, email: data.data?.me?.email });
    } catch (err) {
        res.json({ connected: false, message: err.message });
    }
});

// ============================================
// ACCESS CONTROL API ROUTES
// ============================================

// Get user's app access
app.get('/api/users/:id/access', requireAdmin, async (req, res) => {
    const { id } = req.params;

    try {
        const result = await pool.query(`
            SELECT a.id, a.name, a.slug,
                   CASE WHEN uaa.id IS NOT NULL THEN true ELSE false END as has_access
            FROM apps a
            LEFT JOIN user_app_access uaa ON a.id = uaa.app_id AND uaa.user_id = $1
            WHERE a.is_active = true
            ORDER BY a.name
        `, [id]);
        res.json(result.rows);
    } catch (err) {
        console.error('Get user access error:', err);
        res.status(500).json({ error: 'Server error' });
    }
});

// Update user's app access
app.put('/api/users/:id/access', requireAdmin, async (req, res) => {
    const { id } = req.params;
    const { app_ids } = req.body; // Array of app IDs the user should have access to

    try {
        // Start transaction
        await pool.query('BEGIN');

        // Remove all existing access
        await pool.query('DELETE FROM user_app_access WHERE user_id = $1', [id]);

        // Add new access
        if (app_ids && app_ids.length > 0) {
            const values = app_ids.map((appId, index) =>
                `($1, $${index + 2}, $${app_ids.length + 2})`
            ).join(', ');

            await pool.query(
                `INSERT INTO user_app_access (user_id, app_id, granted_by) VALUES ${values}`,
                [id, ...app_ids, req.session.userId]
            );
        }

        await pool.query('COMMIT');

        res.json({ success: true });
    } catch (err) {
        await pool.query('ROLLBACK');
        console.error('Update user access error:', err);
        res.status(500).json({ error: 'Server error' });
    }
});

// Get app's users
app.get('/api/apps/:id/users', requireAdmin, async (req, res) => {
    const { id } = req.params;

    try {
        const result = await pool.query(`
            SELECT u.id, u.name, u.email,
                   CASE WHEN uaa.id IS NOT NULL THEN true ELSE false END as has_access
            FROM users u
            LEFT JOIN user_app_access uaa ON u.id = uaa.user_id AND uaa.app_id = $1
            WHERE u.is_active = true
            ORDER BY u.name
        `, [id]);
        res.json(result.rows);
    } catch (err) {
        console.error('Get app users error:', err);
        res.status(500).json({ error: 'Server error' });
    }
});

// ============================================
// EXTERNAL AUTH API (for your other apps)
// ============================================

// Verify user credentials and app access (called by your other apps)
app.post('/api/auth/verify', async (req, res) => {
    const { email, password, app_slug } = req.body;
    const apiKey = req.headers['x-api-key'];

    if (!apiKey) {
        return res.status(401).json({ error: 'API key required' });
    }

    try {
        // Verify API key belongs to an active app
        const appResult = await pool.query(
            'SELECT id, slug FROM apps WHERE api_key = $1 AND is_active = true',
            [apiKey]
        );

        if (appResult.rows.length === 0) {
            return res.status(401).json({ error: 'Invalid API key' });
        }

        const app = appResult.rows[0];

        // If app_slug provided, verify it matches the API key's app
        if (app_slug && app.slug !== app_slug) {
            return res.status(401).json({ error: 'API key does not match app' });
        }

        // Find user
        const userResult = await pool.query(
            'SELECT id, email, password_hash, name, is_active FROM users WHERE email = $1',
            [email.toLowerCase()]
        );

        if (userResult.rows.length === 0) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }

        const user = userResult.rows[0];

        if (!user.is_active) {
            return res.status(401).json({ error: 'Account is deactivated' });
        }

        // Verify password
        const validPassword = await bcrypt.compare(password, user.password_hash);
        if (!validPassword) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }

        // Check app access
        const accessResult = await pool.query(
            'SELECT id FROM user_app_access WHERE user_id = $1 AND app_id = $2',
            [user.id, app.id]
        );

        if (accessResult.rows.length === 0) {
            return res.status(403).json({ error: 'User does not have access to this app' });
        }

        // Update last login
        await pool.query('UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = $1', [user.id]);

        res.json({
            success: true,
            user: {
                id: user.id,
                email: user.email,
                name: user.name
            }
        });
    } catch (err) {
        console.error('Auth verify error:', err);
        res.status(500).json({ error: 'Server error' });
    }
});

// Check if user has access to app (session-based, called after initial login)
app.get('/api/auth/check-access', async (req, res) => {
    const { user_id, app_slug } = req.query;
    const apiKey = req.headers['x-api-key'];

    if (!apiKey) {
        return res.status(401).json({ error: 'API key required' });
    }

    try {
        const result = await pool.query(`
            SELECT u.id, u.email, u.name
            FROM users u
            JOIN user_app_access uaa ON u.id = uaa.user_id
            JOIN apps a ON uaa.app_id = a.id
            WHERE u.id = $1 AND a.slug = $2 AND a.api_key = $3 AND u.is_active = true AND a.is_active = true
        `, [user_id, app_slug, apiKey]);

        if (result.rows.length === 0) {
            return res.status(403).json({ error: 'Access denied' });
        }

        res.json({ success: true, user: result.rows[0] });
    } catch (err) {
        console.error('Check access error:', err);
        res.status(500).json({ error: 'Server error' });
    }
});

// ============================================
// DASHBOARD STATS
// ============================================

app.get('/api/stats', requireAdmin, async (req, res) => {
    try {
        const stats = await pool.query(`
            SELECT
                (SELECT COUNT(*) FROM users WHERE is_active = true) as total_users,
                (SELECT COUNT(*) FROM apps WHERE is_active = true) as total_apps,
                (SELECT COUNT(*) FROM user_app_access) as total_assignments,
                (SELECT COUNT(*) FROM users WHERE last_login > NOW() - INTERVAL '7 days') as active_users_week
        `);
        res.json(stats.rows[0]);
    } catch (err) {
        console.error('Get stats error:', err);
        res.status(500).json({ error: 'Server error' });
    }
});

// Start server with database initialization
initializeDatabase()
    .then(() => {
        app.listen(PORT, () => {
            console.log(`Admin Panel running on port ${PORT}`);
        });
    })
    .catch(err => {
        console.error('Failed to start server:', err);
        process.exit(1);
    });
