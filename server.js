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

            // Add granted_by column to user_app_access table if it doesn't exist
            const grantedByColumnCheck = await pool.query(`
                SELECT EXISTS (
                    SELECT FROM information_schema.columns
                    WHERE table_name = 'user_app_access' AND column_name = 'granted_by'
                );
            `);

            if (!grantedByColumnCheck.rows[0].exists) {
                console.log('Adding missing granted_by column to user_app_access table...');
                await pool.query('ALTER TABLE user_app_access ADD COLUMN granted_by INTEGER REFERENCES users(id)');
                console.log('granted_by column added successfully.');
            }

            // Create login_activity table if it doesn't exist
            const loginActivityCheck = await pool.query(`
                SELECT EXISTS (
                    SELECT FROM information_schema.tables
                    WHERE table_name = 'login_activity'
                );
            `);

            if (!loginActivityCheck.rows[0].exists) {
                console.log('Creating login_activity table...');
                await pool.query(`
                    CREATE TABLE login_activity (
                        id SERIAL PRIMARY KEY,
                        user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
                        app_id INTEGER REFERENCES apps(id) ON DELETE CASCADE,
                        login_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        ip_address VARCHAR(45),
                        city VARCHAR(100),
                        region VARCHAR(100),
                        country VARCHAR(100),
                        user_agent TEXT
                    );
                    CREATE INDEX idx_login_activity_time ON login_activity(login_time DESC);
                    CREATE INDEX idx_login_activity_user ON login_activity(user_id);
                    CREATE INDEX idx_login_activity_app ON login_activity(app_id);
                `);
                console.log('login_activity table created successfully.');
            }

            // Create health_checks table if it doesn't exist
            const healthChecksCheck = await pool.query(`
                SELECT EXISTS (
                    SELECT FROM information_schema.tables
                    WHERE table_name = 'health_checks'
                );
            `);

            if (!healthChecksCheck.rows[0].exists) {
                console.log('Creating health_checks table...');
                await pool.query(`
                    CREATE TABLE health_checks (
                        id SERIAL PRIMARY KEY,
                        app_id INTEGER REFERENCES apps(id) ON DELETE CASCADE,
                        check_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        status VARCHAR(20) NOT NULL,
                        response_time_ms INTEGER,
                        status_code INTEGER,
                        error_message TEXT
                    );
                    CREATE INDEX idx_health_checks_app ON health_checks(app_id);
                    CREATE INDEX idx_health_checks_time ON health_checks(check_time DESC);
                `);
                console.log('health_checks table created successfully.');
            }

            // Create data_freshness table for tracking data imports
            const dataFreshnessCheck = await pool.query(`
                SELECT EXISTS (
                    SELECT FROM information_schema.tables
                    WHERE table_name = 'data_freshness'
                );
            `);

            if (!dataFreshnessCheck.rows[0].exists) {
                console.log('Creating data_freshness table...');
                await pool.query(`
                    CREATE TABLE data_freshness (
                        id SERIAL PRIMARY KEY,
                        app_id INTEGER REFERENCES apps(id) ON DELETE CASCADE,
                        data_source VARCHAR(255) NOT NULL,
                        last_updated TIMESTAMP,
                        record_count INTEGER,
                        notes TEXT,
                        UNIQUE(app_id, data_source)
                    );
                    CREATE INDEX idx_data_freshness_app ON data_freshness(app_id);
                `);
                console.log('data_freshness table created successfully.');
            }

            // Create departments table if it doesn't exist
            const departmentsCheck = await pool.query(`
                SELECT EXISTS (
                    SELECT FROM information_schema.tables
                    WHERE table_name = 'departments'
                );
            `);

            if (!departmentsCheck.rows[0].exists) {
                console.log('Creating departments table...');
                await pool.query(`
                    CREATE TABLE departments (
                        id SERIAL PRIMARY KEY,
                        name VARCHAR(255) NOT NULL,
                        slug VARCHAR(100) UNIQUE NOT NULL,
                        sort_order INTEGER DEFAULT 0,
                        is_active BOOLEAN DEFAULT TRUE,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    );
                `);
                console.log('departments table created successfully.');
            }

            // Add department_id column to apps table if it doesn't exist
            const deptIdColumnCheck = await pool.query(`
                SELECT EXISTS (
                    SELECT FROM information_schema.columns
                    WHERE table_name = 'apps' AND column_name = 'department_id'
                );
            `);

            if (!deptIdColumnCheck.rows[0].exists) {
                console.log('Adding department_id column to apps table...');
                await pool.query('ALTER TABLE apps ADD COLUMN department_id INTEGER REFERENCES departments(id)');
                console.log('department_id column added successfully.');
            }

            // Add icon column to apps table if it doesn't exist
            const iconColumnCheck = await pool.query(`
                SELECT EXISTS (
                    SELECT FROM information_schema.columns
                    WHERE table_name = 'apps' AND column_name = 'icon'
                );
            `);

            if (!iconColumnCheck.rows[0].exists) {
                console.log('Adding icon column to apps table...');
                await pool.query("ALTER TABLE apps ADD COLUMN icon VARCHAR(20) DEFAULT '📱'");
                console.log('icon column added successfully.');
            }

            // Add color column to apps table if it doesn't exist
            const colorColumnCheck = await pool.query(`
                SELECT EXISTS (
                    SELECT FROM information_schema.columns
                    WHERE table_name = 'apps' AND column_name = 'color'
                );
            `);

            if (!colorColumnCheck.rows[0].exists) {
                console.log('Adding color column to apps table...');
                await pool.query("ALTER TABLE apps ADD COLUMN color VARCHAR(50) DEFAULT 'color-blue'");
                console.log('color column added successfully.');
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
                icon VARCHAR(20) DEFAULT '📱',
                color VARCHAR(50) DEFAULT 'color-blue',
                department_id INTEGER,
                is_active BOOLEAN DEFAULT TRUE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );

            CREATE TABLE IF NOT EXISTS departments (
                id SERIAL PRIMARY KEY,
                name VARCHAR(255) NOT NULL,
                slug VARCHAR(100) UNIQUE NOT NULL,
                sort_order INTEGER DEFAULT 0,
                is_active BOOLEAN DEFAULT TRUE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
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

            CREATE TABLE IF NOT EXISTS login_activity (
                id SERIAL PRIMARY KEY,
                user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
                app_id INTEGER REFERENCES apps(id) ON DELETE CASCADE,
                login_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                ip_address VARCHAR(45),
                city VARCHAR(100),
                region VARCHAR(100),
                country VARCHAR(100),
                user_agent TEXT
            );

            CREATE INDEX IF NOT EXISTS idx_sessions_expire ON sessions(expire);
            CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
            CREATE INDEX IF NOT EXISTS idx_apps_slug ON apps(slug);
            CREATE INDEX IF NOT EXISTS idx_login_activity_time ON login_activity(login_time DESC);
            CREATE INDEX IF NOT EXISTS idx_login_activity_user ON login_activity(user_id);
            CREATE INDEX IF NOT EXISTS idx_login_activity_app ON login_activity(app_id);
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

// Generate memorable password using Word-Word-Number-Symbol format
function generatePassword() {
    // Common, easy-to-remember words (capitalized)
    const words = [
        'Apple', 'Beach', 'Cloud', 'Dance', 'Eagle', 'Flame', 'Green', 'Happy',
        'Island', 'Jungle', 'Kite', 'Lemon', 'Magic', 'Night', 'Ocean', 'Piano',
        'Quest', 'River', 'Storm', 'Tiger', 'Unity', 'Vivid', 'Water', 'Xray',
        'Yellow', 'Zebra', 'Amber', 'Brave', 'Coral', 'Dream', 'Frost', 'Globe',
        'Heart', 'Ivory', 'Jewel', 'Karma', 'Light', 'Maple', 'Noble', 'Olive',
        'Pearl', 'Quilt', 'Radar', 'Silk', 'Trust', 'Ultra', 'Valor', 'Wheel',
        'Blue', 'Candy', 'Delta', 'Echo', 'Flora', 'Grace', 'Honey', 'Jazz',
        'Luna', 'Mocha', 'Nova', 'Opal', 'Prism', 'Rose', 'Solar', 'Terra',
        'Brave', 'Crisp', 'Dusk', 'Ember', 'Fresh', 'Glow', 'Haze', 'Iris',
        'Jade', 'Keen', 'Leaf', 'Mist', 'Neon', 'Oak', 'Peak', 'Rust', 'Sky'
    ];

    const numbers = ['2', '3', '4', '5', '6', '7', '8', '9'];
    const symbols = ['!', '@', '#', '$', '%', '&', '*'];

    // Pick two random words
    const word1 = words[Math.floor(Math.random() * words.length)];
    let word2 = words[Math.floor(Math.random() * words.length)];
    // Ensure word2 is different from word1
    while (word2 === word1) {
        word2 = words[Math.floor(Math.random() * words.length)];
    }

    const num = numbers[Math.floor(Math.random() * numbers.length)];
    const symbol = symbols[Math.floor(Math.random() * symbols.length)];

    // Format: Word-Word#! (e.g., "Apple-Tiger7!")
    return `${word1}-${word2}${num}${symbol}`;
}

// Log login activity with IP geolocation
async function logLoginActivity(userId, appId, ipAddress, userAgent) {
    try {
        let city = null, region = null, country = null;

        // Try to get location from IP using free ipapi.co service
        // Skip for localhost/private IPs
        if (ipAddress && !ipAddress.startsWith('127.') && !ipAddress.startsWith('192.168.') &&
            !ipAddress.startsWith('10.') && ipAddress !== '::1' && ipAddress !== 'unknown') {
            try {
                const geoResponse = await fetch(`https://ipapi.co/${ipAddress}/json/`, {
                    timeout: 3000
                });
                if (geoResponse.ok) {
                    const geoData = await geoResponse.json();
                    if (!geoData.error) {
                        city = geoData.city || null;
                        region = geoData.region || null;
                        country = geoData.country_name || null;
                    }
                }
            } catch (geoErr) {
                // Geolocation failed, continue without it
                console.log('Geolocation lookup failed:', geoErr.message);
            }
        }

        // Insert activity record
        await pool.query(
            `INSERT INTO login_activity (user_id, app_id, ip_address, city, region, country, user_agent)
             VALUES ($1, $2, $3, $4, $5, $6, $7)`,
            [userId, appId, ipAddress, city, region, country, userAgent]
        );
    } catch (err) {
        console.error('Failed to log login activity:', err);
        // Don't throw - this shouldn't break the login flow
    }
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
    const { email, password, name, is_admin, auto_generate_password } = req.body;

    if (!email || !name) {
        return res.status(400).json({ error: 'Email and name are required' });
    }

    // Either use provided password or auto-generate one
    let userPassword = password;
    let generatedPassword = null;

    if (auto_generate_password || !password) {
        generatedPassword = generatePassword(12);
        userPassword = generatedPassword;
    }

    try {
        const passwordHash = await bcrypt.hash(userPassword, 10);
        const result = await pool.query(
            'INSERT INTO users (email, password_hash, name, is_admin) VALUES ($1, $2, $3, $4) RETURNING id, email, name, is_admin, is_active, created_at',
            [email.toLowerCase(), passwordHash, name, is_admin || false]
        );

        const response = result.rows[0];
        // Include the generated password in the response so admin can share it with the user
        if (generatedPassword) {
            response.generated_password = generatedPassword;
        }
        res.json(response);
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

// Admin reset user password (generates new password)
app.post('/api/users/:id/reset-password', requireAdmin, async (req, res) => {
    const { id } = req.params;

    try {
        // Check if user exists
        const userCheck = await pool.query('SELECT id, email, name FROM users WHERE id = $1', [id]);
        if (userCheck.rows.length === 0) {
            return res.status(404).json({ error: 'User not found' });
        }

        // Generate new password
        const newPassword = generatePassword(12);
        const passwordHash = await bcrypt.hash(newPassword, 10);

        // Update user's password
        await pool.query(
            'UPDATE users SET password_hash = $1, updated_at = CURRENT_TIMESTAMP WHERE id = $2',
            [passwordHash, id]
        );

        res.json({
            success: true,
            message: `Password reset for ${userCheck.rows[0].name}`,
            new_password: newPassword,
            user: {
                id: userCheck.rows[0].id,
                email: userCheck.rows[0].email,
                name: userCheck.rows[0].name
            }
        });
    } catch (err) {
        console.error('Reset password error:', err);
        res.status(500).json({ error: 'Failed to reset password' });
    }
});

// User change own password (requires current password)
app.post('/api/auth/change-password', async (req, res) => {
    const { current_password, new_password } = req.body;

    // Check if user is logged in
    if (!req.session.userId) {
        return res.status(401).json({ error: 'Not authenticated' });
    }

    if (!current_password || !new_password) {
        return res.status(400).json({ error: 'Current password and new password are required' });
    }

    if (new_password.length < 8) {
        return res.status(400).json({ error: 'New password must be at least 8 characters long' });
    }

    try {
        // Get user's current password hash
        const userResult = await pool.query(
            'SELECT id, password_hash FROM users WHERE id = $1',
            [req.session.userId]
        );

        if (userResult.rows.length === 0) {
            return res.status(404).json({ error: 'User not found' });
        }

        // Verify current password
        const validPassword = await bcrypt.compare(current_password, userResult.rows[0].password_hash);
        if (!validPassword) {
            return res.status(401).json({ error: 'Current password is incorrect' });
        }

        // Hash and save new password
        const newPasswordHash = await bcrypt.hash(new_password, 10);
        await pool.query(
            'UPDATE users SET password_hash = $1, updated_at = CURRENT_TIMESTAMP WHERE id = $2',
            [newPasswordHash, req.session.userId]
        );

        res.json({ success: true, message: 'Password changed successfully' });
    } catch (err) {
        console.error('Change password error:', err);
        res.status(500).json({ error: 'Failed to change password' });
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
            SELECT a.*, d.name as department_name, d.slug as department_slug,
                   COUNT(uaa.user_id) as user_count
            FROM apps a
            LEFT JOIN departments d ON a.department_id = d.id
            LEFT JOIN user_app_access uaa ON a.id = uaa.app_id
            GROUP BY a.id, d.name, d.slug
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
    const { name, slug, description, url, icon, color, department_id, is_active } = req.body;

    if (!name || !slug) {
        return res.status(400).json({ error: 'Name and slug are required' });
    }

    const apiKey = generateApiKey();

    try {
        const result = await pool.query(
            'INSERT INTO apps (name, slug, description, url, api_key, icon, color, department_id, is_active) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) RETURNING *',
            [name, slug.toLowerCase(), description, url, apiKey, icon || '📱', color || 'color-blue', department_id || null, is_active !== undefined ? is_active : true]
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
    const { name, slug, description, url, icon, color, department_id, is_active } = req.body;

    try {
        const result = await pool.query(
            `UPDATE apps SET name = $1, slug = $2, description = $3, url = $4, icon = $5, color = $6, department_id = $7, is_active = $8, updated_at = CURRENT_TIMESTAMP
             WHERE id = $9 RETURNING *`,
            [name, slug.toLowerCase(), description, url, icon || '📱', color || 'color-blue', department_id || null, is_active, id]
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

// Get all Railway projects (for dropdown)
app.get('/api/railway/projects', requireAdmin, async (req, res) => {
    const railwayToken = process.env.RAILWAY_API_TOKEN;
    
    if (!railwayToken) {
        return res.status(400).json({ error: 'Railway API token not configured in environment variables' });
    }

    try {
        const query = `
            {
                me {
                    projects {
                        edges {
                            node {
                                id
                                name
                                description
                                createdAt
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

        const projects = data.data?.me?.projects?.edges.map(edge => edge.node) || [];
        res.json(projects);
    } catch (err) {
        console.error('Fetch Railway projects error:', err);
        res.status(500).json({ error: 'Failed to fetch Railway projects: ' + err.message });
    }
});

// Sync apps from a specific Railway project
app.post('/api/railway/sync/:projectId', requireAdmin, async (req, res) => {
    const { projectId } = req.params;
    const railwayToken = process.env.RAILWAY_API_TOKEN;
    
    if (!railwayToken) {
        return res.status(400).json({ error: 'Railway API token not configured in environment variables' });
    }

    try {
        const query = `
            {
                project(id: "${projectId}") {
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

        const project = data.data?.project;
        if (!project) {
            return res.status(404).json({ error: 'Project not found' });
        }

        const services = project.services?.edges || [];
        let synced = 0;
        let skipped = 0;
        const syncedApps = [];

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
            const existing = await pool.query('SELECT id, name, url FROM apps WHERE slug = $1', [slug]);

            if (existing.rows.length === 0) {
                // Insert new app
                const apiKey = generateApiKey();
                const result = await pool.query(
                    'INSERT INTO apps (name, slug, description, url, api_key) VALUES ($1, $2, $3, $4, $5) RETURNING *',
                    [serviceName, slug, `Synced from Railway project: ${project.name}`, url, apiKey]
                );
                syncedApps.push(result.rows[0]);
                synced++;
            } else {
                // Update URL if changed
                if (existing.rows[0].url !== url && url) {
                    await pool.query(
                        'UPDATE apps SET url = $1, updated_at = CURRENT_TIMESTAMP WHERE slug = $2',
                        [url, slug]
                    );
                }
                syncedApps.push(existing.rows[0]);
                skipped++;
            }
        }

        res.json({
            success: true,
            message: `Synced project "${project.name}". Added ${synced} new apps, ${skipped} already existed.`,
            synced,
            skipped,
            apps: syncedApps
        });
    } catch (err) {
        console.error('Railway sync error:', err);
        res.status(500).json({ error: 'Failed to sync with Railway: ' + err.message });
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
        // Verify user exists
        const userCheck = await pool.query('SELECT id FROM users WHERE id = $1', [id]);
        if (userCheck.rows.length === 0) {
            return res.status(404).json({ error: 'User not found' });
        }

        // Start transaction
        await pool.query('BEGIN');

        // Remove all existing access
        await pool.query('DELETE FROM user_app_access WHERE user_id = $1', [id]);

        // Add new access
        if (app_ids && app_ids.length > 0) {
            // Get granted_by - use session user or null if not available
            const grantedBy = req.session.userId || null;

            // Insert each app access individually for better error handling
            for (const appId of app_ids) {
                await pool.query(
                    `INSERT INTO user_app_access (user_id, app_id, granted_by) VALUES ($1, $2, $3)`,
                    [id, appId, grantedBy]
                );
            }
        }

        await pool.query('COMMIT');

        res.json({ success: true });
    } catch (err) {
        await pool.query('ROLLBACK');
        console.error('Update user access error:', err);
        console.error('Error details:', err.message, err.code);
        res.status(500).json({ error: 'Failed to save access settings: ' + err.message });
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

        // Log login activity
        const ipAddress = req.headers['x-forwarded-for']?.split(',')[0]?.trim() || req.ip || 'unknown';
        const userAgent = req.headers['user-agent'] || 'unknown';

        // Try to get location from IP (async, don't wait for it)
        logLoginActivity(user.id, app.id, ipAddress, userAgent);

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
// ACTIVITY TRACKING API
// ============================================

// Get recent login activity
app.get('/api/activity/recent', requireAdmin, async (req, res) => {
    const limit = parseInt(req.query.limit) || 50;

    try {
        const result = await pool.query(`
            SELECT la.id, la.login_time, la.ip_address, la.city, la.region, la.country, la.user_agent,
                   u.id as user_id, u.name as user_name, u.email as user_email,
                   a.id as app_id, a.name as app_name, a.slug as app_slug
            FROM login_activity la
            JOIN users u ON la.user_id = u.id
            JOIN apps a ON la.app_id = a.id
            ORDER BY la.login_time DESC
            LIMIT $1
        `, [limit]);

        res.json(result.rows);
    } catch (err) {
        console.error('Get recent activity error:', err);
        res.status(500).json({ error: 'Server error' });
    }
});

// Get activity statistics summary
app.get('/api/activity/stats', requireAdmin, async (req, res) => {
    try {
        const stats = await pool.query(`
            SELECT
                (SELECT COUNT(*) FROM login_activity WHERE login_time > NOW() - INTERVAL '24 hours') as logins_today,
                (SELECT COUNT(*) FROM login_activity WHERE login_time > NOW() - INTERVAL '7 days') as logins_week,
                (SELECT COUNT(DISTINCT user_id) FROM login_activity WHERE login_time > NOW() - INTERVAL '24 hours') as unique_users_today,
                (SELECT COUNT(DISTINCT user_id) FROM login_activity WHERE login_time > NOW() - INTERVAL '7 days') as unique_users_week,
                (SELECT COUNT(*) FROM login_activity) as total_logins
        `);

        res.json(stats.rows[0]);
    } catch (err) {
        console.error('Get activity stats error:', err);
        res.status(500).json({ error: 'Server error' });
    }
});

// Get logins grouped by app
app.get('/api/activity/by-app', requireAdmin, async (req, res) => {
    try {
        const result = await pool.query(`
            SELECT a.id, a.name, a.slug,
                   COUNT(la.id) as total_logins,
                   COUNT(CASE WHEN la.login_time > NOW() - INTERVAL '7 days' THEN 1 END) as logins_week,
                   COUNT(CASE WHEN la.login_time > NOW() - INTERVAL '24 hours' THEN 1 END) as logins_today,
                   MAX(la.login_time) as last_login
            FROM apps a
            LEFT JOIN login_activity la ON a.id = la.app_id
            WHERE a.is_active = true
            GROUP BY a.id, a.name, a.slug
            ORDER BY logins_week DESC
        `);

        res.json(result.rows);
    } catch (err) {
        console.error('Get activity by app error:', err);
        res.status(500).json({ error: 'Server error' });
    }
});

// Get logins grouped by location
app.get('/api/activity/by-location', requireAdmin, async (req, res) => {
    try {
        const result = await pool.query(`
            SELECT country, city, region,
                   COUNT(*) as login_count,
                   COUNT(DISTINCT user_id) as unique_users,
                   MAX(login_time) as last_login
            FROM login_activity
            WHERE country IS NOT NULL
            GROUP BY country, city, region
            ORDER BY login_count DESC
            LIMIT 50
        `);

        res.json(result.rows);
    } catch (err) {
        console.error('Get activity by location error:', err);
        res.status(500).json({ error: 'Server error' });
    }
});

// Get activity for a specific user
app.get('/api/activity/user/:id', requireAdmin, async (req, res) => {
    const { id } = req.params;
    const limit = parseInt(req.query.limit) || 20;

    try {
        const result = await pool.query(`
            SELECT la.id, la.login_time, la.ip_address, la.city, la.region, la.country, la.user_agent,
                   a.name as app_name, a.slug as app_slug
            FROM login_activity la
            JOIN apps a ON la.app_id = a.id
            WHERE la.user_id = $1
            ORDER BY la.login_time DESC
            LIMIT $2
        `, [id, limit]);

        res.json(result.rows);
    } catch (err) {
        console.error('Get user activity error:', err);
        res.status(500).json({ error: 'Server error' });
    }
});

// ============================================
// DEPARTMENT MANAGEMENT API ROUTES
// ============================================

// Get all departments
app.get('/api/departments', requireAdmin, async (req, res) => {
    try {
        const result = await pool.query(`
            SELECT d.*, COUNT(a.id) as app_count
            FROM departments d
            LEFT JOIN apps a ON d.id = a.department_id AND a.is_active = true
            GROUP BY d.id
            ORDER BY d.sort_order, d.name
        `);
        res.json(result.rows);
    } catch (err) {
        console.error('Get departments error:', err);
        res.status(500).json({ error: 'Server error' });
    }
});

// Create department
app.post('/api/departments', requireAdmin, async (req, res) => {
    const { name, slug, sort_order } = req.body;

    if (!name) {
        return res.status(400).json({ error: 'Name is required' });
    }

    const deptSlug = slug || name.toLowerCase().replace(/[^a-z0-9]+/g, '-');

    try {
        const maxOrder = await pool.query('SELECT COALESCE(MAX(sort_order), 0) + 1 as next_order FROM departments');
        const result = await pool.query(
            'INSERT INTO departments (name, slug, sort_order) VALUES ($1, $2, $3) RETURNING *',
            [name, deptSlug, sort_order || maxOrder.rows[0].next_order]
        );
        res.json(result.rows[0]);
    } catch (err) {
        if (err.code === '23505') {
            return res.status(400).json({ error: 'Department slug already exists' });
        }
        console.error('Create department error:', err);
        res.status(500).json({ error: 'Server error' });
    }
});

// Update department
app.put('/api/departments/:id', requireAdmin, async (req, res) => {
    const { id } = req.params;
    const { name, sort_order, is_active } = req.body;
    const slug = name.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '');

    try {
        const result = await pool.query(
            'UPDATE departments SET name = $1, slug = $2, sort_order = $3, is_active = $4 WHERE id = $5 RETURNING *',
            [name, slug, sort_order, is_active, id]
        );

        if (result.rows.length === 0) {
            return res.status(404).json({ error: 'Department not found' });
        }

        res.json(result.rows[0]);
    } catch (err) {
        console.error('Update department error:', err);
        res.status(500).json({ error: 'Server error' });
    }
});

// Delete department
app.delete('/api/departments/:id', requireAdmin, async (req, res) => {
    const { id } = req.params;

    try {
        // Unassign apps from this department first
        await pool.query('UPDATE apps SET department_id = NULL WHERE department_id = $1', [id]);
        const result = await pool.query('DELETE FROM departments WHERE id = $1 RETURNING id', [id]);

        if (result.rows.length === 0) {
            return res.status(404).json({ error: 'Department not found' });
        }

        res.json({ success: true });
    } catch (err) {
        console.error('Delete department error:', err);
        res.status(500).json({ error: 'Server error' });
    }
});

// ============================================
// APP HUB API (called by the App Hub app)
// ============================================

// SSO token store (in-memory, short-lived)
const ssoTokens = new Map();
const SSO_TOKEN_TTL = 60 * 1000; // 60 seconds

// Clean expired SSO tokens every 5 minutes
setInterval(() => {
    const now = Date.now();
    for (const [token, data] of ssoTokens) {
        if (now > data.expiresAt) ssoTokens.delete(token);
    }
}, 5 * 60 * 1000);

// Authenticate user and return their accessible apps grouped by department
// Called by App Hub on login
app.post('/api/hub/authenticate', async (req, res) => {
    const { email, password } = req.body;

    if (!email || !password) {
        return res.status(400).json({ error: 'Email and password required' });
    }

    try {
        // Find user
        const userResult = await pool.query(
            'SELECT id, email, password_hash, name, is_admin, is_active FROM users WHERE email = $1',
            [email.toLowerCase()]
        );

        if (userResult.rows.length === 0) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }

        const user = userResult.rows[0];

        if (!user.is_active) {
            return res.status(401).json({ error: 'Account is deactivated' });
        }

        const validPassword = await bcrypt.compare(password, user.password_hash);
        if (!validPassword) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }

        // Update last login
        await pool.query('UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = $1', [user.id]);

        // Get user's accessible apps grouped by department
        const appsResult = await pool.query(`
            SELECT a.id, a.name, a.slug, a.description, a.url, a.icon, a.color,
                   d.id as department_id, d.name as department_name, d.slug as department_slug, d.sort_order as department_sort
            FROM apps a
            JOIN user_app_access uaa ON a.id = uaa.app_id
            LEFT JOIN departments d ON a.department_id = d.id
            WHERE uaa.user_id = $1 AND a.is_active = true
            ORDER BY d.sort_order NULLS LAST, d.name, a.name
        `, [user.id]);

        // Group apps by department
        const departments = {};
        const ungrouped = [];

        for (const app of appsResult.rows) {
            if (app.department_id) {
                if (!departments[app.department_id]) {
                    departments[app.department_id] = {
                        id: app.department_id,
                        name: app.department_name,
                        slug: app.department_slug,
                        sort_order: app.department_sort,
                        apps: []
                    };
                }
                departments[app.department_id].apps.push({
                    id: app.id,
                    name: app.name,
                    slug: app.slug,
                    description: app.description,
                    url: app.url,
                    icon: app.icon || '📱',
                    color: app.color || 'color-blue'
                });
            } else {
                ungrouped.push({
                    id: app.id,
                    name: app.name,
                    slug: app.slug,
                    description: app.description,
                    url: app.url,
                    icon: app.icon || '📱',
                    color: app.color || 'color-blue'
                });
            }
        }

        // Sort departments by sort_order
        const sortedDepartments = Object.values(departments).sort((a, b) => (a.sort_order || 0) - (b.sort_order || 0));

        // Add ungrouped at end if any
        if (ungrouped.length > 0) {
            sortedDepartments.push({
                id: null,
                name: 'Other',
                slug: 'other',
                sort_order: 999,
                apps: ungrouped
            });
        }

        res.json({
            success: true,
            user: {
                id: user.id,
                email: user.email,
                name: user.name,
                is_admin: user.is_admin
            },
            departments: sortedDepartments
        });
    } catch (err) {
        console.error('Hub authenticate error:', err);
        res.status(500).json({ error: 'Server error' });
    }
});

// Get user's apps (for already-authenticated sessions, called by App Hub)
app.post('/api/hub/user-apps', async (req, res) => {
    const { user_id } = req.body;
    const ssoSecret = req.headers['x-sso-secret'];

    // Verify SSO secret
    if (!process.env.SSO_SECRET || ssoSecret !== process.env.SSO_SECRET) {
        return res.status(401).json({ error: 'Invalid SSO secret' });
    }

    if (!user_id) {
        return res.status(400).json({ error: 'user_id required' });
    }

    try {
        const appsResult = await pool.query(`
            SELECT a.id, a.name, a.slug, a.description, a.url, a.icon, a.color,
                   d.id as department_id, d.name as department_name, d.slug as department_slug, d.sort_order as department_sort
            FROM apps a
            JOIN user_app_access uaa ON a.id = uaa.app_id
            LEFT JOIN departments d ON a.department_id = d.id
            WHERE uaa.user_id = $1 AND a.is_active = true
            ORDER BY d.sort_order NULLS LAST, d.name, a.name
        `, [user_id]);

        // Group by department (same logic as authenticate)
        const departments = {};
        const ungrouped = [];

        for (const app of appsResult.rows) {
            if (app.department_id) {
                if (!departments[app.department_id]) {
                    departments[app.department_id] = {
                        id: app.department_id,
                        name: app.department_name,
                        slug: app.department_slug,
                        sort_order: app.department_sort,
                        apps: []
                    };
                }
                departments[app.department_id].apps.push({
                    id: app.id, name: app.name, slug: app.slug,
                    description: app.description, url: app.url,
                    icon: app.icon || '📱', color: app.color || 'color-blue'
                });
            } else {
                ungrouped.push({
                    id: app.id, name: app.name, slug: app.slug,
                    description: app.description, url: app.url,
                    icon: app.icon || '📱', color: app.color || 'color-blue'
                });
            }
        }

        const sortedDepartments = Object.values(departments).sort((a, b) => (a.sort_order || 0) - (b.sort_order || 0));
        if (ungrouped.length > 0) {
            sortedDepartments.push({ id: null, name: 'Other', slug: 'other', sort_order: 999, apps: ungrouped });
        }

        res.json({ success: true, departments: sortedDepartments });
    } catch (err) {
        console.error('Hub user-apps error:', err);
        res.status(500).json({ error: 'Server error' });
    }
});

// Generate SSO token (called by App Hub when user clicks an app)
app.post('/api/hub/sso-generate', async (req, res) => {
    const { user_id, user_email, user_name, is_admin, target_url } = req.body;
    const ssoSecret = req.headers['x-sso-secret'];

    if (!process.env.SSO_SECRET || ssoSecret !== process.env.SSO_SECRET) {
        return res.status(401).json({ error: 'Invalid SSO secret' });
    }

    const ssoToken = crypto.randomBytes(32).toString('hex');
    ssoTokens.set(ssoToken, {
        user: { id: user_id, email: user_email, name: user_name, is_admin: is_admin },
        targetUrl: target_url,
        createdAt: Date.now(),
        expiresAt: Date.now() + SSO_TOKEN_TTL,
        used: false
    });

    res.json({ success: true, sso_token: ssoToken });
});

// Validate SSO token (called by individual apps when they receive ?sso_token)
app.post('/api/hub/sso-validate', async (req, res) => {
    const { sso_token } = req.body;
    const ssoSecret = req.headers['x-sso-secret'];

    if (!process.env.SSO_SECRET || ssoSecret !== process.env.SSO_SECRET) {
        return res.status(401).json({ error: 'Invalid SSO secret' });
    }

    if (!sso_token) {
        return res.status(400).json({ error: 'sso_token required' });
    }

    const tokenData = ssoTokens.get(sso_token);

    if (!tokenData) {
        return res.status(401).json({ error: 'Invalid or expired SSO token' });
    }

    if (Date.now() > tokenData.expiresAt) {
        ssoTokens.delete(sso_token);
        return res.status(401).json({ error: 'SSO token expired' });
    }

    if (tokenData.used) {
        ssoTokens.delete(sso_token);
        return res.status(401).json({ error: 'SSO token already used' });
    }

    tokenData.used = true;
    ssoTokens.delete(sso_token);

    // Log SSO activity
    try {
        const ipAddress = req.headers['x-forwarded-for']?.split(',')[0]?.trim() || req.ip || 'unknown';
        const userAgent = req.headers['user-agent'] || 'SSO';
        
        // Find the app by URL to log activity
        if (tokenData.targetUrl) {
            const appResult = await pool.query('SELECT id FROM apps WHERE url = $1 AND is_active = true', [tokenData.targetUrl]);
            if (appResult.rows.length > 0) {
                logLoginActivity(tokenData.user.id, appResult.rows[0].id, ipAddress, userAgent);
            }
        }
    } catch (err) {
        console.log('SSO activity logging failed:', err.message);
    }

    res.json({
        success: true,
        user: tokenData.user
    });
});

// ============================================
// HEALTH CHECK API
// ============================================

// Perform health check on a single app
async function checkAppHealth(app) {
    const startTime = Date.now();
    let status = 'unknown';
    let statusCode = null;
    let errorMessage = null;
    let responseTimeMs = null;

    if (!app.url) {
        return { status: 'no_url', responseTimeMs: null, statusCode: null, errorMessage: 'No URL configured' };
    }

    try {
        const controller = new AbortController();
        const timeout = setTimeout(() => controller.abort(), 10000); // 10 second timeout

        const response = await fetch(app.url, {
            method: 'GET',
            signal: controller.signal,
            headers: { 'User-Agent': 'AdminPanel-HealthCheck/1.0' }
        });

        clearTimeout(timeout);
        responseTimeMs = Date.now() - startTime;
        statusCode = response.status;

        if (response.ok) {
            status = 'healthy';
        } else {
            status = 'unhealthy';
            errorMessage = `HTTP ${response.status}`;
        }
    } catch (err) {
        responseTimeMs = Date.now() - startTime;
        status = 'error';
        errorMessage = err.name === 'AbortError' ? 'Timeout (>10s)' : err.message;
    }

    return { status, responseTimeMs, statusCode, errorMessage };
}

// Run health checks on all apps
app.post('/api/health/check-all', requireAdmin, async (req, res) => {
    try {
        const appsResult = await pool.query('SELECT id, name, url FROM apps WHERE is_active = true');
        const results = [];

        for (const app of appsResult.rows) {
            const health = await checkAppHealth(app);

            // Store the result
            await pool.query(`
                INSERT INTO health_checks (app_id, status, response_time_ms, status_code, error_message)
                VALUES ($1, $2, $3, $4, $5)
            `, [app.id, health.status, health.responseTimeMs, health.statusCode, health.errorMessage]);

            results.push({
                app_id: app.id,
                app_name: app.name,
                ...health
            });
        }

        res.json({ success: true, results });
    } catch (err) {
        console.error('Health check error:', err);
        res.status(500).json({ error: 'Failed to run health checks' });
    }
});

// Get latest health status for all apps
app.get('/api/health/status', requireAdmin, async (req, res) => {
    try {
        const result = await pool.query(`
            SELECT DISTINCT ON (a.id)
                a.id, a.name, a.slug, a.url,
                hc.status, hc.response_time_ms, hc.status_code, hc.error_message, hc.check_time
            FROM apps a
            LEFT JOIN health_checks hc ON a.id = hc.app_id
            WHERE a.is_active = true
            ORDER BY a.id, hc.check_time DESC
        `);

        res.json(result.rows);
    } catch (err) {
        console.error('Get health status error:', err);
        res.status(500).json({ error: 'Server error' });
    }
});

// Get health history for an app
app.get('/api/health/history/:id', requireAdmin, async (req, res) => {
    const { id } = req.params;
    const limit = parseInt(req.query.limit) || 50;

    try {
        const result = await pool.query(`
            SELECT status, response_time_ms, status_code, error_message, check_time
            FROM health_checks
            WHERE app_id = $1
            ORDER BY check_time DESC
            LIMIT $2
        `, [id, limit]);

        res.json(result.rows);
    } catch (err) {
        console.error('Get health history error:', err);
        res.status(500).json({ error: 'Server error' });
    }
});

// Get/update data freshness for an app
app.get('/api/health/freshness', requireAdmin, async (req, res) => {
    try {
        const result = await pool.query(`
            SELECT df.*, a.name as app_name, a.slug as app_slug
            FROM data_freshness df
            JOIN apps a ON df.app_id = a.id
            WHERE a.is_active = true
            ORDER BY df.last_updated DESC
        `);

        res.json(result.rows);
    } catch (err) {
        console.error('Get data freshness error:', err);
        res.status(500).json({ error: 'Server error' });
    }
});

// Update data freshness (can be called by apps via API)
app.post('/api/health/freshness', async (req, res) => {
    const { app_slug, data_source, last_updated, record_count, notes } = req.body;
    const apiKey = req.headers['x-api-key'];

    if (!apiKey) {
        return res.status(401).json({ error: 'API key required' });
    }

    try {
        // Verify API key
        const appResult = await pool.query(
            'SELECT id FROM apps WHERE api_key = $1 AND is_active = true',
            [apiKey]
        );

        if (appResult.rows.length === 0) {
            return res.status(401).json({ error: 'Invalid API key' });
        }

        const appId = appResult.rows[0].id;

        // Upsert freshness record
        await pool.query(`
            INSERT INTO data_freshness (app_id, data_source, last_updated, record_count, notes)
            VALUES ($1, $2, $3, $4, $5)
            ON CONFLICT (app_id, data_source)
            DO UPDATE SET last_updated = $3, record_count = $4, notes = $5
        `, [appId, data_source, last_updated || new Date(), record_count, notes]);

        res.json({ success: true });
    } catch (err) {
        console.error('Update freshness error:', err);
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
