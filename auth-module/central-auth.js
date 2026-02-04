/**
 * Central Auth Module
 *
 * Drop this module into any of your existing apps to integrate with the central admin panel.
 *
 * SETUP:
 * 1. npm install express-session
 * 2. Add environment variables:
 *    - ADMIN_PANEL_URL: URL of your admin panel (e.g., https://admin-panel.railway.app)
 *    - APP_API_KEY: The API key from the admin panel for this app
 *    - APP_SLUG: The slug identifier for this app (e.g., "product-catalog")
 *    - SESSION_SECRET: Secret for session cookies
 *
 * 3. In your server.js:
 *    const { setupAuth, requireAuth, getLoginPage } = require('./central-auth');
 *    setupAuth(app);  // Call before your routes
 *
 * 4. Protect routes:
 *    app.get('/dashboard', requireAuth, (req, res) => { ... });
 *    // req.user will contain { id, email, name }
 */

const session = require('express-session');

const ADMIN_PANEL_URL = process.env.ADMIN_PANEL_URL;
const APP_API_KEY = process.env.APP_API_KEY;
const APP_SLUG = process.env.APP_SLUG;

/**
 * Setup authentication middleware
 * Call this in your app before defining routes
 */
function setupAuth(app) {
    // Session middleware
    app.use(session({
        secret: process.env.SESSION_SECRET || 'change-me-in-production',
        resave: false,
        saveUninitialized: false,
        cookie: {
            maxAge: 24 * 60 * 60 * 1000, // 24 hours
            secure: process.env.NODE_ENV === 'production'
        }
    }));

    // Login page route
    app.get('/login', (req, res) => {
        if (req.session.user) {
            return res.redirect('/');
        }
        res.send(getLoginPage(req.query.error));
    });

    // Login handler
    app.post('/login', async (req, res) => {
        const { email, password } = req.body;

        try {
            const response = await fetch(`${ADMIN_PANEL_URL}/api/auth/verify`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-API-Key': APP_API_KEY
                },
                body: JSON.stringify({ email, password, app_slug: APP_SLUG })
            });

            const data = await response.json();

            if (response.ok && data.success) {
                req.session.user = data.user;
                res.redirect('/');
            } else {
                res.redirect('/login?error=' + encodeURIComponent(data.error || 'Login failed'));
            }
        } catch (err) {
            console.error('Auth error:', err);
            res.redirect('/login?error=' + encodeURIComponent('Authentication service unavailable'));
        }
    });

    // Logout handler
    app.get('/logout', (req, res) => {
        req.session.destroy();
        res.redirect('/login');
    });

    app.post('/logout', (req, res) => {
        req.session.destroy();
        res.redirect('/login');
    });
}

/**
 * Middleware to require authentication
 * Use on routes that need login
 */
function requireAuth(req, res, next) {
    if (!req.session.user) {
        return res.redirect('/login');
    }
    req.user = req.session.user;
    next();
}

/**
 * Middleware to require authentication (API version)
 * Returns JSON instead of redirect
 */
function requireAuthAPI(req, res, next) {
    if (!req.session.user) {
        return res.status(401).json({ error: 'Authentication required' });
    }
    req.user = req.session.user;
    next();
}

/**
 * Get the login page HTML
 */
function getLoginPage(error = null) {
    const appName = process.env.APP_NAME || 'Application';

    return `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Login - ${appName}</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
        }
        .login-container {
            background: white;
            padding: 40px;
            border-radius: 12px;
            box-shadow: 0 20px 60px rgba(0, 0, 0, 0.3);
            width: 100%;
            max-width: 400px;
        }
        .login-header { text-align: center; margin-bottom: 30px; }
        .login-header h1 { color: #1a1a2e; font-size: 24px; margin-bottom: 8px; }
        .login-header p { color: #666; font-size: 14px; }
        .form-group { margin-bottom: 20px; }
        .form-group label {
            display: block;
            margin-bottom: 8px;
            color: #333;
            font-weight: 500;
        }
        .form-group input {
            width: 100%;
            padding: 12px 16px;
            border: 2px solid #e0e0e0;
            border-radius: 8px;
            font-size: 16px;
        }
        .form-group input:focus {
            outline: none;
            border-color: #4a6cf7;
        }
        .btn-login {
            width: 100%;
            padding: 14px;
            background: linear-gradient(135deg, #4a6cf7 0%, #6366f1 100%);
            color: white;
            border: none;
            border-radius: 8px;
            font-size: 16px;
            font-weight: 600;
            cursor: pointer;
        }
        .btn-login:hover {
            transform: translateY(-2px);
            box-shadow: 0 8px 20px rgba(74, 108, 247, 0.4);
        }
        .error-message {
            background: #fee2e2;
            color: #dc2626;
            padding: 12px 16px;
            border-radius: 8px;
            margin-bottom: 20px;
            font-size: 14px;
        }
    </style>
</head>
<body>
    <div class="login-container">
        <div class="login-header">
            <h1>${appName}</h1>
            <p>Sign in to continue</p>
        </div>
        ${error ? `<div class="error-message">${error}</div>` : ''}
        <form method="POST" action="/login">
            <div class="form-group">
                <label for="email">Email</label>
                <input type="email" id="email" name="email" required>
            </div>
            <div class="form-group">
                <label for="password">Password</label>
                <input type="password" id="password" name="password" required>
            </div>
            <button type="submit" class="btn-login">Sign In</button>
        </form>
    </div>
</body>
</html>`;
}

/**
 * Check if user is authenticated (for templates)
 */
function isAuthenticated(req) {
    return !!req.session?.user;
}

/**
 * Get current user (for templates)
 */
function getCurrentUser(req) {
    return req.session?.user || null;
}

module.exports = {
    setupAuth,
    requireAuth,
    requireAuthAPI,
    getLoginPage,
    isAuthenticated,
    getCurrentUser
};
