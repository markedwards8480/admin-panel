require('dotenv').config();
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const fs = require('fs');
const path = require('path');

const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
});

async function setup() {
    console.log('Setting up database...');
    try {
        const schemaPath = path.join(__dirname, 'schema.sql');
        const schema = fs.readFileSync(schemaPath, 'utf8');
        await pool.query(schema);
        console.log('✓ Schema created');

        const existingAdmin = await pool.query("SELECT id FROM users WHERE email = $1", [process.env.ADMIN_EMAIL || 'admin@example.com']);
        if (existingAdmin.rows.length === 0) {
            const adminEmail = process.env.ADMIN_EMAIL || 'admin@example.com';
            const adminPassword = process.env.ADMIN_PASSWORD || 'changeme123';
            const adminName = process.env.ADMIN_NAME || 'Admin';
            const passwordHash = await bcrypt.hash(adminPassword, 10);
            await pool.query('INSERT INTO users (email, password_hash, name, is_admin, is_active) VALUES ($1, $2, $3, true, true)', [adminEmail, passwordHash, adminName]);
            console.log('✓ Admin user created');
            console.log('  Email: ' + adminEmail);
            console.log('  Password: ' + adminPassword);
            console.log('  ⚠️  Please change this password after first login!');
        } else {
            console.log('✓ Admin user already exists');
        }
        console.log('\n✅ Database setup complete!');
    } catch (err) {
        console.error('❌ Setup failed:', err.message);
        process.exit(1);
    } finally {
        await pool.end();
    }
}

setup();
