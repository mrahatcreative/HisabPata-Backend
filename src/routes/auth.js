const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { prisma } = require('../config/database');
const { authenticateToken } = require('../middleware/auth');
const { authLimiter } = require('../middleware/rateLimiter');
const { JWT_SECRET } = require('../config/env');
const { DEFAULT_CATEGORIES } = require('../config/constants');

const JWT_SECRET_FINAL = JWT_SECRET || 'dev_secret_key_do_not_use_in_production';

module.exports = function(app) {
  // --- AUTH ROUTES ---

  // Rate-limited auth routes
  app.use('/api/auth/login', authLimiter);
  app.use('/api/auth/register', authLimiter);
  app.use('/api/auth/change-password', authLimiter);

  // Register User
  app.post('/api/auth/register', async (req, res) => {
    try {
      const { name, identifier, password, phone } = req.body;

      if (!identifier || !password || !name) {
        return res.status(400).json({ error: 'Name, identifier (email/phone), and password are required' });
      }

      if (password.length < 6) {
        return res.status(400).json({ error: 'Password must be at least 6 characters long' });
      }

      const email = identifier.includes('@') ? identifier.toLowerCase().trim() : null;
      const phoneNumber = phone ? phone.trim() : (!identifier.includes('@') ? identifier.trim() : null);

      // Check if user already exists
      const existingUser = await prisma.user.findFirst({
        where: {
          OR: [
            email ? { email } : null,
            phoneNumber ? { phoneNumber } : null
          ].filter(Boolean)
        }
      });

      if (existingUser) {
        return res.status(400).json({ error: 'User with this email or phone already exists' });
      }

      // Hash password
      const hashedPassword = await bcrypt.hash(password, 10);

      // Create user + personal org + member + book in one transaction
      const user = await prisma.$transaction(async (tx) => {
        const u = await tx.user.create({
          data: {
            name,
            email,
            phoneNumber,
            password: hashedPassword,
          }
        });

        const personalOrg = await tx.organization.create({
          data: {
            name: `${name}'s Personal`,
            isPersonal: true,
            inviteCode: null,
            categories: DEFAULT_CATEGORIES,
          }
        });

        await tx.organizationMember.create({
          data: {
            userId: u.id,
            organizationId: personalOrg.id,
            role: 'admin',
            status: 'active',
          }
        });

        await tx.book.create({
          data: {
            name: 'Personal Book',
            isDefault: true,
            balance: 0.0,
            organizationId: personalOrg.id,
          }
        });

        return u;
      });

      // Generate JWT
      const token = jwt.sign({ id: user.id, name: user.name, email: user.email, tokenVersion: user.tokenVersion }, JWT_SECRET_FINAL, { expiresIn: '30d' });

      res.status(201).json({
        message: 'User registered successfully',
        token,
        user: {
          id: user.id,
          name: user.name,
          email: user.email,
          phoneNumber: user.phoneNumber,
        }
      });
    } catch (error) {
      console.error('Registration error:', error);
      const hint = error?.code === 'P2022'
        ? 'Database schema out of date — run: npx prisma migrate deploy'
        : error?.code === 'P2002'
          ? 'User with this email or phone already exists'
          : null;
      res.status(500).json({
        error: hint || 'Server error during registration',
        ...(process.env.NODE_ENV !== 'production' && error?.message ? { detail: error.message } : {}),
      });
    }
  });

  // Login User
  app.post('/api/auth/login', async (req, res) => {
    try {
      const { identifier, password } = req.body;

      if (!identifier || !password) {
        return res.status(400).json({ error: 'Identifier and password are required' });
      }

      const searchKey = identifier.trim();
      const isEmail = searchKey.includes('@');

      // Find User
      const user = await prisma.user.findFirst({
        where: {
          OR: [
            isEmail ? { email: searchKey.toLowerCase() } : null,
            { phoneNumber: searchKey }
          ].filter(Boolean)
        }
      });

      if (!user) {
        return res.status(400).json({ error: 'Invalid identifier or password' });
      }

      // Check Password
      const isPasswordValid = await bcrypt.compare(password, user.password);
      if (!isPasswordValid) {
        return res.status(400).json({ error: 'Invalid identifier or password' });
      }

      // Auto-create Personal Org if missing (safety net)
      const existingPersonalOrg = await prisma.organization.findFirst({
        where: { isPersonal: true, members: { some: { userId: user.id } } }
      });
      if (!existingPersonalOrg) {
        const personalOrg = await prisma.organization.create({
          data: {
            name: `${user.name}'s Personal`,
            isPersonal: true,
            inviteCode: null,
            categories: DEFAULT_CATEGORIES,
          }
        });
        await prisma.organizationMember.create({
          data: { userId: user.id, organizationId: personalOrg.id, role: 'admin', status: 'active' }
        });
        await prisma.book.create({
          data: { name: 'Personal Book', isDefault: true, balance: 0.0, organizationId: personalOrg.id }
        });
      }

      // Generate JWT
      const token = jwt.sign({ id: user.id, name: user.name, email: user.email, tokenVersion: user.tokenVersion }, JWT_SECRET_FINAL, { expiresIn: '30d' });

      res.json({
        message: 'Login successful',
        token,
        user: {
          id: user.id,
          name: user.name,
          email: user.email,
          phoneNumber: user.phoneNumber,
          tokenVersion: user.tokenVersion,
        }
      });
    } catch (error) {
      console.error('Login error:', error);
      res.status(500).json({ error: 'Server error during login' });
    }
  });

  // Change Password
  app.post('/api/auth/change-password', authenticateToken, async (req, res) => {
    try {
      const { oldPassword, newPassword } = req.body;
      if (!oldPassword || !newPassword) {
        return res.status(400).json({ error: 'Old and new passwords are required' });
      }
      if (newPassword.length < 6) {
        return res.status(400).json({ error: 'New password must be at least 6 characters' });
      }
      const user = await prisma.user.findUnique({ where: { id: req.user.id } });
      if (!user) return res.status(404).json({ error: 'User not found' });
      const valid = await bcrypt.compare(oldPassword, user.password);
      if (!valid) return res.status(401).json({ error: 'Current password is incorrect' });
      const hashed = await bcrypt.hash(newPassword, 10);
      await prisma.user.update({ where: { id: req.user.id }, data: { password: hashed, tokenVersion: { increment: 1 } } });
      res.json({ message: 'Password changed successfully' });
    } catch (error) {
      console.error('Change password error:', error);
      res.status(500).json({ error: 'Server error changing password' });
    }
  });
};
