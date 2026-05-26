const express = require('express');
const http = require('http');
const { WebSocketServer } = require('ws');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const { Pool } = require('pg');
const { PrismaPg } = require('@prisma/adapter-pg');
const { PrismaClient } = require('@prisma/client');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
require('dotenv').config();

const pool = new Pool({ connectionString: process.env.DATABASE_URL });
const adapter = new PrismaPg(pool);
const prisma = new PrismaClient({ adapter });
const app = express();
const PORT = process.env.PORT || 8000;

const uploadDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadDir)) {
  fs.mkdirSync(uploadDir, { recursive: true });
}

const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, uploadDir);
  },
  filename: (req, file, cb) => {
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
    cb(null, uniqueSuffix + path.extname(file.originalname));
  }
});

const upload = multer({
  storage: storage,
  limits: { fileSize: 100 * 1024 * 1024 }, // 100MB limit (large for videos)
  fileFilter: (req, file, cb) => {
    const filetypes = /jpeg|jpg|png|gif|webp|mp4|mov|avi|mkv|quicktime/;
    const mimetype = filetypes.test(file.mimetype);
    const extname = filetypes.test(path.extname(file.originalname).toLowerCase());
    
    if (mimetype || extname) {
      return cb(null, true);
    }
    cb(new Error('Only images (jpeg, jpg, png, gif, webp) and videos (mp4, mov, avi, mkv) are allowed!'));
  }
});

const JWT_SECRET = process.env.JWT_SECRET;
if (!JWT_SECRET) {
  if (process.env.NODE_ENV === 'production') {
    console.error('FATAL: JWT_SECRET must be set in production!');
    process.exit(1);
  }
  console.warn('WARNING: JWT_SECRET not set. Using fallback (dev only).');
}
const JWT_SECRET_FINAL = JWT_SECRET || 'dev_secret_key_do_not_use_in_production';

// Rate limiting: max 10 requests per minute on auth routes
const authLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 10,
  message: { error: 'Too many attempts. Please try again later.' },
  standardHeaders: true,
  legacyHeaders: false,
});

const corsOrigins = process.env.CORS_ORIGINS;
const isCorsWildcard = corsOrigins === '*';
const allowedOrigins = isCorsWildcard
  ? true
  : corsOrigins
    ? corsOrigins.split(',').map(s => s.trim())
    : ['http://localhost:3000', 'http://127.0.0.1:3000', 'http://localhost:5000', 'http://127.0.0.1:5000', 'http://localhost:5173', 'http://127.0.0.1:5173'];
app.use(helmet({
  crossOriginResourcePolicy: { policy: 'cross-origin' },
}));
app.use(cors({
  origin: allowedOrigins,
  credentials: !isCorsWildcard,
}));
app.use(express.json());
app.use('/uploads', express.static(uploadDir));
app.use('/admin', express.static(path.join(__dirname, '..', 'admin_console')));

// Log requests
app.use((req, res, next) => {
  console.log(`[${new Date().toISOString()}] ${req.method} ${req.path}`);
  next();
});

// Healthcheck endpoint (no auth required)
app.get('/api/health', (_req, res) => res.json({ status: 'ok' }));

// Middleware: Authenticate JWT Token
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'Access token required' });
  }

  jwt.verify(token, JWT_SECRET_FINAL, async (err, decoded) => {
    if (err) {
      return res.status(403).json({ error: 'Invalid or expired token' });
    }
    
    try {
      // Security Hardening: check tokenVersion in database to support revocation
      const dbUser = await prisma.user.findUnique({ where: { id: decoded.id } });
      if (!dbUser || dbUser.tokenVersion !== decoded.tokenVersion) {
        return res.status(403).json({ error: 'Token has been revoked or expired' });
      }
      req.user = decoded;
      next();
    } catch (dbErr) {
      console.error('Auth middleware error:', dbErr);
      return res.status(500).json({ error: 'Internal server error during auth' });
    }
  });
};

// Middleware: Admin-only access via admin key
const authenticateAdmin = (req, res, next) => {
  const adminKey = req.headers['x-admin-key'];
  if (!adminKey || adminKey !== process.env.ADMIN_KEY) {
    return res.status(401).json({ error: 'Valid admin key required' });
  }
  next();
};

// Upload Endpoint (requires authentication, max 5MB, key: 'file')
app.post('/api/upload', authenticateToken, (req, res) => {
  upload.single('file')(req, res, (err) => {
    if (err instanceof multer.MulterError) {
      if (err.code === 'LIMIT_FILE_SIZE') {
        return res.status(400).json({ error: 'File size limit exceeded. Max limit is 5MB.' });
      }
      return res.status(400).json({ error: err.message });
    } else if (err) {
      return res.status(400).json({ error: err.message });
    }
    
    if (!req.file) {
      return res.status(400).json({ error: 'No file uploaded' });
    }
    
    // Return relative URL path
    const fileUrl = `/uploads/${req.file.filename}`;
    res.json({ imageUrl: fileUrl });
  });
});


// Helper: Check if user is an active member of the book's organization
const hasBookAccess = async (book, userId) => {
  const membership = await prisma.organizationMember.findUnique({
    where: {
      userId_organizationId: {
        userId,
        organizationId: book.organizationId
      }
    }
  });
  return !!membership && membership.status === 'active';
};

// Helper: Check permission for a user in an org
// Admin (role='admin') has all permissions automatically
// Member (role='member') must have the required permission in permissions[]
// Legacy 'editor' role is treated as having 'edit_all' permission
// Personal orgs: user always has all permissions
const checkPermission = async (orgId, userId, permission) => {
  const [membership, org] = await Promise.all([
    prisma.organizationMember.findUnique({
      where: { userId_organizationId: { userId, organizationId: orgId } }
    }),
    prisma.organization.findUnique({ where: { id: orgId }, select: { isPersonal: true } })
  ]);
  if (org?.isPersonal) return true;
  if (!membership || membership.status !== 'active') return false;
  if (membership.role === 'admin') return true;
  // Legacy backward compatibility: 'editor' role = has 'edit_all' permission
  if (membership.role === 'editor') return permission === 'edit_all';
  const perms = membership.permissions || [];
  return perms.includes(permission);
};

// Helper: Check if user has admin or editor access (legacy, used in book edit/delete)
const hasAdminOrEditorAccess = async (orgId, userId) => {
  return checkPermission(orgId, userId, 'edit_all');
};

// Check if a user bypasses org approval based on the org's approval policy
const checkApprovalBypass = async (orgId, userId) => {
  const org = await prisma.organization.findUnique({ where: { id: orgId }, select: { approvalPolicy: true, whitelistedUserIds: true, isPersonal: true } });
  if (!org || org.isPersonal) return true; // Personal orgs always bypass
  
  // Admins bypass approval by default
  const membership = await prisma.organizationMember.findUnique({
    where: { userId_organizationId: { userId, organizationId: orgId } }
  });
  if (membership && membership.role === 'admin') return true;
  
  if (org.approvalPolicy === 'GLOBALLY_OFF') return true;
  if (org.approvalPolicy === 'CONDITIONAL_ON' && (org.whitelistedUserIds || []).includes(userId)) return true;
  return false; // GLOBALLY_ON or CONDITIONAL_ON but not whitelisted
};

// Calculate remaining balance of an org fund advance (for chain split / deficit)
// Returns { remaining, parentAmount, splitTotal } so callers have full context.
const getChainRemainingBalance = async (orgFundId) => {
  const parentTxn = await prisma.transaction.findUnique({ where: { id: orgFundId } });
  if (!parentTxn) return { remaining: 0, parentAmount: 0, splitTotal: 0 };
  let chainId = parentTxn.chainId;
  if (!chainId && parentTxn.linkedTransactionId) {
    const linked = await prisma.transaction.findUnique({ where: { id: parentTxn.linkedTransactionId } });
    chainId = linked?.chainId;
  }
  if (!chainId) return { remaining: parentTxn.amount, parentAmount: parentTxn.amount, splitTotal: 0 };
  const chainTxns = await prisma.transaction.findMany({ where: { chainId } });
  const parentAmount = chainTxns.filter(t => t.chainType === 'parent').reduce((s, t) => s + t.amount, 0) || parentTxn.amount;
  const splitTotal = chainTxns.filter(t => t.chainType === 'split').reduce((s, t) => s + t.amount, 0);
  // Guard against overshoot: remaining cannot be negative
  const remaining = Math.max(0, parentAmount - splitTotal);
  return { remaining, parentAmount, splitTotal };
};

// Get active admin user IDs for an organization
const getOrgAdminUserIds = async (orgId) => {
  const admins = await prisma.organizationMember.findMany({
    where: { organizationId: orgId, role: 'admin', status: 'active' },
    select: { userId: true }
  });
  return admins.map(a => a.userId);
};

// Generate a UUID-like chain ID
const generateChainId = () => {
  return 'chain_' + Date.now().toString(36) + '_' + Math.random().toString(36).substring(2, 10);
};

// Optimistic-locking update: only succeeds if version matches, then increments it.
// Returns the updated transaction or throws a concurrency error.
async function updateTxnWithVersion(txnId, expectedVersion, data, prismaClient) {
  const client = prismaClient || prisma;
  const result = await client.transaction.updateMany({
    where: { id: txnId, version: expectedVersion },
    data: { ...data, version: { increment: 1 } }
  });
  if (result.count === 0) {
    const current = await prisma.transaction.findUnique({ where: { id: txnId }, select: { version: true, reconStatus: true } });
    if (!current) throw new Error('Transaction not found');
    throw new Error(`Concurrency conflict: expected version ${expectedVersion}, current version ${current.version}, status ${current.reconStatus}`);
  }
  return client.transaction.findUnique({ where: { id: txnId } });
}

// Atomic update for both linked transaction pair with version locking
async function updateLinkedPairAtomic(txn1Id, txn2Id, data, prismaClient) {
  const client = prismaClient || prisma;
  const txn1 = await client.transaction.findUnique({ where: { id: txn1Id }, select: { version: true } });
  if (!txn1) throw new Error('Transaction 1 not found');
  const txn2 = txn2Id ? await client.transaction.findUnique({ where: { id: txn2Id }, select: { version: true } }) : null;
  if (txn2Id && !txn2) throw new Error('Transaction 2 not found');

  const ops = [
    client.transaction.updateMany({
      where: { id: txn1Id, version: txn1.version },
      data: { ...data, version: { increment: 1 } }
    })
  ];
  if (txn2) {
    ops.push(
      client.transaction.updateMany({
        where: { id: txn2Id, version: txn2.version },
        data: { ...data, version: { increment: 1 } }
      })
    );
  }
  const results = await Promise.all(ops);
  for (let i = 0; i < results.length; i++) {
    if (results[i].count === 0) {
      const txnId = i === 0 ? txn1Id : txn2Id;
      const current = await prisma.transaction.findUnique({ where: { id: txnId }, select: { version: true, reconStatus: true } });
      throw new Error(`Concurrency conflict on ${txnId}: expected version ${i === 0 ? txn1.version : txn2.version}, current ${current.version}`);
    }
  }
  const [updated1, updated2] = await Promise.all([
    client.transaction.findUnique({ where: { id: txn1Id } }),
    txn2Id ? client.transaction.findUnique({ where: { id: txn2Id } }) : Promise.resolve(null)
  ]);
  return [updated1, updated2];
}

// Shared transaction enrichment helper — resolves recipientName, fundName, creatorName
async function enrichTxn(txn) {
  let recipientName = null;
  if (txn.recipientUserId) {
    const u = await prisma.user.findUnique({ where: { id: txn.recipientUserId }, select: { name: true } });
    recipientName = u?.name || null;
  }
  let fundName = null;
  if (txn.orgFundId) {
    const fundTxn = await prisma.transaction.findUnique({ where: { id: txn.orgFundId } });
    if (fundTxn?.linkedTransactionId) {
      const orgTxn = await prisma.transaction.findUnique({ where: { id: fundTxn.linkedTransactionId }, include: { book: { include: { organization: { select: { name: true } } } } } });
      fundName = orgTxn?.book?.organization?.name || null;
    }
  }
  if (!fundName && txn.linkedTransactionId) {
    const linkedTxn = await prisma.transaction.findUnique({ where: { id: txn.linkedTransactionId }, include: { book: { include: { organization: { select: { name: true } } } } } });
    fundName = linkedTxn?.book?.organization?.name || null;
  }
  let creatorName = null;
  let creatorAvatarUrl = null;
  if (txn.createdById) {
    const u = await prisma.user.findUnique({ where: { id: txn.createdById }, select: { name: true, avatarUrl: true } });
    creatorName = u?.name || null;
    creatorAvatarUrl = u?.avatarUrl || null;
  }
  return { ...txn, recipientName, fundName, creatorName, creatorAvatarUrl, chainId: txn.chainId, chainType: txn.chainType, isLiability: txn.isLiability, adjustedAmount: txn.adjustedAmount };
}

// --- AUTH ROUTES ---

// Rate-limited auth routes
app.use('/api/auth/login', authLimiter);
app.use('/api/auth/register', authLimiter);

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

    // Create user
    const user = await prisma.user.create({
      data: {
        name,
        email,
        phoneNumber,
        password: hashedPassword,
      }
    });

    // Create Personal Organization (auto-created, no invite code, no members)
    const personalOrg = await prisma.organization.create({
      data: {
        name: `${name}'s Personal`,
        isPersonal: true,
        inviteCode: null,
      }
    });

    // Add user as admin of personal org (auto-active)
    await prisma.organizationMember.create({
      data: {
        userId: user.id,
        organizationId: personalOrg.id,
        role: 'admin',
        status: 'active',
      }
    });

    // Create default book for personal org
    await prisma.book.create({
      data: {
        name: 'Personal Book',
        isDefault: true,
        balance: 0.0,
        organizationId: personalOrg.id,
      }
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
    res.status(500).json({ error: 'Server error during registration' });
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
        data: { name: `${user.name}'s Personal`, isPersonal: true, inviteCode: null }
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
    await prisma.user.update({ where: { id: req.user.id }, data: { password: hashed } });
    res.json({ message: 'Password changed successfully' });
  } catch (error) {
    console.error('Change password error:', error);
    res.status(500).json({ error: 'Server error changing password' });
  }
});

// Get Current Profile & State
app.get('/api/user/profile', authenticateToken, async (req, res) => {
  try {
    const user = await prisma.user.findUnique({
      where: { id: req.user.id },
      include: {
        memberships: {
          include: {
            organization: true,
          }
        }
      }
    });

    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    // Separate active vs pending memberships
    const activeMemberships = user.memberships.filter(m => m.status === 'active');
    const pendingMemberships = user.memberships.filter(m => m.status === 'pending');

    const orgIds = activeMemberships.map(m => m.organizationId);
    const orgs = await prisma.organization.findMany({
      where: { id: { in: orgIds } },
      include: {
        books: true,
        members: { where: { status: 'active' }, include: { user: { select: { id: true, name: true } } } },
      }
    });

    // Get pending org info separately
    const pendingOrgIds = pendingMemberships.map(m => m.organizationId);
    const pendingOrgs = pendingOrgIds.length > 0 ? await prisma.organization.findMany({
      where: { id: { in: pendingOrgIds } },
      select: { id: true, name: true }
    }) : [];

    res.json({
      user: {
        id: user.id,
        name: user.name,
        email: user.email,
        phoneNumber: user.phoneNumber,
        tokenVersion: user.tokenVersion,
        avatarUrl: user.avatarUrl,
      },
      organizations: orgs.map(o => ({
        id: o.id,
        name: o.name,
        isPersonal: o.isPersonal,
        inviteCode: o.inviteCode,
        imageUrl: o.imageUrl,
        categories: o.categories,
        role: activeMemberships.find(m => m.organizationId === o.id)?.role || 'member',
        status: 'active',
        books: o.books,
        members: o.members.map(m => ({ id: m.user.id, name: m.user.name, role: m.role, userId: m.userId })),
      })),
      pendingOrganizations: pendingOrgs.map(o => ({
        id: o.id,
        name: o.name,
        status: 'pending',
      })),
    });
  } catch (error) {
    console.error('Profile fetch error:', error);
    res.status(500).json({ error: 'Server error fetching profile' });
  }
});

// Search users by name or phone (last 10 digits)
app.get('/api/users/search', authenticateToken, async (req, res) => {
  try {
    const q = (req.query.q || '').trim();
    if (!q || q.length < 2) {
      return res.json({ users: [] });
    }

    const users = await prisma.user.findMany({
      where: {
        OR: [
          { name: { contains: q, mode: 'insensitive' } },
          { phoneNumber: { endsWith: q.slice(-10) } },
        ],
      },
      select: { id: true, name: true, phoneNumber: true, email: true },
      take: 20,
    });

    res.json({ users });
  } catch (error) {
    console.error('User search error:', error);
    res.status(500).json({ error: 'Server error searching users' });
  }
});

// Get org members across current user's organizations
app.get('/api/org/members', authenticateToken, async (req, res) => {
  try {
    const memberships = await prisma.organizationMember.findMany({
      where: { userId: req.user.id, status: 'active' },
      select: { organizationId: true },
    });

    const orgIds = memberships.map(m => m.organizationId);

    const orgMembers = await prisma.organizationMember.findMany({
      where: { organizationId: { in: orgIds }, status: 'active' },
      include: {
        user: { select: { id: true, name: true, phoneNumber: true, email: true } },
        organization: { select: { id: true, name: true } },
      },
    });

    // Group by organization
    const grouped = {};
    for (const m of orgMembers) {
      const orgId = m.organizationId;
      if (!grouped[orgId]) {
        grouped[orgId] = {
          id: orgId,
          name: m.organization.name,
          members: [],
        };
      }
      grouped[orgId].members.push({
        id: m.user.id,
        name: m.user.name,
        phoneNumber: m.user.phoneNumber,
        email: m.user.email,
        role: m.role,
      });
    }

    res.json({ organizations: Object.values(grouped) });
  } catch (error) {
    console.error('Org members fetch error:', error);
    res.status(500).json({ error: 'Server error fetching org members' });
  }
});

// Update Profile
app.post('/api/onboarding/complete', authenticateToken, async (req, res) => {
  try {
    const { name, avatarUrl } = req.body;
    if (!name) {
      return res.status(400).json({ error: 'Name is required' });
    }

    const updateData = { name };
    if (avatarUrl !== undefined) {
      updateData.avatarUrl = avatarUrl;
    }

    const updatedUser = await prisma.user.update({
      where: { id: req.user.id },
      data: updateData,
    });

    res.json({
      message: 'Profile updated successfully',
      user: {
        id: updatedUser.id,
        name: updatedUser.name,
        email: updatedUser.email,
        avatarUrl: updatedUser.avatarUrl,
      }
    });
  } catch (error) {
    console.error('Onboarding complete error:', error);
    res.status(500).json({ error: 'Server error completing profile' });
  }
});

// --- LEDGER BOOKS & TRANSACTIONS ---

// Get User Books (all books from all orgs user is active member of)
app.get('/api/books', authenticateToken, async (req, res) => {
  try {
    const user = await prisma.user.findUnique({
      where: { id: req.user.id },
      include: { memberships: true }
    });

    const activeMemberships = user.memberships.filter(m => m.status === 'active');
    const orgIds = activeMemberships.map(m => m.organizationId);
    const books = await prisma.book.findMany({
      where: { organizationId: { in: orgIds } },
      include: { organization: { select: { id: true, name: true, isPersonal: true, imageUrl: true } } }
    });

    const booksWithRole = books.map(book => {
      const membership = activeMemberships.find(m => m.organizationId === book.organizationId);
      return { ...book, role: membership?.role || 'member', permissions: membership?.permissions || [] };
    });

    res.json(booksWithRole);
  } catch (error) {
    console.error('Fetch books error:', error);
    res.status(500).json({ error: 'Server error fetching books' });
  }
});

// Create Book under an organization
app.post('/api/books', authenticateToken, async (req, res) => {
  try {
    const { name, organizationId, parentBookId } = req.body;
    if (!name || !organizationId) {
      return res.status(400).json({ error: 'Name and organizationId are required' });
    }

    // Verify user is a member of the organization
    const membership = await prisma.organizationMember.findUnique({
      where: {
        userId_organizationId: {
          userId: req.user.id,
          organizationId
        }
      }
    });
    if (!membership) {
      return res.status(403).json({ error: 'Not a member of this organization' });
    }

    // If parentBookId is provided, verify it exists in same org
    if (parentBookId) {
      const parentBook = await prisma.book.findUnique({ where: { id: parentBookId } });
      if (!parentBook || parentBook.organizationId !== organizationId) {
        return res.status(400).json({ error: 'Invalid parent book' });
      }
      if (!parentBook.isDefault) {
        return res.status(400).json({ error: 'Sub-books can only be created under the default book' });
      }
    }

    const book = await prisma.book.create({
      data: {
        name,
        balance: 0.0,
        organizationId,
        parentBookId: parentBookId || null,
      }
    });

    res.status(201).json(book);
  } catch (error) {
    console.error('Create book error:', error);
    res.status(500).json({ error: 'Server error creating book' });
  }
});

// Delete Book (default books cannot be deleted)
app.delete('/api/books/:bookId', authenticateToken, async (req, res) => {
  try {
    if (!req.params.bookId || typeof req.params.bookId !== 'string' || req.params.bookId.length < 8) {
      return res.status(400).json({ error: 'Invalid book ID' });
    }
    const book = await prisma.book.findUnique({ where: { id: req.params.bookId } });
    if (!book) return res.status(404).json({ error: 'Book not found' });

    // Verify user is a member of the org
    const membership = await prisma.organizationMember.findUnique({
      where: {
        userId_organizationId: {
          userId: req.user.id,
          organizationId: book.organizationId
        }
      }
    });
    if (!membership || !['admin', 'editor'].includes(membership.role)) {
      return res.status(403).json({ error: 'Only admins or editors can delete books' });
    }

    // Default book cannot be deleted
    if (book.isDefault) {
      return res.status(400).json({ error: 'Default book cannot be deleted' });
    }

    // Check if this is a sub-book (has parentBookId)
    if (book.parentBookId) {
      const purgeAll = req.query.purge === 'true';
      const parentBookId = book.parentBookId;
      if (purgeAll) {
        // Purge All: Delete sub-book + its mirrored transactions from parent
        const mirrors = await prisma.transaction.findMany({
          where: { sourceSubBookId: book.id, bookId: parentBookId }
        });
        const mirrorIds = mirrors.map(m => m.id);
        if (mirrorIds.length > 0) {
          // Reverse balance for each mirror in parent book
          let totalBalanceAdj = 0;
          for (const m of mirrors) {
            if (m.type === 'expense') totalBalanceAdj += m.amount;
            else if (m.type === 'income') totalBalanceAdj -= m.amount;
          }
          await prisma.$transaction([
            prisma.transaction.deleteMany({ where: { id: { in: mirrorIds } } }),
            prisma.book.update({ where: { id: parentBookId }, data: { balance: { increment: totalBalanceAdj } } }),
            prisma.book.delete({ where: { id: book.id } }),
          ]);
        } else {
          await prisma.$transaction([
            prisma.transaction.deleteMany({ where: { bookId: book.id } }),
            prisma.book.delete({ where: { id: book.id } }),
          ]);
        }
      } else {
        // Keep Data: Delete sub-book only, mirrored transactions stay in parent
        await prisma.$transaction([
          prisma.transaction.deleteMany({ where: { bookId: book.id } }),
          prisma.book.delete({ where: { id: book.id } }),
        ]);
      }
    } else {
      // Regular book (not a sub-book) — delete everything
      await prisma.$transaction([
        prisma.transaction.deleteMany({ where: { bookId: book.id } }),
        prisma.book.delete({ where: { id: book.id } }),
      ]);
    }

    broadcast({ type: "data_changed" });
    res.json({ message: 'Book deleted successfully' });
  } catch (error) {
    console.error('Delete book error:', error);
    res.status(500).json({ error: 'Server error deleting book' });
  }
});

// Create Transaction (supports org fund handshake for "Send" category)
app.post('/api/transactions', authenticateToken, async (req, res) => {
  try {
    const { bookId, amount, type, note, category, contact, recipientUserId, orgFundId, imageUrl, clientRef } = req.body;

    if (!bookId || !amount || !type) {
      return res.status(400).json({ error: 'BookId, amount, and type are required' });
    }

    const parsedAmount = parseFloat(amount);
    if (!parsedAmount || parsedAmount <= 0) {
      return res.status(400).json({ error: 'Amount must be a positive number' });
    }

    const isSend = type === 'expense' && category === 'Send';
    const isVoucher = !!orgFundId;

    const book = await prisma.book.findUnique({ where: { id: bookId }, include: { organization: { select: { isPersonal: true } } } });
    if (!book) {
      return res.status(404).json({ error: 'Ledger book not found' });
    }

    if (!(await hasBookAccess(book, req.user.id))) {
      return res.status(403).json({ error: 'Not authorized to use this book' });
    }

    // --- DISBURSEMENT FLOW (expense with category "Send" + recipientUserId) ---
    if (isSend && recipientUserId) {
      const recipientMembership = await prisma.organizationMember.findFirst({
        where: { userId: recipientUserId, organization: { isPersonal: true } },
        include: { organization: { include: { books: { where: { isDefault: true } } } } }
      });
      if (!recipientMembership || recipientMembership.organization.books.length === 0) {
        return res.status(400).json({ error: 'Recipient has no personal book' });
      }
      const recipientBook = recipientMembership.organization.books[0];

      // Determine initial state based on org approval policy
      const bypassOrgApproval = await checkApprovalBypass(book.organizationId, req.user.id);
      const initialStatus = bypassOrgApproval ? 'pending_recipient' : 'pending_org';

      // ── Chain / Split / Deficit logic when fund source is selected ──
      let chainId = null;
      let chainType = null;
      let fundTxnParent = null;
      if (orgFundId) {
        fundTxnParent = await prisma.transaction.findUnique({ where: { id: orgFundId } });
        if (fundTxnParent) {
          // Determine chainId — reuse or generate
          chainId = fundTxnParent.chainId;
          if (!chainId && fundTxnParent.linkedTransactionId) {
            const linkedFund = await prisma.transaction.findUnique({ where: { id: fundTxnParent.linkedTransactionId } });
            chainId = linkedFund?.chainId;
          }
          const { remaining } = await getChainRemainingBalance(orgFundId);
          if (parsedAmount > remaining) {
            return res.status(400).json({ error: `Insufficient fund balance: requested ${parsedAmount}, remaining ${remaining}` });
          }
          chainType = 'split';
        }
      }

      const result = await prisma.$transaction(async (prisma) => {
        const sourceTxn = await prisma.transaction.create({
          data: { bookId, amount: parsedAmount, type: 'expense', note, category: 'Send', contact, recipientUserId, createdById: req.user.id, reconStatus: initialStatus, imageUrl, chainId, chainType, orgFundId, clientRef }
        });
        const recipientTxn = await prisma.transaction.create({
          data: { bookId: recipientBook.id, amount: parsedAmount, type: 'income', note: 'Org fund advance: ' + (note || ''), category: 'Org Fund Advance', contact, recipientUserId: req.user.id, linkedTransactionId: null, createdById: req.user.id, reconStatus: initialStatus, chainId, chainType }
        });
        await prisma.book.update({ where: { id: bookId }, data: { balance: { decrement: parsedAmount } } });
        await prisma.book.update({ where: { id: recipientBook.id }, data: { balance: { increment: parsedAmount } } });
        await prisma.transaction.update({ where: { id: sourceTxn.id }, data: { linkedTransactionId: recipientTxn.id } });
        await prisma.transaction.update({ where: { id: recipientTxn.id }, data: { linkedTransactionId: sourceTxn.id } });
        return sourceTxn;
      });

      broadcast({ type: "data_changed" });
      const enriched = await enrichTxn(result);

      // ── Dynamic notification to org admins ──
      const adminIds = await getOrgAdminUserIds(book.organizationId);
      const senderName = req.user.name || 'A user';
      const recipientName = enriched.recipientName || 'another member';

      if (chainType === 'split' && fundTxnParent) {
        const { remaining } = await getChainRemainingBalance(orgFundId);
        const bnMsg = `${senderName}-কে দেওয়া ${fundTxnParent.amount} টাকা থেকে ${parsedAmount} টাকা এখন ${recipientName}-এর কাছে ট্রান্সফার করা হয়েছে। ${senderName}-এর অবশিষ্টাংশ: ${remaining} টাকা।`;
        const enMsg = `${parsedAmount} Tk from the ${fundTxnParent.amount} Tk given to ${senderName} has been transferred to ${recipientName}. ${senderName}'s remaining: ${remaining} Tk.`;
        broadcastToUsers(adminIds, { type: "chain_split", message: { bn: bnMsg, en: enMsg }, transaction: enriched });
      } else if (chainType === 'deficit') {
        const deficitAmt = parsedAmount;
        const bnMsg = `${senderName} ${enriched.fundName || 'ফান্ড'} থেকে ${recipientName}-কে ${deficitAmt} টাকা অগ্রিম (Advance) পাঠিয়েছে। ${senderName}-এর বর্তমান ফান্ড ব্যালেন্স: -${deficitAmt} টাকা।`;
        const enMsg = `${senderName} sent ${deficitAmt} Tk as an advance from ${enriched.fundName || 'the fund'} to ${recipientName}. ${senderName}'s current fund balance: -${deficitAmt} Tk.`;
        broadcastToUsers(adminIds, { type: "deficit_send", message: { bn: bnMsg, en: enMsg }, transaction: enriched });
      }

      // Notify recipient immediately if org approval was bypassed
      if (bypassOrgApproval) {
        broadcastToUser(recipientUserId, { type: "pending_send_received", transaction: enriched });
      }
      return res.status(201).json({ transaction: enriched, isHandshake: true, approvalBypassed: bypassOrgApproval });
    }

    // --- VOUCHER FLOW ---
    if (isVoucher) {
      const origDisbursement = await prisma.transaction.findUnique({ where: { id: orgFundId } });
      if (!origDisbursement) return res.status(404).json({ error: 'Original disbursement not found' });
      const origBook = await prisma.book.findUnique({ where: { id: origDisbursement.bookId } });
      if (!origBook || origBook.organizationId !== book.organizationId) {
        return res.status(400).json({ error: 'Voucher must reference a disbursement from the same organization' });
      }

      const bypass = await checkApprovalBypass(book.organizationId, req.user.id);
      const voucherStatus = bypass ? 'approved' : 'pending_org';

      const [txn, updatedBook] = await prisma.$transaction([
        prisma.transaction.create({ data: { bookId, amount: parsedAmount, type: 'expense', note, category, contact, orgFundId, createdById: req.user.id, reconStatus: voucherStatus, imageUrl, clientRef } }),
        prisma.book.update({ where: { id: bookId }, data: { balance: book.balance - parsedAmount } })
      ]);

      broadcast({ type: "data_changed" });
      const enriched = await enrichTxn(txn);
      return res.status(201).json({ transaction: enriched, book: updatedBook, isVoucher: true });
    }

    // --- NORMAL INCOME/EXPENSE ---
    const balanceOp = type === 'income' ? { increment: parsedAmount } : { decrement: parsedAmount };

    // Determine if this is a general expense needing org approval
    let initialStatus = 'approved';
    if (type === 'expense' && !book.organization.isPersonal) {
      const bypass = await checkApprovalBypass(book.organizationId, req.user.id);
      initialStatus = bypass ? 'approved' : 'pending_org';
    }

    // Mirror to parent book if this is a sub-book
    let mirrorTransaction = null;
    if (book.parentBookId) {
      const mirrorBalanceOp = type === 'income' ? { increment: parsedAmount } : { decrement: parsedAmount };
      mirrorTransaction = prisma.transaction.create({
        data: {
          bookId: book.parentBookId,
          amount: parsedAmount,
          type,
          note: note ? (note + ' [' + book.name + ']') : ('[' + book.name + ']'),
          category,
          contact,
          createdById: req.user.id,
          reconStatus: initialStatus,
          imageUrl,
          sourceSubBookId: bookId,
        }
      });
      const allOps = [
        prisma.transaction.create({
          data: {
            bookId,
            amount: parsedAmount, type, note, category, contact,
            createdById: req.user.id, reconStatus: initialStatus, imageUrl, clientRef
          }
        }),
        prisma.book.update({ where: { id: bookId }, data: { balance: balanceOp } }),
        prisma.book.update({ where: { id: book.parentBookId }, data: { balance: mirrorBalanceOp } }),
        mirrorTransaction,
      ];
      const [transaction, , , _mirror] = await prisma.$transaction(allOps);
      broadcast({ type: "data_changed" });
      const enriched = await enrichTxn(transaction);
      return res.status(201).json({ transaction: enriched, book: await prisma.book.findUnique({ where: { id: bookId } }), mirrorBook: await prisma.book.findUnique({ where: { id: book.parentBookId } }) });
    }

    const [transaction, updatedBook] = await prisma.$transaction([
      prisma.transaction.create({ data: { bookId, amount: parsedAmount, type, note, category, contact, createdById: req.user.id, reconStatus: initialStatus, imageUrl, clientRef } }),
      prisma.book.update({ where: { id: bookId }, data: { balance: balanceOp } })
    ]);

    broadcast({ type: "data_changed" });
    const enriched = await enrichTxn(transaction);
    res.status(201).json({ transaction: enriched, book: updatedBook });
  } catch (error) {
    console.error('Create transaction error:', error);
    res.status(500).json({ error: 'Server error creating transaction' });
  }
});

// --- EDIT TRANSACTION ---
app.put('/api/transactions/:id', authenticateToken, async (req, res) => {
  try {
    const { amount, type, note, category, contact, recipientUserId, imageUrl } = req.body;
    const txnId = req.params.id;

    const txn = await prisma.transaction.findUnique({ where: { id: txnId } });
    if (!txn) return res.status(404).json({ error: 'Transaction not found' });

    const book = await prisma.book.findUnique({ where: { id: txn.bookId } });
    if (!book) return res.status(404).json({ error: 'Book not found' });

    if (!(await hasAdminOrEditorAccess(book.organizationId, req.user.id))) {
      return res.status(403).json({ error: 'Only admins or editors can edit transactions' });
    }

    const changes = {};
    if (amount !== undefined) {
      const parsed = parseFloat(amount);
      if (!Number.isFinite(parsed) || parsed <= 0) return res.status(400).json({ error: 'Amount must be a valid positive number' });
      changes.amount = parsed;
    }
    if (type !== undefined) changes.type = type;
    if (note !== undefined) changes.note = note;
    if (category !== undefined) changes.category = category;
    if (contact !== undefined) changes.contact = contact;
    if (recipientUserId !== undefined) changes.recipientUserId = recipientUserId;
    if (imageUrl !== undefined) changes.imageUrl = imageUrl;

    if (Object.keys(changes).length === 0) return res.status(400).json({ error: 'No fields to update' });

    if (changes.amount !== undefined && (!changes.amount || changes.amount <= 0)) {
      return res.status(400).json({ error: 'Amount must be a positive number' });
    }

    const parsedAmount = changes.amount !== undefined ? changes.amount : txn.amount;
    const parsedType = changes.type !== undefined ? changes.type : txn.type;

    if (changes.recipientUserId !== undefined && changes.recipientUserId !== txn.recipientUserId && txn.category === 'Send') {
      return res.status(400).json({ error: 'Cannot change recipient on a Send transaction' });
    }

    const user = await prisma.user.findUnique({ where: { id: req.user.id }, select: { name: true } });

    // Personal org — edit directly, no pending/approval flow needed
    const editOrg = await prisma.organization.findUnique({ where: { id: book.organizationId }, select: { isPersonal: true } });
    const isManualIncome = txn.type === 'income' && !txn.linkedTransactionId;
    if (editOrg?.isPersonal || isManualIncome) {
      // Personal book or manual income: direct update, balance adjusted, no approval needed
      let personalBalAdj = 0;
      if (changes.amount !== undefined && changes.amount !== txn.amount) {
        if (txn.type === 'expense') personalBalAdj = txn.amount - parsedAmount;
        else if (txn.type === 'income') personalBalAdj = parsedAmount - txn.amount;
      }
      const personalUpdated = await prisma.$transaction(async (prisma) => {
        const updatedTxn = await prisma.transaction.update({
          where: { id: txnId },
          data: { ...changes, updateHistory: [...(txn.updateHistory || []), { timestamp: new Date().toISOString(), userId: req.user.id, userName: user?.name || 'Unknown', action: 'edit', changes: { old: { amount: txn.amount, type: txn.type, note: txn.note }, new: changes } }] },
        });
        if (personalBalAdj !== 0) {
          await prisma.book.update({ where: { id: book.id }, data: { balance: { increment: personalBalAdj } } });
        }
        return updatedTxn;
      });
      broadcast({ type: 'data_changed' });
      const enrichedPersonal = await enrichTxn(personalUpdated);
      return res.json({ transaction: enrichedPersonal, message: 'Transaction updated' });
    } else if (txn.reconStatus === 'approved') {
      // Reverse current balance to compute the pre-txn balance
      let preTxnBalance = book.balance;
      if (txn.type === 'expense') {
        preTxnBalance += txn.amount;
      } else if (txn.type === 'income') {
        preTxnBalance -= txn.amount;
      }

      // Store old data for potential revert
      const pendingData = {
        oldAmount: txn.amount,
        oldType: txn.type,
        oldCategory: txn.category,
        oldNote: txn.note,
        oldRecipientUserId: txn.recipientUserId,
        requestedBy: req.user.id,
      };

      // Update transaction: apply changes, set to pending
      const updated = await prisma.$transaction(async (prisma) => {
        const updatedTxn = await prisma.transaction.update({
          where: { id: txnId },
          data: {
            ...changes,
            reconStatus: 'pending',
            pendingAction: 'edit',
            pendingData,
            updateHistory: [
              ...(txn.updateHistory || []),
              {
                timestamp: new Date().toISOString(),
                userId: req.user.id,
                userName: user?.name || 'Unknown',
                action: 'edit',
                changes: { old: { amount: txn.amount, type: txn.type, category: txn.category, note: txn.note }, new: changes },
              },
            ],
          },
        });

        await prisma.book.update({
          where: { id: book.id },
          data: { balance: preTxnBalance },
        });

        // If linked transaction exists, also set it to pending
        if (txn.linkedTransactionId) {
          const linkedTxn = await prisma.transaction.findUnique({ where: { id: txn.linkedTransactionId } });
          if (linkedTxn && linkedTxn.reconStatus === 'approved') {
            const linkedBalanceOp = linkedTxn.type === 'income'
              ? { decrement: linkedTxn.amount }
              : { increment: linkedTxn.amount };
            await prisma.book.update({
              where: { id: linkedTxn.bookId },
              data: { balance: linkedBalanceOp },
            });
            const linkedBook = await prisma.book.findUnique({ where: { id: linkedTxn.bookId } });
            const linkedPre = linkedBook ? linkedBook.balance : 0;
            if (parsedType === 'expense' && parsedAmount > linkedPre) {
            }

            const linkedChanges = {};
            if (changes.amount !== undefined) linkedChanges.amount = parsedAmount;
            if (changes.note !== undefined) linkedChanges.note = note;

            await prisma.transaction.update({
              where: { id: txn.linkedTransactionId },
              data: {
                ...linkedChanges,
                reconStatus: 'pending',
                pendingAction: 'edit',
                pendingData: {
                  oldAmount: linkedTxn.amount,
                  oldType: linkedTxn.type,
                  oldCategory: linkedTxn.category,
                  oldNote: linkedTxn.note,
                  requestedBy: req.user.id,
                },
                updateHistory: [
                  ...(linkedTxn.updateHistory || []),
                  {
                    timestamp: new Date().toISOString(),
                    userId: req.user.id,
                    userName: user?.name || 'Unknown',
                    action: 'edit (linked)',
                    changes: { old: { amount: linkedTxn.amount, note: linkedTxn.note }, new: linkedChanges },
                  },
                ],
              },
            });
          }
        }

        return updatedTxn;
      });

      broadcast({ type: "data_changed" });
      const enriched = await enrichTxn(updated);
      return res.json({ transaction: enriched, message: 'Edit submitted for approval' });
    } else {
      // Not approved — update directly with no approval needed
      // Balance may need adjustment if amount changed
      let balanceAdjustment = 0;
      if (changes.amount !== undefined && changes.amount !== txn.amount) {
        if (txn.type === 'expense') {
          balanceAdjustment = txn.amount - parsedAmount;
        } else if (txn.type === 'income') {
          balanceAdjustment = parsedAmount - txn.amount;
        }
      }

      const updated = await prisma.$transaction(async (prisma) => {
        const updatedTxn = await prisma.transaction.update({
          where: { id: txnId },
          data: {
            ...changes,
            updateHistory: [
              ...(txn.updateHistory || []),
              {
                timestamp: new Date().toISOString(),
                userId: req.user.id,
                userName: user?.name || 'Unknown',
                action: 'edit',
                changes: { old: { amount: txn.amount, type: txn.type, category: txn.category, note: txn.note }, new: changes },
              },
            ],
          },
        });

        if (balanceAdjustment !== 0) {
          await prisma.book.update({
            where: { id: book.id },
            data: { balance: { increment: balanceAdjustment } },
          });
        }

        // Update linked transaction for pending Send txns too
        if (txn.linkedTransactionId) {
          const linkedTxn = await prisma.transaction.findUnique({ where: { id: txn.linkedTransactionId } });
          if (linkedTxn && linkedTxn.reconStatus === 'pending') {
            const linkedChanges = {};
            if (changes.amount !== undefined) linkedChanges.amount = parsedAmount;
            if (changes.note !== undefined) linkedChanges.note = note;
            if (Object.keys(linkedChanges).length > 0) {
              await prisma.transaction.update({
                where: { id: txn.linkedTransactionId },
                data: {
                  ...linkedChanges,
                  updateHistory: [
                    ...(linkedTxn.updateHistory || []),
                    {
                      timestamp: new Date().toISOString(),
                      userId: req.user.id,
                      userName: user?.name || 'Unknown',
                      action: 'edit (linked)',
                      changes: { old: { amount: linkedTxn.amount, note: linkedTxn.note }, new: linkedChanges },
                    },
                  ],
                },
              });
            }
          }
        }

        return updatedTxn;
      });

      broadcast({ type: "data_changed" });
      const enriched2 = await enrichTxn(updated);
      return res.json({ transaction: enriched2, message: 'Transaction updated' });
    }
  } catch (error) {
    console.error('Edit transaction error:', error);
    res.status(500).json({ error: 'Server error editing transaction' });
  }
});

// --- MODIFY PENDING TRANSACTION AMOUNT ---
// Recipient → sets counterProposedAmount (needs sender counter-approval)
// Sender/Admin → directly updates amount on both txns (no counter-approval needed)
app.post('/api/transactions/:id/modify', authenticateToken, async (req, res) => {
  try {
    const { amount: newAmount } = req.body;
    const txnId = req.params.id;

    if (!newAmount || parseFloat(newAmount) <= 0) {
      return res.status(400).json({ error: 'New amount must be a positive number' });
    }
    const parsedNew = parseFloat(newAmount);

    const txn = await prisma.transaction.findUnique({ where: { id: txnId } });
    if (!txn) return res.status(404).json({ error: 'Transaction not found' });
    if (!['pending', 'pending_org', 'pending_recipient'].includes(txn.reconStatus)) return res.status(400).json({ error: 'Only pending transactions can be modified' });

    // Determine if caller is the recipient or an admin/editor
    const txnBook = await prisma.book.findUnique({ where: { id: txn.bookId }, include: { organization: true } });
    if (!txnBook) return res.status(404).json({ error: 'Book not found' });

    // Recipient check: if txn is in user's personal book, they own it
    const memberCheck = await prisma.organizationMember.findFirst({
      where: { userId: req.user.id, organizationId: txnBook.organizationId, role: 'admin', status: 'active' }
    });
    const isPersonalBookOwner = txnBook.organization.isPersonal && !!memberCheck;
    const isRecipient = isPersonalBookOwner || txn.recipientUserId === req.user.id;
    const isEditor = await hasAdminOrEditorAccess(txnBook.organizationId, req.user.id);

    if (!isRecipient && !isEditor) {
      return res.status(403).json({ error: 'Only the recipient or an admin/editor can modify the amount' });
    }

    // Sender/Admin: directly update the amount on both linked txns
    if (isEditor && !isRecipient) {
      const updates = [];
      const clearData = { counterProposedAmount: null, counterProposedBy: null };
      updates.push(
        prisma.transaction.update({
          where: { id: txnId },
          data: { amount: parsedNew, ...clearData }
        })
      );
      if (txn.linkedTransactionId) {
        updates.push(
          prisma.transaction.update({
            where: { id: txn.linkedTransactionId },
            data: { amount: parsedNew, ...clearData }
          })
        );
      }
      await prisma.$transaction(updates);

      // Notify the recipient about the amount change
      if (txn.recipientUserId && txn.recipientUserId !== req.user.id) {
        broadcastToUser(txn.recipientUserId, { type: 'amount_modified' });
      }

      broadcast({ type: "data_changed" });
      return res.json({ message: 'Amount updated directly', amount: parsedNew });
    }

    // Recipient: set counter-proposal (needs sender counter-approval)
    await prisma.transaction.update({
      where: { id: txnId },
      data: { counterProposedAmount: parsedNew, counterProposedBy: req.user.id }
    });

    if (txn.linkedTransactionId) {
      await prisma.transaction.update({
        where: { id: txn.linkedTransactionId },
        data: { counterProposedAmount: parsedNew, counterProposedBy: req.user.id }
      });
    }

    // Notify the sender that recipient modified the amount
    if (txn.linkedTransactionId) {
      const sourceTxn = await prisma.transaction.findUnique({ where: { id: txn.linkedTransactionId }, select: { createdById: true } });
      if (sourceTxn && sourceTxn.createdById && sourceTxn.createdById !== req.user.id) {
        broadcastToUser(sourceTxn.createdById, { type: 'amount_modified' });
      }
    }

    broadcast({ type: "data_changed" });
    return res.json({ message: 'Modification proposed, waiting for sender approval', counterProposedAmount: parsedNew });
  } catch (error) {
    console.error('Modify transaction error:', error);
    res.status(500).json({ error: 'Server error modifying transaction' });
  }
});

// --- DELETE TRANSACTION ---
app.delete('/api/transactions/:id', authenticateToken, async (req, res) => {
  try {
    const txnId = req.params.id;

    const txn = await prisma.transaction.findUnique({ where: { id: txnId } });
    if (!txn) return res.status(404).json({ error: 'Transaction not found' });

    const book = await prisma.book.findUnique({ where: { id: txn.bookId } });
    if (!book) return res.status(404).json({ error: 'Book not found' });

    // Verify admin/editor access
    if (!(await hasAdminOrEditorAccess(book.organizationId, req.user.id))) {
      return res.status(403).json({ error: 'Only admins or editors can delete transactions' });
    }

    const user = await prisma.user.findUnique({ where: { id: req.user.id }, select: { name: true } });

    // C3: Personal org or manual income — hard-delete immediately, no pending flow
    const org = await prisma.organization.findUnique({ where: { id: book.organizationId }, select: { isPersonal: true } });
    const isManualIncome = txn.type === 'income' && !txn.linkedTransactionId;
    if (org?.isPersonal || isManualIncome) {
      await prisma.$transaction(async (prisma) => {
        let balanceAdjustment = 0;
        if (txn.type === 'expense') {
          balanceAdjustment = txn.amount;
        } else if (txn.type === 'income') {
          balanceAdjustment = -txn.amount;
        }
        if (balanceAdjustment !== 0) {
          await prisma.book.update({ where: { id: book.id }, data: { balance: { increment: balanceAdjustment } } });
        }
        if (txn.linkedTransactionId) {
          const linked = await prisma.transaction.findUnique({ where: { id: txn.linkedTransactionId } });
          if (linked) {
            const linkedBook = await prisma.book.findUnique({ where: { id: linked.bookId } });
            if (linkedBook) {
              let linkedAdj = 0;
              if (linked.type === 'income') linkedAdj = -linked.amount;
              else if (linked.type === 'expense') linkedAdj = linked.amount;
              if (linkedAdj !== 0) {
                await prisma.book.update({ where: { id: linked.bookId }, data: { balance: { increment: linkedAdj } } });
              }
            }
            await prisma.transaction.delete({ where: { id: linked.id } });
          }
        }
        await prisma.transaction.delete({ where: { id: txnId } });
      });
      broadcast({ type: "data_changed" });
      return res.json({ message: 'Transaction deleted' });
    }

    if (txn.reconStatus === 'approved') {
      // Reverse balance
      let reversedBalance = book.balance;
      if (txn.type === 'expense') {
        reversedBalance += txn.amount;
      } else if (txn.type === 'income') {
        reversedBalance -= txn.amount;
      }

      const pendingData = {
        oldAmount: txn.amount,
        oldType: txn.type,
        oldCategory: txn.category,
        oldNote: txn.note,
        oldRecipientUserId: txn.recipientUserId,
        oldLinkedTransactionId: txn.linkedTransactionId,
        oldOrgFundId: txn.orgFundId,
        requestedBy: req.user.id,
      };

      await prisma.$transaction(async (prisma) => {
        await prisma.transaction.update({
          where: { id: txnId },
          data: {
            reconStatus: 'pending',
            pendingAction: 'delete',
            pendingData,
            updateHistory: [
              ...(txn.updateHistory || []),
              {
                timestamp: new Date().toISOString(),
                userId: req.user.id,
                userName: user?.name || 'Unknown',
                action: 'delete_request',
                changes: { old: { amount: txn.amount, type: txn.type, category: txn.category, note: txn.note } },
              },
            ],
          },
        });

        await prisma.book.update({
          where: { id: book.id },
          data: { balance: reversedBalance },
        });

        // Also set linked transaction to pending
        if (txn.linkedTransactionId) {
          const linkedTxn = await prisma.transaction.findUnique({ where: { id: txn.linkedTransactionId } });
          if (linkedTxn && linkedTxn.reconStatus === 'approved') {
            const linkedBook = await prisma.book.findUnique({ where: { id: linkedTxn.bookId } });
            if (linkedBook) {
              let linkedReversed = linkedBook.balance;
              if (linkedTxn.type === 'income') {
                linkedReversed -= linkedTxn.amount;
              } else if (linkedTxn.type === 'expense') {
                linkedReversed += linkedTxn.amount;
              }
              await prisma.book.update({
                where: { id: linkedTxn.bookId },
                data: { balance: linkedReversed },
              });
            }

            await prisma.transaction.update({
              where: { id: txn.linkedTransactionId },
              data: {
                reconStatus: 'pending',
                pendingAction: 'delete',
                pendingData: {
                  oldAmount: linkedTxn.amount,
                  oldType: linkedTxn.type,
                  oldCategory: linkedTxn.category,
                  oldNote: linkedTxn.note,
                  requestedBy: req.user.id,
                },
                updateHistory: [
                  ...(linkedTxn.updateHistory || []),
                  {
                    timestamp: new Date().toISOString(),
                    userId: req.user.id,
                    userName: user?.name || 'Unknown',
                    action: 'delete_request (linked)',
                    changes: { old: { amount: linkedTxn.amount, type: linkedTxn.type, category: linkedTxn.category, note: linkedTxn.note } },
                  },
                ],
              },
            });
          }
        }
      });

      broadcast({ type: "data_changed" });
      return res.json({ message: 'Delete request submitted for approval' });
    } else {
      // Not approved — hard delete and reverse any balance effect
      await prisma.$transaction(async (prisma) => {
        // Reverse balance if needed
        let balanceAdjustment = 0;
        if (txn.type === 'expense') {
          balanceAdjustment = txn.amount; // add back
        } else if (txn.type === 'income') {
          balanceAdjustment = -txn.amount; // subtract
        }
        if (balanceAdjustment !== 0) {
          await prisma.book.update({
            where: { id: book.id },
            data: { balance: { increment: balanceAdjustment } },
          });
        }

        await prisma.transaction.delete({ where: { id: txnId } });

        // Also delete linked transaction if exists
        if (txn.linkedTransactionId) {
          const linkedTxn = await prisma.transaction.findUnique({ where: { id: txn.linkedTransactionId } });
          if (linkedTxn) {
            const linkedBook = await prisma.book.findUnique({ where: { id: linkedTxn.bookId } });
            if (linkedBook) {
              let linkedAdj = 0;
              if (linkedTxn.type === 'income') {
                linkedAdj = -linkedTxn.amount;
              } else if (linkedTxn.type === 'expense') {
                linkedAdj = linkedTxn.amount;
              }
              if (linkedAdj !== 0) {
                await prisma.book.update({
                  where: { id: linkedTxn.bookId },
                  data: { balance: { increment: linkedAdj } },
                });
              }
            }
            await prisma.transaction.delete({ where: { id: linkedTxn.id } });
          }
        }
      });

      broadcast({ type: "data_changed" });
      return res.json({ message: 'Transaction deleted' });
    }
  } catch (error) {
    console.error('Delete transaction error:', error);
    res.status(500).json({ error: 'Server error deleting transaction' });
  }
});

// --- ORG FUND APPROVAL / REJECTION ---
app.post('/api/transactions/:id/action', authenticateToken, async (req, res) => {
  try {
    const { action } = req.body; // "approve" | "reject" | "counter_approve" | "reject_modification"
    const txnId = req.params.id;

    if (!['approve', 'reject', 'counter_approve', 'reject_modification'].includes(action)) {
      return res.status(400).json({ error: 'Action must be "approve", "reject", "counter_approve", or "reject_modification"' });
    }

    const txn = await prisma.transaction.findUnique({ where: { id: txnId } });
    if (!txn) return res.status(404).json({ error: 'Transaction not found' });

    const txnBook = await prisma.book.findUnique({ where: { id: txn.bookId } });
    if (!txnBook) return res.status(404).json({ error: 'Book not found' });

    // Verify caller is admin/editor of the transaction's org
    // OR that the caller is the recipient of this or the linked transaction
    const isRecipient = txn.recipientUserId === req.user.id || (
      txn.linkedTransactionId && (await prisma.transaction.findUnique({ where: { id: txn.linkedTransactionId }, select: { recipientUserId: true } }))?.recipientUserId === req.user.id
    );
    if (!isRecipient && !(await hasAdminOrEditorAccess(txnBook.organizationId, req.user.id))) {
      return res.status(403).json({ error: 'Only admins, editors, or the recipient can approve/reject transactions' });
    }

    // 1. Check if this is an edit/delete request and the requester is trying to approve/reject it.
    if (txn.pendingAction && ['edit', 'delete'].includes(txn.pendingAction)) {
      const pendingDataObj = txn.pendingData ? (typeof txn.pendingData === 'string' ? JSON.parse(txn.pendingData) : txn.pendingData) : {};
      if (pendingDataObj.requestedBy === req.user.id) {
        return res.status(403).json({ error: 'You cannot approve or reject your own edit/delete request. The other party must approve it.' });
      }
    }

    // 2. Check if this is a pending_recipient creation step and the caller is NOT the recipient.
    if (action === 'approve' && txn.reconStatus === 'pending_recipient') {
      let recipientUserId = null;
      if (txn.type === 'expense' && txn.category === 'Send') {
        recipientUserId = txn.recipientUserId;
      } else if (txn.linkedTransactionId) {
        const linked = await prisma.transaction.findUnique({ where: { id: txn.linkedTransactionId } });
        if (linked && linked.type === 'expense' && linked.category === 'Send') {
          recipientUserId = linked.recipientUserId;
        }
      }
      if (!recipientUserId || req.user.id !== recipientUserId) {
        return res.status(403).json({ error: 'Only the recipient of the transfer can accept/approve it.' });
      }
    }

    // --- REJECT MODIFICATION (sender rejects recipient's proposed change) ---
    if (action === 'reject_modification') {
      const updates = [];
      updates.push(
        prisma.transaction.update({
          where: { id: txnId },
          data: { counterProposedAmount: null, counterProposedBy: null }
        })
      );
      if (txn.linkedTransactionId) {
        updates.push(
          prisma.transaction.update({
            where: { id: txn.linkedTransactionId },
            data: { counterProposedAmount: null, counterProposedBy: null }
          })
        );
      }
      await prisma.$transaction(updates);
      broadcast({ type: "data_changed" });
      return res.json({ message: 'Modification rejected, original amount preserved' });
    }

    // --- COUNTER-APPROVE (sender accepts recipient's proposed change) ---
    if (action === 'counter_approve') {
      if (txn.counterProposedAmount == null) {
        return res.status(400).json({ error: 'No modification to counter-approve' });
      }
      const finalAmount = txn.counterProposedAmount;
      const linkedId = txn.linkedTransactionId;
      if (!linkedId) {
        return res.status(400).json({ error: 'No linked transaction found' });
      }
      const linkedTxn = await prisma.transaction.findUnique({ where: { id: linkedId } });
      if (!linkedTxn) return res.status(404).json({ error: 'Linked transaction not found' });

      // Identify source (expense in org book) vs recipient (income in personal book)
      const sourceTxn = txn.type === 'expense' ? txn : linkedTxn;
      const recipientTxn = txn.type === 'income' ? txn : linkedTxn;

      // Adjust balances from old amount to new amount
      // Source (expense): balance was decremented by old amount, now should be decremented by new amount
      const sourceDiff = sourceTxn.amount - finalAmount;
      // Recipient (income): balance was incremented by old amount, now should be incremented by new amount
      const recipientDiff = finalAmount - recipientTxn.amount;

      await prisma.$transaction([
        prisma.transaction.update({
          where: { id: sourceTxn.id },
          data: { amount: finalAmount, reconStatus: 'approved', counterProposedAmount: null, counterProposedBy: null }
        }),
        prisma.transaction.update({
          where: { id: recipientTxn.id },
          data: { amount: finalAmount, reconStatus: 'approved', counterProposedAmount: null, counterProposedBy: null }
        }),
        prisma.book.update({
          where: { id: sourceTxn.bookId },
          data: { balance: { increment: sourceDiff } }
        }),
        prisma.book.update({
          where: { id: recipientTxn.bookId },
          data: { balance: { increment: recipientDiff } }
        })
      ]);
      broadcast({ type: "data_changed" });
      return res.json({ message: 'Counter-approved, amount updated and approved' });
    }

    if (action === 'approve') {
      // Handle pendingAction transactions (edit/delete requests)
      if (txn.pendingAction) {
        if (txn.pendingAction === 'edit') {
          await prisma.$transaction(async (tx) => {
            const current = await tx.transaction.findUnique({ where: { id: txnId }, select: { version: true } });
            if (!current) throw new Error('Transaction not found');
            const upd1 = await tx.transaction.updateMany({
              where: { id: txnId, version: current.version },
              data: { reconStatus: 'approved', pendingAction: null, pendingData: null, version: { increment: 1 } }
            });
            if (upd1.count === 0) throw new Error('Concurrency conflict on edit-approve');

            if (txn.linkedTransactionId) {
              const linkedCurrent = await tx.transaction.findUnique({ where: { id: txn.linkedTransactionId }, select: { version: true } });
              if (linkedCurrent) {
                const upd2 = await tx.transaction.updateMany({
                  where: { id: txn.linkedTransactionId, version: linkedCurrent.version },
                  data: { reconStatus: 'approved', pendingAction: null, pendingData: null, version: { increment: 1 } }
                });
                if (upd2.count === 0) throw new Error('Concurrency conflict on linked edit-approve');
              }
            }

            // Apply the new amount effect using increment/decrement (GAP 2.3 fix)
            const updated = await tx.transaction.findUnique({ where: { id: txnId } });
            if (updated) {
              const delta = updated.type === 'expense' ? -updated.amount : updated.amount;
              await tx.book.update({
                where: { id: txn.bookId },
                data: { balance: { increment: delta } }
              });
            }
          });
          const updated = await prisma.transaction.findUnique({ where: { id: txnId } });
          broadcast({ type: "data_changed" });
          return res.json({ transaction: updated, message: 'Edit approved' });
        } else if (txn.pendingAction === 'delete') {
          await prisma.$transaction(async (tx) => {
            if (txn.linkedTransactionId) {
              const linked = await tx.transaction.findUnique({ where: { id: txn.linkedTransactionId } });
              if (linked) {
                await tx.transaction.delete({ where: { id: linked.id } });
              }
            }
            await tx.transaction.delete({ where: { id: txnId } });
          });
          broadcast({ type: "data_changed" });
          return res.json({ message: 'Deletion approved, transaction removed' });
        }
      }

      // Counter-approve inside approve action (legacy path)
      if (txn.counterProposedAmount != null && txn.counterProposedBy !== req.user.id) {
        const finalAmount = txn.counterProposedAmount;
        const updates = [];
        if (txn.linkedTransactionId) {
          updates.push(
            prisma.transaction.update({
              where: { id: txn.linkedTransactionId },
              data: { amount: finalAmount, category: 'Send', reconStatus: 'approved', counterProposedAmount: null, counterProposedBy: null }
            })
          );
        }
        updates.push(
          prisma.transaction.update({
            where: { id: txnId },
            data: { amount: finalAmount, reconStatus: 'approved', counterProposedAmount: null, counterProposedBy: null }
          })
        );
        await prisma.$transaction(updates);
        const updated = await prisma.transaction.findUnique({ where: { id: txnId } });
        broadcast({ type: "data_changed" });
        return res.json({ transaction: updated, message: 'Counter-approved, amount updated and approved' });
      }

      // --- PENDING_ORG → advance to next stage ---
      if (txn.reconStatus === 'pending_org') {
        const isSend = txn.category === 'Send' && txn.linkedTransactionId;
        if (isSend || (txn.category === 'Send' && txn.recipientUserId)) {
          // Send: advance both linked txns to pending_recipient (orange) with version lock
          await prisma.$transaction(async (tx) => {
            const main = await tx.transaction.findUnique({ where: { id: txnId }, select: { version: true } });
            if (!main) throw new Error('Transaction not found');
            const upd1 = await tx.transaction.updateMany({
              where: { id: txnId, version: main.version },
              data: { reconStatus: 'pending_recipient', version: { increment: 1 } }
            });
            if (upd1.count === 0) throw new Error('Concurrency conflict on pending_org advance');

            if (txn.linkedTransactionId) {
              const linked = await tx.transaction.findUnique({ where: { id: txn.linkedTransactionId }, select: { version: true } });
              if (linked) {
                const upd2 = await tx.transaction.updateMany({
                  where: { id: txn.linkedTransactionId, version: linked.version },
                  data: { reconStatus: 'pending_recipient', version: { increment: 1 } }
                });
                if (upd2.count === 0) throw new Error('Concurrency conflict on linked pending_org advance');
              }
            }
          });

          // Notify recipient that org approval passed
          if (txn.recipientUserId) {
            broadcastToUser(txn.recipientUserId, { type: 'pending_send_received', transaction: txn });
          }
          broadcast({ type: "data_changed" });
          return res.json({ message: 'Org approved, waiting for recipient acceptance' });
        } else {
          // General expense/voucher: approve directly with version lock
          const updated = await updateTxnWithVersion(txnId, txn.version, { reconStatus: 'approved' });
          broadcast({ type: "data_changed" });
          return res.json({ transaction: updated, message: 'Transaction approved' });
        }
      }

      // --- PENDING_RECIPIENT → approve (green) ---
      if (txn.reconStatus === 'pending_recipient') {
        await prisma.$transaction(async (tx) => {
          const main = await tx.transaction.findUnique({ where: { id: txnId }, select: { version: true } });
          if (!main) throw new Error('Transaction not found');
          const upd1 = await tx.transaction.updateMany({
            where: { id: txnId, version: main.version },
            data: { reconStatus: 'approved', counterProposedAmount: null, counterProposedBy: null, version: { increment: 1 } }
          });
          if (upd1.count === 0) throw new Error('Concurrency conflict on pending_recipient approve');

          if (txn.linkedTransactionId) {
            const linked = await tx.transaction.findUnique({ where: { id: txn.linkedTransactionId }, select: { version: true } });
            if (linked) {
              const upd2 = await tx.transaction.updateMany({
                where: { id: txn.linkedTransactionId, version: linked.version },
                data: { reconStatus: 'approved', counterProposedAmount: null, counterProposedBy: null, version: { increment: 1 } }
              });
              if (upd2.count === 0) throw new Error('Concurrency conflict on linked pending_recipient approve');
            }
          }

          // ── Auto-adjustment: deduct existing approved deficits from new fund release ──
          if (txn.type === 'income') {
            const isPersonalOwner = await tx.organizationMember.findFirst({
              where: { userId: req.user.id, organization: { isPersonal: true, books: { some: { id: txn.bookId } } } }
            });
            if (isPersonalOwner) {
              const deficits = await tx.transaction.findMany({
                where: {
                  chainType: 'deficit',
                  createdById: req.user.id,
                  bookId: txn.bookId,
                  adjustedAmount: null,
                  isLiability: false,
                  reconStatus: 'approved'
                }
              });
              const totalDeficit = deficits.reduce((sum, d) => sum + d.amount, 0);
              if (totalDeficit > 0) {
                const adjustmentAmount = Math.min(totalDeficit, txn.amount);
                const adjChainId = generateChainId();
                await tx.transaction.create({
                  data: {
                    bookId: txn.bookId,
                    amount: adjustmentAmount,
                    type: 'expense',
                    note: `Auto-adjustment: ${adjustmentAmount} Tk deficit deducted from new fund release`,
                    category: 'Adjustment',
                    createdById: req.user.id,
                    reconStatus: 'approved',
                    chainId: adjChainId,
                    chainType: 'adjustment'
                  }
                });
                await tx.book.update({
                  where: { id: txn.bookId },
                  data: { balance: { decrement: adjustmentAmount } }
                });
                for (const d of deficits) {
                  await tx.transaction.update({
                    where: { id: d.id },
                    data: { adjustedAmount: d.amount }
                  });
                }
              }
            }
          }
        });

        // Broadcast deficit adjustment notification outside txn (non-critical)
        if (txn.type === 'income') {
          const deficits = await prisma.transaction.findMany({
            where: {
              chainType: 'deficit',
              createdById: req.user.id,
              bookId: txn.bookId,
              adjustedAmount: { not: null },
              reconStatus: 'approved'
            }
          });
          const totalAdj = deficits.reduce((s, d) => s + (d.adjustedAmount || 0), 0);
          if (totalAdj > 0) {
            const txnBook = await prisma.book.findUnique({ where: { id: txn.bookId }, select: { organizationId: true } });
            broadcastToUsers(
              (await getOrgAdminUserIds(txnBook?.organizationId || '')) || [],
              { type: "deficit_adjusted", message: { bn: `${totalAdj} টাকা ঘাটতি নতুন তহবিল থেকে কেটে নেওয়া হয়েছে`, en: `${totalAdj} Tk deficit deducted from new fund release` } }
            );
          }
        }

        broadcast({ type: "data_changed" });
        return res.json({ message: 'Transaction fully approved' });
      }

      // Legacy: handle old 'pending' reconStatus for backward compat
      if (txn.reconStatus === 'pending') {
        if (txn.orgFundId) {
          const updated = await updateTxnWithVersion(txnId, txn.version, { reconStatus: 'approved' });
          broadcast({ type: "data_changed" });
          return res.json({ transaction: updated, message: 'Voucher approved' });
        }
        if (txn.category === 'Send' && txn.recipientUserId) {
          await prisma.$transaction(async (tx) => {
            const main = await tx.transaction.findUnique({ where: { id: txnId }, select: { version: true } });
            if (!main) throw new Error('Transaction not found');
            const upd1 = await tx.transaction.updateMany({
              where: { id: txnId, version: main.version },
              data: { reconStatus: 'approved', counterProposedAmount: null, counterProposedBy: null, version: { increment: 1 } }
            });
            if (upd1.count === 0) throw new Error('Concurrency conflict on legacy pending approve');
            if (txn.linkedTransactionId) {
              const linked = await tx.transaction.findUnique({ where: { id: txn.linkedTransactionId }, select: { version: true } });
              if (linked) {
                const upd2 = await tx.transaction.updateMany({
                  where: { id: txn.linkedTransactionId, version: linked.version },
                  data: { reconStatus: 'approved', category: 'Send', counterProposedAmount: null, counterProposedBy: null, version: { increment: 1 } }
                });
                if (upd2.count === 0) throw new Error('Concurrency conflict on linked legacy pending approve');
              }
            }
          });
          const updated = await prisma.transaction.findUnique({ where: { id: txnId } });
          broadcast({ type: "data_changed" });
          return res.json({ transaction: updated, message: 'Disbursement approved' });
        }
      }

      return res.status(400).json({ error: 'Transaction not eligible for approval' });
    } else {
      // REJECT
      if (txn.pendingAction) {
        const pd = txn.pendingData;
        if (pd) {
          await prisma.$transaction(async (tx) => {
            // Restore balance using increment/decrement (GAP 2.3 fix)
            const balanceDelta = pd.oldType === 'expense' ? -pd.oldAmount : pd.oldAmount;
            await tx.book.update({
              where: { id: txn.bookId },
              data: { balance: { increment: balanceDelta } }
            });

            // Version-locked restore of main transaction
            const mainVer = await tx.transaction.findUnique({ where: { id: txnId }, select: { version: true } });
            if (!mainVer) throw new Error('Transaction not found');
            const upd = await tx.transaction.updateMany({
              where: { id: txnId, version: mainVer.version },
              data: {
                amount: pd.oldAmount, type: pd.oldType, category: pd.oldCategory,
                note: pd.oldNote, recipientUserId: pd.oldRecipientUserId || null,
                reconStatus: 'approved', pendingAction: null, pendingData: null,
                version: { increment: 1 }
              }
            });
            if (upd.count === 0) throw new Error('Concurrency conflict on pendingAction reject restore');

            if (txn.linkedTransactionId) {
              const linkedTxn = await tx.transaction.findUnique({ where: { id: txn.linkedTransactionId } });
              if (linkedTxn && linkedTxn.pendingAction) {
                const lpd = linkedTxn.pendingData;
                if (lpd) {
                  const linkedDelta = lpd.oldType === 'income' ? lpd.oldAmount : -lpd.oldAmount;
                  await tx.book.update({
                    where: { id: linkedTxn.bookId },
                    data: { balance: { increment: linkedDelta } }
                  });
                  const linkVer = linkedTxn.version;
                  const updL = await tx.transaction.updateMany({
                    where: { id: txn.linkedTransactionId, version: linkVer },
                    data: { amount: lpd.oldAmount, type: lpd.oldType, category: lpd.oldCategory, note: lpd.oldNote, reconStatus: 'approved', pendingAction: null, pendingData: null, counterProposedAmount: null, counterProposedBy: null, version: { increment: 1 } }
                  });
                  if (updL.count === 0) throw new Error('Concurrency conflict on linked pendingAction reject');
                }
              }
            }
          });
        }
        broadcast({ type: "data_changed" });
        return res.json({ message: 'Changes rejected, original values restored' });
      }

      // Reject any pending state (pending_org, pending_recipient, pending)
      if (!['pending_org', 'pending_recipient', 'pending'].includes(txn.reconStatus)) {
        return res.status(400).json({ error: 'Transaction is not in a rejectable state' });
      }

      const book = await prisma.book.findUnique({ where: { id: txn.bookId } });
      if (!book) return res.status(404).json({ error: 'Book not found' });

      // ── Deficit liability check ──
      // If rejecting a deficit chain where the recipient's income was already approved,
      // mark it as personal liability instead of rolling back the recipient's balance.
      let isLiabilityReject = false;
      if (txn.chainType === 'deficit' && txn.linkedTransactionId) {
        const linked = await prisma.transaction.findUnique({ where: { id: txn.linkedTransactionId } });
        if (linked && linked.reconStatus === 'approved') {
          isLiabilityReject = true;
        }
      }

      let reversedBalance = book.balance;
      if (txn.type === 'expense') {
        reversedBalance += txn.amount;
      } else if (txn.type === 'income') {
        reversedBalance -= txn.amount;
      }

      // ── Atomic reject with linked transaction rollback ──
      await prisma.$transaction(async (tx) => {
        // Version-locked reject of main transaction
        const mainCurrent = await tx.transaction.findUnique({ where: { id: txnId }, select: { version: true } });
        if (!mainCurrent) throw new Error('Transaction not found');
        const updMain = await tx.transaction.updateMany({
          where: { id: txnId, version: mainCurrent.version },
          data: { reconStatus: 'rejected', pendingAction: null, pendingData: null, counterProposedAmount: null, counterProposedBy: null, isLiability: isLiabilityReject || undefined, version: { increment: 1 } }
        });
        if (updMain.count === 0) throw new Error('Concurrency conflict on reject');

        // Use increment/decrement for balance (GAP 2.3 fix)
        const balanceAdjustment = txn.type === 'expense' ? txn.amount : -txn.amount;
        await tx.book.update({
          where: { id: txn.bookId },
          data: { balance: { increment: balanceAdjustment } }
        });

        // Handle linked transaction
        if (txn.linkedTransactionId) {
          const linked = await tx.transaction.findUnique({ where: { id: txn.linkedTransactionId } });
          if (linked) {
            const linkedVersion = linked.version;
            if (isLiabilityReject) {
              // Recipient already accepted → mark linked as liability, don't reverse its balance
              const updLink = await tx.transaction.updateMany({
                where: { id: txn.linkedTransactionId, version: linkedVersion },
                data: { reconStatus: 'rejected', isLiability: true, pendingAction: null, pendingData: null, counterProposedAmount: null, counterProposedBy: null, version: { increment: 1 } }
              });
              if (updLink.count === 0) throw new Error('Concurrency conflict on linked liability reject');
            } else if (['pending_org', 'pending_recipient', 'pending'].includes(linked.reconStatus)) {
              // Normal rollback: reject linked + reverse its balance atomically
              const updLink = await tx.transaction.updateMany({
                where: { id: txn.linkedTransactionId, version: linkedVersion },
                data: { reconStatus: 'rejected', pendingAction: null, pendingData: null, counterProposedAmount: null, counterProposedBy: null, version: { increment: 1 } }
              });
              if (updLink.count === 0) throw new Error('Concurrency conflict on linked reject');
              const linkedBalanceAdj = linked.type === 'income' ? -linked.amount : linked.amount;
              await tx.book.update({
                where: { id: linked.bookId },
                data: { balance: { increment: linkedBalanceAdj } }
              });
            }
          }
        }
      });

      // Broadcast liability notification if applicable
      if (isLiabilityReject) {
        const txnBookForNotify = await prisma.book.findUnique({ where: { id: txn.bookId }, select: { organizationId: true } });
        broadcastToUsers(
          (await getOrgAdminUserIds(txnBookForNotify?.organizationId || '')) || [],
          { type: "deficit_liability", message: { bn: `${txn.amount} টাকা ঘাটতি ব্যক্তিগত দায় হিসেবে লক করা হয়েছে`, en: `${txn.amount} Tk deficit locked as personal liability` } }
        );
      }

      const updated = await prisma.transaction.findUnique({ where: { id: txnId } });
      broadcast({ type: "data_changed" });
      return res.json({ transaction: updated, message: 'Transaction rejected and reversed' });
    }
  } catch (error) {
    console.error('Transaction action error:', error);
    res.status(500).json({ error: 'Server error processing action' });
  }
});

// ── RETRY a rejected transaction: create a fresh submission from old data ──
app.post('/api/transactions/:id/retry', authenticateToken, async (req, res) => {
  try {
    const txnId = req.params.id;
    const txn = await prisma.transaction.findUnique({ where: { id: txnId } });
    if (!txn) return res.status(404).json({ error: 'Transaction not found' });
    if (txn.reconStatus !== 'rejected') {
      return res.status(400).json({ error: 'Only rejected transactions can be retried' });
    }

    const book = await prisma.book.findUnique({ where: { id: txn.bookId }, include: { organization: true } });
    if (!book) return res.status(404).json({ error: 'Book not found' });

    // Determine the correct initial reconStatus based on current org policy
    const bypassOrgApproval = await checkApprovalBypass(book.organizationId, req.user.id);
    const isSend = txn.category === 'Send';
    const newStatus = isSend
      ? (bypassOrgApproval ? 'pending_recipient' : 'pending_org')
      : (bypassOrgApproval ? 'approved' : 'pending_org');

    const updated = await prisma.$transaction(async (tx) => {
      // Version-locked retry: set retried status + increment version
      const main = await tx.transaction.findUnique({ where: { id: txnId }, select: { version: true } });
      if (!main) throw new Error('Transaction not found');
      const upd = await tx.transaction.updateMany({
        where: { id: txnId, version: main.version },
        data: {
          reconStatus: newStatus,
          pendingAction: null,
          pendingData: null,
          counterProposedAmount: null,
          counterProposedBy: null,
          version: { increment: 1 }
        }
      });
      if (upd.count === 0) throw new Error('Concurrency conflict on retry');

      // If linked transaction exists, also reset it to the same status
      if (txn.linkedTransactionId) {
        const linked = await tx.transaction.findUnique({ where: { id: txn.linkedTransactionId }, select: { version: true } });
        if (linked) {
          const updL = await tx.transaction.updateMany({
            where: { id: txn.linkedTransactionId, version: linked.version },
            data: {
              reconStatus: newStatus,
              pendingAction: null,
              pendingData: null,
              counterProposedAmount: null,
              counterProposedBy: null,
              isLiability: false,
              version: { increment: 1 }
            }
          });
          if (updL.count === 0) throw new Error('Concurrency conflict on linked retry');
        }
      }

      // If bypass approval, re-apply balance (reject reversed it, approve needs it back)
      if (!isSend && bypassOrgApproval) {
        const balanceDelta = txn.type === 'expense' ? -txn.amount : txn.amount;
        await tx.book.update({
          where: { id: txn.bookId },
          data: { balance: { increment: balanceDelta } }
        });
      }

      return tx.transaction.findUnique({ where: { id: txnId } });
    });

    broadcast({ type: "data_changed" });
    const enriched = await (async (txn) => {
      let recipientName = null;
      if (txn.recipientUserId) {
        const u = await prisma.user.findUnique({ where: { id: txn.recipientUserId }, select: { name: true } });
        recipientName = u?.name || null;
      }
      return { ...txn, recipientName };
    })(updated);

    return res.json({ transaction: enriched, message: 'Transaction retried, sent for approval again' });
  } catch (error) {
    console.error('Retry transaction error:', error);
    res.status(500).json({ error: 'Server error retrying transaction' });
  }
});

// ── PERMANENT DELETE a transaction (hard delete from DB) ──
app.delete('/api/transactions/:id/permanent', authenticateToken, async (req, res) => {
  try {
    const txnId = req.params.id;
    const txn = await prisma.transaction.findUnique({ where: { id: txnId } });
    if (!txn) return res.status(404).json({ error: 'Transaction not found' });

    const book = await prisma.book.findUnique({ where: { id: txn.bookId } });
    if (!book) return res.status(404).json({ error: 'Book not found' });

    if (!(await hasAdminOrEditorAccess(book.organizationId, req.user.id))) {
      return res.status(403).json({ error: 'Only admins or editors can permanently delete transactions' });
    }

    await prisma.$transaction(async (tx) => {
      // Reverse any lingering balance effect
      const balanceAdj = txn.type === 'expense' ? txn.amount : -txn.amount;
      await tx.book.update({
        where: { id: txn.bookId },
        data: { balance: { increment: balanceAdj } }
      });

      // Delete linked transaction first if exists
      if (txn.linkedTransactionId) {
        const linked = await tx.transaction.findUnique({ where: { id: txn.linkedTransactionId } });
        if (linked) {
          const linkedBalanceAdj = linked.type === 'income' ? -linked.amount : linked.amount;
          await tx.book.update({
            where: { id: linked.bookId },
            data: { balance: { increment: linkedBalanceAdj } }
          });
          await tx.transaction.delete({ where: { id: txn.linkedTransactionId } });
        }
      }

      await tx.transaction.delete({ where: { id: txnId } });
    });

    broadcast({ type: "data_changed" });
    return res.json({ message: 'Transaction permanently deleted' });
  } catch (error) {
    console.error('Permanent delete error:', error);
    res.status(500).json({ error: 'Server error permanently deleting transaction' });
  }
});

// Get Transactions by Book (includes recipient user name)
app.get('/api/transactions/:bookId', authenticateToken, async (req, res) => {
  try {
    const { bookId } = req.params;
    const book = await prisma.book.findUnique({ where: { id: bookId } });
    if (!book) return res.status(404).json({ error: 'Book not found' });
    if (!(await hasBookAccess(book, req.user.id))) {
      return res.status(403).json({ error: 'Not authorized to view this book' });
    }

    const transactions = await prisma.transaction.findMany({
      where: { bookId },
      orderBy: { createdAt: 'desc' }
    });

    // Enrich with recipient names and fund info
    const enriched = await Promise.all(transactions.map(async (txn) => {
      let recipientName = null;
      if (txn.recipientUserId) {
        const user = await prisma.user.findUnique({ where: { id: txn.recipientUserId }, select: { name: true } });
        recipientName = user?.name || null;
      }
      // Identify the source fund name:
      // 1. If orgFundId exists (personal book Send referencing a fund income)
      // 2. If linkedTransactionId exists (direct org Send or linked txn)
      let fundName = null;
      if (txn.orgFundId) {
        const fundTxn = await prisma.transaction.findUnique({
          where: { id: txn.orgFundId },
        });
        if (fundTxn?.linkedTransactionId) {
          const orgTxn = await prisma.transaction.findUnique({
            where: { id: fundTxn.linkedTransactionId },
            include: { book: { include: { organization: { select: { name: true } } } } },
          });
          fundName = orgTxn?.book?.organization?.name || null;
        }
      }
      if (!fundName && txn.linkedTransactionId) {
        const linkedTxn = await prisma.transaction.findUnique({
          where: { id: txn.linkedTransactionId },
          include: { book: { include: { organization: { select: { name: true } } } } },
        });
        fundName = linkedTxn?.book?.organization?.name || null;
      }
      let creatorName = null;
      let creatorAvatarUrl = null;
      if (txn.createdById) {
        const u = await prisma.user.findUnique({ where: { id: txn.createdById }, select: { name: true, avatarUrl: true } });
        creatorName = u?.name || null;
        creatorAvatarUrl = u?.avatarUrl || null;
      }
      return { ...txn, recipientName, fundName, creatorName, creatorAvatarUrl, chainId: txn.chainId, chainType: txn.chainType, isLiability: txn.isLiability, adjustedAmount: txn.adjustedAmount };
    }));

    res.json(enriched);
  } catch (error) {
    console.error('Fetch transactions error:', error);
    res.status(500).json({ error: 'Server error fetching transactions' });
  }
});

// Get pending approvals/notifications across all user's orgs
app.get('/api/approvals/pending', authenticateToken, async (req, res) => {
  try {
    const user = await prisma.user.findUnique({
      where: { id: req.user.id },
      include: { memberships: { include: { organization: { include: { books: true } } } } }
    });

    const result = [];

    // --- 1. Pending Transaction Approvals ---
    const adminOrgIds = user.memberships
      .filter(m => m.status === 'active' && (m.role === 'admin' || (m.permissions || []).includes('edit_all')))
      .map(m => m.organizationId);
    const adminBookIds = user.memberships
      .filter(m => adminOrgIds.includes(m.organizationId))
      .flatMap(m => m.organization.books.map(b => b.id));

    if (adminBookIds.length > 0) {
      const pendingTxns = await prisma.transaction.findMany({
        where: {
          bookId: { in: adminBookIds },
          reconStatus: { in: ['pending_org', 'pending_recipient', 'pending'] },
          OR: [
            { category: 'Send' },
            { orgFundId: { not: null } },
            { pendingAction: { not: null } }
          ]
        },
        orderBy: { createdAt: 'desc' }
      });

      for (const txn of pendingTxns) {
        const book = await prisma.book.findUnique({ where: { id: txn.bookId }, include: { organization: true } });
        let recipientName = null;
        if (txn.recipientUserId) {
          const u = await prisma.user.findUnique({ where: { id: txn.recipientUserId }, select: { name: true } });
          recipientName = u?.name || null;
        }
        if (txn.orgFundId) {
          const orig = await prisma.transaction.findUnique({ where: { id: txn.orgFundId } });
          if (orig?.recipientUserId) {
            const u = await prisma.user.findUnique({ where: { id: orig.recipientUserId }, select: { name: true } });
            recipientName = u?.name || null;
          }
        }
        const actionLabel = txn.pendingAction === 'delete'
          ? 'Delete Request'
          : txn.pendingAction === 'edit'
            ? 'Edit Approval'
            : (txn.category === 'Send' ? 'Disbursement Approval' : 'Voucher Approval');

        let senderName = null;
        const sender = await prisma.user.findUnique({ where: { id: txn.createdById }, select: { name: true } });
        senderName = sender?.name || null;

        result.push({
          type: txn.category === 'Send' ? 'disbursement_approval' : 'voucher_approval',
          id: txn.id,
          refId: txn.id,
          title: actionLabel,
          message: txn.note || '',
          amount: txn.amount,
          category: txn.category,
          recipientName,
          bookName: book?.name || 'Unknown',
          orgName: book?.organization?.name || 'Unknown',
          createdAt: txn.createdAt,
          pendingAction: txn.pendingAction,
          reconStatus: txn.reconStatus,
          counterProposedAmount: txn.counterProposedAmount,
          counterProposedBy: txn.counterProposedBy,
          senderName,
          role: 'admin', // sender/admin view
          chainId: txn.chainId,
          chainType: txn.chainType,
          isLiability: txn.isLiability,
          adjustedAmount: txn.adjustedAmount,
        });
      }
    }

    // --- 1b. Pending Incoming Sends (user is the recipient) ---
    // Find pending income txns in user's personal books where the linked source txn's recipientUserId matches
    const personalBookIds = user.memberships
      .filter(m => m.status === 'active' && m.organization.isPersonal)
      .flatMap(m => m.organization.books.map(b => b.id));
      const incomingPendingTxns = await prisma.transaction.findMany({
        where: {
          bookId: { in: personalBookIds },
          reconStatus: { in: ['pending_recipient', 'pending'] },
          type: 'income',
          OR: [
            { category: 'Org Fund Advance' },
            { category: 'Send' }
          ]
        },
        orderBy: { createdAt: 'desc' }
      });

    for (const txn of incomingPendingTxns) {
      const book = await prisma.book.findUnique({ where: { id: txn.bookId } });
      let senderName = null;
      let orgName = null;

      // Get sender and org info from the linked source transaction
      if (txn.linkedTransactionId) {
        const sourceTxn = await prisma.transaction.findUnique({
          where: { id: txn.linkedTransactionId },
          include: { book: { include: { organization: { select: { name: true } } } } }
        });
        if (sourceTxn) {
          const u = await prisma.user.findUnique({ where: { id: sourceTxn.createdById }, select: { name: true } });
          senderName = u?.name || null;
          orgName = sourceTxn.book?.organization?.name || null;
        }
      }

      result.push({
        type: 'incoming_send',
        id: txn.id,
        refId: txn.id,
        title: 'Incoming Fund Send',
        message: txn.note || '',
        amount: txn.amount,
        category: txn.category,
        bookName: book?.name || 'Unknown',
        orgName: orgName || 'Unknown',
        senderName,
        createdAt: txn.createdAt,
        reconStatus: txn.reconStatus,
        counterProposedAmount: txn.counterProposedAmount,
        counterProposedBy: txn.counterProposedBy,
        role: 'recipient', // recipient view
        chainId: txn.chainId,
        chainType: txn.chainType,
        isLiability: txn.isLiability,
        adjustedAmount: txn.adjustedAmount,
      });
    }

    // --- 2. Pending Membership Requests (for users with manage_members permission) ---
    for (const membership of user.memberships) {
      if (membership.status === 'active' && (membership.role === 'admin' || (membership.permissions || []).includes('manage_members'))) {
        const pendingMembers = await prisma.organizationMember.findMany({
          where: { organizationId: membership.organizationId, status: 'pending' },
          include: { user: true, organization: true }
        });
        for (const pm of pendingMembers) {
          result.push({
            type: 'membership_request',
            id: pm.id,
            refId: pm.id,
            title: 'Membership Request',
            message: `${pm.user.name} wants to join ${pm.organization.name}`,
            userName: pm.user.name,
            userId: pm.userId,
            orgName: pm.organization.name,
            orgId: pm.organizationId,
            createdAt: pm.createdAt,
          });
        }
      }
    }

    // Sort by newest first
    result.sort((a, b) => new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime());

    res.json(result);
  } catch (error) {
    console.error('Fetch pending approvals error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// --- ORGANIZATIONS & INVITES ---

// Create Organization
app.post('/api/org/create', authenticateToken, async (req, res) => {
  try {
    const { name } = req.body;
    if (!name) {
      return res.status(400).json({ error: 'Organization name is required' });
    }

    const inviteCode = 'HP-' + Math.random().toString(36).substring(2, 8).toUpperCase();

    const organization = await prisma.organization.create({
      data: {
        name,
        inviteCode,
      }
    });

    // Add creator as Admin (automatically active)
    await prisma.organizationMember.create({
      data: {
        userId: req.user.id,
        organizationId: organization.id,
        role: 'admin',
        status: 'active'
      }
    });

    // Create a default ledger book for organization
    const orgBook = await prisma.book.create({
      data: {
        name: `${name} Cash Book`,
        isDefault: true,
        organizationId: organization.id,
        balance: 0.0
      }
    });

    res.status(201).json({ organization, orgBook });
  } catch (error) {
    console.error('Create org error:', error);
    res.status(500).json({ error: 'Server error creating organization' });
  }
});

// Get organization approval policy
app.get('/api/organizations/:orgId/approval-policy', authenticateToken, async (req, res) => {
  try {
    const { orgId } = req.params;
    const org = await prisma.organization.findUnique({
      where: { id: orgId },
      select: { approvalPolicy: true, whitelistedUserIds: true, isPersonal: true }
    });
    if (!org) return res.status(404).json({ error: 'Organization not found' });
    if (org.isPersonal) return res.status(400).json({ error: 'Personal organizations do not have approval policies' });

    // Verify caller is admin
    if (!(await hasAdminOrEditorAccess(orgId, req.user.id))) {
      return res.status(403).json({ error: 'Only admins can view approval policy' });
    }

    res.json({ approvalPolicy: org.approvalPolicy, whitelistedUserIds: org.whitelistedUserIds });
  } catch (error) {
    console.error('Get approval policy error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Update organization approval policy
app.put('/api/organizations/:orgId/approval-policy', authenticateToken, async (req, res) => {
  try {
    const { orgId } = req.params;
    const { approvalPolicy, whitelistedUserIds } = req.body;

    if (!['GLOBALLY_ON', 'GLOBALLY_OFF', 'CONDITIONAL_ON'].includes(approvalPolicy)) {
      return res.status(400).json({ error: 'approvalPolicy must be GLOBALLY_ON, GLOBALLY_OFF, or CONDITIONAL_ON' });
    }

    if (approvalPolicy === 'CONDITIONAL_ON' && (!Array.isArray(whitelistedUserIds) || whitelistedUserIds.length === 0)) {
      return res.status(400).json({ error: 'CONDITIONAL_ON requires at least one whitelisted user' });
    }

    const org = await prisma.organization.findUnique({
      where: { id: orgId },
      select: { isPersonal: true }
    });
    if (!org) return res.status(404).json({ error: 'Organization not found' });
    if (org.isPersonal) return res.status(400).json({ error: 'Personal organizations do not have approval policies' });

    if (!(await hasAdminOrEditorAccess(orgId, req.user.id))) {
      return res.status(403).json({ error: 'Only admins can update approval policy' });
    }

    const updated = await prisma.organization.update({
      where: { id: orgId },
      data: {
        approvalPolicy,
        whitelistedUserIds: approvalPolicy === 'CONDITIONAL_ON' ? (whitelistedUserIds || []) : []
      }
    });

    res.json({ approvalPolicy: updated.approvalPolicy, whitelistedUserIds: updated.whitelistedUserIds });
  } catch (error) {
    console.error('Update approval policy error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Join Organization via Code
app.post('/api/org/join', authenticateToken, async (req, res) => {
  try {
    const { inviteCode } = req.body;
    if (!inviteCode) {
      return res.status(400).json({ error: 'Invite code is required' });
    }

    const organization = await prisma.organization.findUnique({
      where: { inviteCode: inviteCode.trim().toUpperCase() }
    });

    if (!organization) {
      return res.status(404).json({ error: 'Organization not found' });
    }

    // Cannot join personal orgs
    if (organization.isPersonal) {
      return res.status(400).json({ error: 'Cannot join a personal organization' });
    }

    // Check if already a member
    const existingMembership = await prisma.organizationMember.findUnique({
      where: {
        userId_organizationId: {
          userId: req.user.id,
          organizationId: organization.id
        }
      }
    });

    if (existingMembership) {
      if (existingMembership.status === 'pending') {
        return res.status(202).json({ message: 'Your join request is pending admin approval' });
      }
      return res.status(400).json({ error: 'You are already a member of this organization' });
    }

    // Create Membership with pending status (admin must approve)
    const membership = await prisma.organizationMember.create({
      data: {
        userId: req.user.id,
        organizationId: organization.id,
        role: 'member',
        status: 'pending'
      }
    });

    res.json({ message: 'Join request submitted. Waiting for admin approval.', membership: { ...membership, organization } });
  } catch (error) {
    console.error('Join org error:', error);
    res.status(500).json({ error: 'Server error joining organization' });
  }
});

// Get Organization Details (invite code, member count, etc.)
app.get('/api/org/:orgId', authenticateToken, async (req, res) => {
  try {
    const org = await prisma.organization.findUnique({
      where: { id: req.params.orgId },
      include: {
        members: { include: { user: { select: { id: true, name: true, email: true, phoneNumber: true } } } },
        books: { select: { id: true, name: true, balance: true } },
      }
    });
    if (!org) return res.status(404).json({ error: 'Organization not found' });

    // Check caller is a member
    const membership = org.members.find(m => m.userId === req.user.id);
    if (!membership) return res.status(403).json({ error: 'Not a member' });

    res.json({
      organization: {
        id: org.id,
        name: org.name,
        inviteCode: org.inviteCode,
        imageUrl: org.imageUrl,
        categories: org.categories,
        approvalPolicy: org.approvalPolicy,
        whitelistedUserIds: org.whitelistedUserIds,
        createdAt: org.createdAt,
      },
      members: org.members.map(m => ({
        id: m.id,
        userId: m.userId,
        name: m.user.name,
        email: m.user.email,
        phone: m.user.phoneNumber,
        role: m.role,
        permissions: m.permissions,
        joinedAt: m.createdAt,
      })),
      books: org.books,
      callerRole: membership.role,
      callerPermissions: membership.permissions,
    });
  } catch (error) {
    console.error('Get org error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Add Organization Category (admin or editor only)
app.post('/api/org/:orgId/categories', authenticateToken, async (req, res) => {
  try {
    const { category } = req.body;
    if (!category || !category.trim()) {
      return res.status(400).json({ error: 'Category name is required' });
    }

    const trimmedCategory = category.trim();

    // Check permission for managing categories
    const membership = await prisma.organizationMember.findUnique({
      where: { userId_organizationId: { userId: req.user.id, organizationId: req.params.orgId } }
    });
    if (!membership || membership.status !== 'active' || (membership.role !== 'admin' && !(membership.permissions || []).includes('manage_categories') && !(membership.permissions || []).includes('manage_settings'))) {
      return res.status(403).json({ error: 'Only admins or users with manage_settings permission can manage categories' });
    }

    const org = await prisma.organization.findUnique({
      where: { id: req.params.orgId }
    });
    if (!org) return res.status(404).json({ error: 'Organization not found' });

    if (org.categories.includes(trimmedCategory)) {
      return res.status(400).json({ error: 'Category already exists' });
    }

    const updatedCategories = [...org.categories, trimmedCategory];

    const updatedOrg = await prisma.organization.update({
      where: { id: req.params.orgId },
      data: { categories: updatedCategories }
    });

    broadcast({ type: "data_changed" });
    res.json({ message: 'Category added', categories: updatedOrg.categories });
  } catch (error) {
    console.error('Add category error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Delete Organization Category (admin or editor only)
app.delete('/api/org/:orgId/categories', authenticateToken, async (req, res) => {
  try {
    const { category } = req.body;
    if (!category) return res.status(400).json({ error: 'Category name is required' });

    // Check permission for managing categories
    const membership = await prisma.organizationMember.findUnique({
      where: { userId_organizationId: { userId: req.user.id, organizationId: req.params.orgId } }
    });
    if (!membership || membership.status !== 'active' || (membership.role !== 'admin' && !(membership.permissions || []).includes('manage_categories') && !(membership.permissions || []).includes('manage_settings'))) {
      return res.status(403).json({ error: 'Only admins or users with manage_settings permission can manage categories' });
    }

    const org = await prisma.organization.findUnique({
      where: { id: req.params.orgId }
    });
    if (!org) return res.status(404).json({ error: 'Organization not found' });

    const updatedCategories = org.categories.filter(c => c !== category.trim());

    const updatedOrg = await prisma.organization.update({
      where: { id: req.params.orgId },
      data: {
        categories: updatedCategories
      }
    });

    broadcast({ type: "data_changed" });
    res.json({ message: 'Category removed successfully', categories: updatedOrg.categories });
  } catch (error) {
    console.error('Remove category error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Update Member Role (admin only)
app.put('/api/org/:orgId/members/:memberId/role', authenticateToken, async (req, res) => {
  try {
    const { role } = req.body;
    if (!['admin', 'editor', 'member'].includes(role)) {
      return res.status(400).json({ error: 'Invalid role. Use admin, editor, or member.' });
    }

    // Check caller is admin
    const callerMembership = await prisma.organizationMember.findUnique({
      where: { userId_organizationId: { userId: req.user.id, organizationId: req.params.orgId } }
    });
    if (!callerMembership || callerMembership.role !== 'admin') {
      return res.status(403).json({ error: 'Only admins can change roles' });
    }

    const updated = await prisma.organizationMember.update({
      where: { id: req.params.memberId },
      data: { role },
      include: { user: { select: { name: true } } },
    });

    res.json({ message: `Role updated to ${role}`, member: updated });
  } catch (error) {
    console.error('Update role error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Update Member Permissions (admin only)
app.patch('/api/org/:orgId/members/:memberId/permissions', authenticateToken, async (req, res) => {
  try {
    const { permissions } = req.body;
    if (!Array.isArray(permissions)) {
      return res.status(400).json({ error: 'Permissions must be an array' });
    }

    const validPermissions = ['view_books', 'add_expense', 'add_income', 'edit_all', 'manage_categories', 'manage_members', 'manage_settings'];
    for (const p of permissions) {
      if (!validPermissions.includes(p)) {
        return res.status(400).json({ error: `Invalid permission: ${p}` });
      }
    }

    const callerMembership = await prisma.organizationMember.findUnique({
      where: { userId_organizationId: { userId: req.user.id, organizationId: req.params.orgId } }
    });
    if (!callerMembership || callerMembership.role !== 'admin') {
      return res.status(403).json({ error: 'Only admins can change permissions' });
    }

    const target = await prisma.organizationMember.findUnique({ where: { id: req.params.memberId } });
    if (!target) return res.status(404).json({ error: 'Member not found' });
    if (target.role === 'admin') {
      return res.status(400).json({ error: 'Cannot change permissions of an admin' });
    }

    const updated = await prisma.organizationMember.update({
      where: { id: req.params.memberId },
      data: { permissions },
    });

    res.json({ message: 'Permissions updated', member: updated });
  } catch (error) {
    console.error('Update permissions error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Approve or Reject a pending membership (admin only)
app.post('/api/org/:orgId/members/:memberId/action', authenticateToken, async (req, res) => {
  try {
    const { action } = req.body; // 'approve' | 'reject'
    if (!['approve', 'reject'].includes(action)) {
      return res.status(400).json({ error: 'Action must be "approve" or "reject"' });
    }

    // Check caller has manage_members permission
    const callerMembership = await prisma.organizationMember.findUnique({
      where: { userId_organizationId: { userId: req.user.id, organizationId: req.params.orgId } }
    });
    if (!callerMembership || callerMembership.status !== 'active' || (callerMembership.role !== 'admin' && !(callerMembership.permissions || []).includes('manage_members'))) {
      return res.status(403).json({ error: 'Only admins or users with manage_members permission can approve/reject membership' });
    }

    const targetMembership = await prisma.organizationMember.findUnique({
      where: { id: req.params.memberId },
      include: { user: true, organization: true }
    });
    if (!targetMembership) return res.status(404).json({ error: 'Membership not found' });
    if (targetMembership.status !== 'pending') {
      return res.status(400).json({ error: 'Membership is not in pending status' });
    }

    if (action === 'approve') {
      await prisma.organizationMember.update({
        where: { id: targetMembership.id },
        data: { status: 'active' }
      });
      broadcast({ type: "data_changed" });
      return res.json({ message: 'Membership approved', member: targetMembership });
    } else {
      // Reject: delete the membership
      await prisma.organizationMember.delete({ where: { id: targetMembership.id } });
      broadcast({ type: "data_changed" });
      return res.json({ message: 'Membership rejected and removed' });
    }
  } catch (error) {
    console.error('Membership action error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Remove Member (admin only)
app.delete('/api/org/:orgId/members/:memberId', authenticateToken, async (req, res) => {
  try {
    const callerMembership = await prisma.organizationMember.findUnique({
      where: { userId_organizationId: { userId: req.user.id, organizationId: req.params.orgId } }
    });
    if (!callerMembership || callerMembership.status !== 'active' || (callerMembership.role !== 'admin' && !(callerMembership.permissions || []).includes('manage_members'))) {
      return res.status(403).json({ error: 'Only admins or users with manage_members permission can remove members' });
    }

    // Prevent removing self
    const target = await prisma.organizationMember.findUnique({ where: { id: req.params.memberId } });
    if (target && target.userId === req.user.id) {
      return res.status(400).json({ error: 'Cannot remove yourself' });
    }

    await prisma.organizationMember.delete({ where: { id: req.params.memberId } });
    res.json({ message: 'Member removed' });
  } catch (error) {
    console.error('Remove member error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Update Organization (admin only)
app.put('/api/org/:orgId', authenticateToken, async (req, res) => {
  try {
    const { name, imageUrl } = req.body;
    const orgId = req.params.orgId;

    const org = await prisma.organization.findUnique({ where: { id: orgId } });
    if (!org) return res.status(404).json({ error: 'Organization not found' });

    // Verify user is an admin or has manage_settings permission
    const membership = await prisma.organizationMember.findUnique({
      where: {
        userId_organizationId: {
          userId: req.user.id,
          organizationId: orgId
        }
      }
    });
    if (!membership || (membership.role !== 'admin' && !(membership.permissions || []).includes('manage_settings'))) {
      return res.status(403).json({ error: 'Only admins or users with manage_settings permission can update organization settings' });
    }

    const updateData = {};
    if (name) updateData.name = name;
    if (imageUrl !== undefined) updateData.imageUrl = imageUrl;

    if (Object.keys(updateData).length === 0) {
      return res.status(400).json({ error: 'No fields to update' });
    }

    const updatedOrg = await prisma.organization.update({
      where: { id: orgId },
      data: updateData,
    });

    broadcast({ type: "data_changed" });
    res.json({ message: 'Organization updated successfully', organization: updatedOrg });
  } catch (error) {
    console.error('Update organization error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Delete Organization (admin only, not personal orgs)
app.delete('/api/org/:orgId', authenticateToken, async (req, res) => {
  try {
    const org = await prisma.organization.findUnique({ where: { id: req.params.orgId } });
    if (!org) return res.status(404).json({ error: 'Organization not found' });
    if (org.isPersonal) return res.status(400).json({ error: 'Cannot delete personal organization' });

    const membership = await prisma.organizationMember.findUnique({
      where: { userId_organizationId: { userId: req.user.id, organizationId: req.params.orgId } }
    });
    if (!membership || membership.role !== 'admin') {
      return res.status(403).json({ error: 'Only admins can delete the organization' });
    }

    // Cascade delete: members, transactions, books, then org
    const orgBooks = await prisma.book.findMany({
      where: { organizationId: req.params.orgId },
      select: { id: true }
    });
    const bookIds = orgBooks.map(b => b.id);
    await prisma.$transaction([
      prisma.organizationMember.deleteMany({ where: { organizationId: req.params.orgId } }),
      prisma.transaction.deleteMany({ where: { bookId: { in: bookIds } } }),
      prisma.book.deleteMany({ where: { organizationId: req.params.orgId } }),
      prisma.organization.delete({ where: { id: req.params.orgId } }),
    ]);

    broadcast({ type: "data_changed" });
    res.json({ message: 'Organization deleted successfully' });
  } catch (error) {
    console.error('Delete org error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// AGENTIC AI ROUTE — Tool Calling & Action Execution
// ─────────────────────────────────────────────────────────────────────────────
app.post('/api/ai/agent', authenticateToken, async (req, res) => {
  try {
    const { provider, apiKey, model, baseUrl, messages, bookId, orgId, temperature, maxTokens } = req.body;

    if (!provider || !apiKey || !model || !messages) {
      return res.status(400).json({ error: 'Missing required fields: provider, apiKey, model, messages' });
    }

    // ── Fetch financial context ──
    const userOrgs = await prisma.organizationMember.findMany({
      where: { userId: req.user.id, status: 'active' },
      include: { organization: { include: { books: true } } }
    });

    const allBooks = userOrgs.flatMap(m => m.organization.books);

    let contextBookId = bookId;
    if (!contextBookId && allBooks.length > 0) {
      const defaultBook = allBooks.find(b => b.isDefault) || allBooks[0];
      contextBookId = defaultBook.id;
    }

    const recentTxns = contextBookId ? await prisma.transaction.findMany({
      where: { bookId: contextBookId },
      orderBy: { dateTime: 'desc' },
      take: 30
    }) : [];

    const userData = await prisma.user.findUnique({ where: { id: req.user.id } });

    const orgSummary = userOrgs.map(m =>
      `Org: "${m.organization.name}" | Role: ${m.role}`
    ).join('\n');

    const booksSummary = allBooks.map(b =>
      `- ID:${b.id} | Name:"${b.name}" | Balance:${b.balance} BDT | Org: "${b.organization?.name || 'Unknown'}"`
    ).join('\n');

    const txnSummary = recentTxns.map(t =>
      `- ${t.dateTime?.toISOString?.().split('T')[0] || ''}: ${t.type} of ${t.amount} BDT | Category:"${t.category}" | Note:"${t.note || ''}"`
    ).join('\n');

    // ── System Prompt ──
    const systemPrompt = `You are Hisab Pata AI — a Bangladeshi personal finance assistant.

## CRITICAL RULES (read carefully):
- NEVER use markdown, asterisks, quotes, or special characters. Plain text ONLY.
- Respond in MAX 2-3 sentences for regular answers. Short and direct.
- Always respond in the same language the user writes in.
- NEVER say "recorded" or "added" for transactions. Say "ready for your approval".

## USER INFO
Name: ${userData?.name || 'User'}
Email: ${userData?.email || 'Unknown'}

## USER'S ORGANIZATIONS
${orgSummary || 'No organizations found'}

## USER'S BOOKS (ALL)
${booksSummary || 'No books found'}

## RECENT TRANSACTIONS
${txnSummary || 'No transactions yet'}

## FORMATTED DATA DISPLAY
When user asks for summaries, balances, or breakdowns — include a DATA block at the end:

Balance summary:
[DATA type:balance]
[{"book":"Personal","balance":15000,"org":"Personal"},{"book":"Office","balance":30000,"org":"Dhaka Office"}]
[/DATA]

Category breakdown:
[DATA type:category]
[{"category":"Food","amount":5000,"count":12},{"category":"Transport","amount":2000,"count":8}]
[/DATA]

Multiple transactions:
[DATA type:transactions]
[{"note":"Rickshaw from Mugda","amount":50,"type":"expense","category":"Transport"},{"note":"Breakfast","amount":120,"type":"expense","category":"Food"}]
[/DATA]

The DATA block will be rendered as beautiful cards/tables by the app.

## CREATING TRANSACTIONS
When user describes daily expenses with details:
1. Parse the description and break into multiple logical transactions
2. Show them in a DATA type:transactions block
3. Include action block for EACH transaction at the end
4. Ask user to confirm

Action block format (MULTIPLE allowed, one per transaction):

\`\`\`action
{
  "action": "create_transaction",
  "data": {
    "bookId": "<book_id>",
    "type": "income" or "expense",
    "amount": <number>,
    "category": "<category>",
    "note": "<note>",
    "dateTime": "<ISO date string>",
    "contact": "<name or phone (optional)>",
    "recipientUserId": "<user_id if sending money>",
    "orgFundId": "<fund_id if applicable>"
  }
}
\`\`\`

For bug/complaint:

\`\`\`action
{
  "action": "create_complaint",
  "data": {
    "subject": "<short title>",
    "message": "<details>",
    "category": "Bug" or "Feature Request" or "Account Issue" or "Other"
  }
}
\`\`\`

## STRICT RULES:
1. For summaries/balances — use DATA block. Text response max 1 line.
2. For creating transactions — use action blocks. Can have MULTIPLE blocks.
3. Categories: খাবার, যাতায়াত, বাজার, বিল, বেতন, ব্যবসা, দান, শিক্ষা, চিকিৎসা, বিনোদন
4. Use today: ${new Date().toISOString().split('T')[0]}
5. Output PLAIN TEXT only. No symbols, no formatting chars.`;

    const tempVal = temperature != null ? parseFloat(temperature) : 0.7;
    const maxTokVal = maxTokens != null ? parseInt(maxTokens) : 2048;

    // ── Forward to AI Provider ──
    let aiResponseText = '';

    if (provider === 'gemini') {
      const url = baseUrl
        ? `${baseUrl}/v1beta/models/${model}:generateContent?key=${apiKey}`
        : `https://generativelanguage.googleapis.com/v1beta/models/${model}:generateContent?key=${apiKey}`;

      const contents = messages.map(m => ({
        role: m.role === 'user' ? 'user' : 'model',
        parts: [{ text: m.content }]
      }));

      const geminiRes = await fetch(url, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          contents,
          systemInstruction: { parts: [{ text: systemPrompt }] },
          generationConfig: { temperature: tempVal, maxOutputTokens: maxTokVal }
        })
      });
      const geminiData = await geminiRes.json();
      if (!geminiRes.ok) {
        return res.status(geminiRes.status).json({ error: geminiData.error?.message || 'Gemini API Error' });
      }
      aiResponseText = geminiData.candidates?.[0]?.content?.parts?.[0]?.text || '';

    } else if (provider === 'openai') {
      const url = baseUrl ? `${baseUrl}/v1/chat/completions` : 'https://api.openai.com/v1/chat/completions';
      const formattedMessages = [
        { role: 'system', content: systemPrompt },
        ...messages.map(m => ({ role: m.role, content: m.content }))
      ];

      const openaiRes = await fetch(url, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${apiKey}`
        },
        body: JSON.stringify({ model, messages: formattedMessages, temperature: tempVal, max_tokens: maxTokVal })
      });
      const openaiData = await openaiRes.json();
      if (!openaiRes.ok) {
        return res.status(openaiRes.status).json({ error: openaiData.error?.message || 'OpenAI API Error' });
      }
      aiResponseText = openaiData.choices?.[0]?.message?.content || '';

    } else if (provider === 'claude') {
      const url = baseUrl ? `${baseUrl}/v1/messages` : 'https://api.anthropic.com/v1/messages';
      const claudeRes = await fetch(url, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'x-api-key': apiKey,
          'anthropic-version': '2023-06-01'
        },
        body: JSON.stringify({
          model,
          max_tokens: maxTokVal,
          temperature: tempVal,
          system: systemPrompt,
          messages: messages.map(m => ({ role: m.role, content: m.content }))
        })
      });
      const claudeData = await claudeRes.json();
      if (!claudeRes.ok) {
        return res.status(claudeRes.status).json({ error: claudeData.error?.message || 'Claude API Error' });
      }
      aiResponseText = claudeData.content?.[0]?.text || '';

    } else {
      return res.status(400).json({ error: 'Unsupported provider' });
    }

    // ── Parse Actions from AI Response ───
    // - create_transaction: added to proposedActions (user must approve)
    // - create_complaint: auto-executed (no approval needed)
    const actionBlockRegex = /```action\s*([\s\S]*?)```/g;
    const matches = [...aiResponseText.matchAll(actionBlockRegex)];
    let cleanResponse = aiResponseText.replace(actionBlockRegex, '').trim();

    const proposedActions = [];
    const autoExecuted = [];

    for (const match of matches) {
      try {
        const actionData = JSON.parse(match[1].trim());

        if (actionData.action === 'create_transaction' && actionData.data) {
          const { bookId: txnBookId, type, amount, category, note, dateTime, contact, recipientUserId, orgFundId } = actionData.data;

          // Validate book access (check only, don't execute)
          const book = await prisma.book.findFirst({
            where: { id: txnBookId || contextBookId },
            include: { organization: { include: { members: { where: { userId: req.user.id } } } } }
          });

          if (!book || book.organization.members.length === 0) {
            proposedActions.push({
              action: 'create_transaction',
              data: actionData.data,
              valid: false,
              reason: 'Book not found or access denied',
            });
          } else {
            const parsedAmount = parseFloat(amount);
            proposedActions.push({
              action: 'create_transaction',
              data: {
                bookId: book.id,
                bookName: book.name,
                orgName: book.organization?.name || 'Unknown',
                type,
                amount: parsedAmount,
                category: category || 'General',
                note: note || '',
                dateTime: dateTime ? new Date(dateTime) : new Date().toISOString(),
                contact: contact || '',
                recipientUserId: recipientUserId || null,
                orgFundId: orgFundId || null,
              },
              valid: true,
            });
          }
        }

        if (actionData.action === 'create_complaint' && actionData.data) {
          const { subject, message, category } = actionData.data;
          if (subject && message) {
            try {
              const complaint = await prisma.complaint.create({
                data: { userId: req.user.id, subject, message, category: category || 'Other' },
              });
              autoExecuted.push({ action: 'create_complaint', subject, id: complaint.id });
              cleanResponse += `\n\n⚠️ I've filed a report: "${subject}". Our team will look into it.`;
            } catch (err) {
              console.error('[AI Agent] Auto-execute complaint failed:', err);
            }
          }
        }
      } catch (parseErr) {
        console.error('[AI Agent] Action parse error:', parseErr);
      }
    }

    return res.json({
      response: cleanResponse,
      proposedActions,
    });

  } catch (error) {
    console.error('[AI Agent] Error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// AGENTIC AI STREAMING ROUTE — SSE streaming response
// ─────────────────────────────────────────────────────────────────────────────
app.post('/api/ai/agent/stream', authenticateToken, async (req, res) => {
  try {
    const { provider, apiKey, model, baseUrl, messages, bookId, orgId, temperature, maxTokens } = req.body;

    if (!provider || !apiKey || !model || !messages) {
      return res.status(400).json({ error: 'Missing required fields: provider, apiKey, model, messages' });
    }

    // ── Fetch financial context ──
    const userOrgs = await prisma.organizationMember.findMany({
      where: { userId: req.user.id, status: 'active' },
      include: { organization: { include: { books: true } } }
    });

    const allBooks = userOrgs.flatMap(m => m.organization.books);

    let contextBookId = bookId;
    if (!contextBookId && allBooks.length > 0) {
      const defaultBook = allBooks.find(b => b.isDefault) || allBooks[0];
      contextBookId = defaultBook.id;
    }

    const recentTxns = contextBookId ? await prisma.transaction.findMany({
      where: { bookId: contextBookId },
      orderBy: { dateTime: 'desc' },
      take: 30
    }) : [];

    const userData = await prisma.user.findUnique({ where: { id: req.user.id } });

    const orgSummary = userOrgs.map(m =>
      `Org: "${m.organization.name}" | Role: ${m.role}`
    ).join('\n');

    const booksSummary = allBooks.map(b =>
      `- ID:${b.id} | Name:"${b.name}" | Balance:${b.balance} BDT | Org: "${b.organization?.name || 'Unknown'}"`
    ).join('\n');

    const txnSummary = recentTxns.map(t =>
      `- ${t.dateTime?.toISOString?.().split('T')[0] || ''}: ${t.type} of ${t.amount} BDT | Category:"${t.category}" | Note:"${t.note || ''}"`
    ).join('\n');

    const systemPrompt = `You are Hisab Pata AI — a Bangladeshi personal finance assistant.

## CRITICAL RULES (read carefully):
- NEVER use markdown, asterisks, quotes, or special characters. Plain text ONLY.
- Respond in MAX 2-3 sentences for regular answers. Short and direct.
- Always respond in the same language the user writes in.
- NEVER say "recorded" or "added" for transactions. Say "ready for your approval".

## USER INFO
Name: ${userData?.name || 'User'}
Email: ${userData?.email || 'Unknown'}

## USER'S ORGANIZATIONS
${orgSummary || 'No organizations found'}

## USER'S BOOKS (ALL)
${booksSummary || 'No books found'}

## RECENT TRANSACTIONS
${txnSummary || 'No transactions yet'}

## FORMATTED DATA DISPLAY
When user asks for summaries, balances, or breakdowns — include a DATA block at the end:

Balance summary:
[DATA type:balance]
[{"book":"Personal","balance":15000,"org":"Personal"},{"book":"Office","balance":30000,"org":"Dhaka Office"}]
[/DATA]

Category breakdown:
[DATA type:category]
[{"category":"Food","amount":5000,"count":12},{"category":"Transport","amount":2000,"count":8}]
[/DATA]

Multiple transactions:
[DATA type:transactions]
[{"note":"Rickshaw from Mugda","amount":50,"type":"expense","category":"Transport"},{"note":"Breakfast","amount":120,"type":"expense","category":"Food"}]
[/DATA]

The DATA block will be rendered as beautiful cards/tables by the app.

## CREATING TRANSACTIONS
When user describes daily expenses with details:
1. Parse the description and break into multiple logical transactions
2. Show them in a DATA type:transactions block
3. Include action block for EACH transaction at the end
4. Ask user to confirm

Action block format (MULTIPLE allowed, one per transaction):

\`\`\`action
{
  "action": "create_transaction",
  "data": {
    "bookId": "<book_id>",
    "type": "income" or "expense",
    "amount": <number>,
    "category": "<category>",
    "note": "<note>",
    "dateTime": "<ISO date string>",
    "contact": "<name or phone (optional)>",
    "recipientUserId": "<user_id if sending money>",
    "orgFundId": "<fund_id if applicable>"
  }
}
\`\`\`

For bug/complaint:

\`\`\`action
{
  "action": "create_complaint",
  "data": {
    "subject": "<short title>",
    "message": "<details>",
    "category": "Bug" or "Feature Request" or "Account Issue" or "Other"
  }
}
\`\`\`

## STRICT RULES:
1. For summaries/balances — use DATA block. Text response max 1 line.
2. For creating transactions — use action blocks. Can have MULTIPLE blocks.
3. Categories: খাবার, যাতায়াত, বাজার, বিল, বেতন, ব্যবসা, দান, শিক্ষা, চিকিৎসা, বিনোদন
4. Use today: ${new Date().toISOString().split('T')[0]}
5. Output PLAIN TEXT only. No symbols, no formatting chars.`;

    // ── Set up SSE ──
    res.setHeader('Content-Type', 'text/event-stream');
    res.setHeader('Cache-Control', 'no-cache');
    res.setHeader('Connection', 'keep-alive');
    res.flushHeaders();

    const sendEvent = (type, data) => {
      res.write(`data: ${JSON.stringify({ type, ...data })}\n\n`);
    };

    const tempVal = temperature != null ? parseFloat(temperature) : 0.7;
    const maxTokVal = maxTokens != null ? parseInt(maxTokens) : 2048;

    if (provider === 'gemini') {
      const url = baseUrl
        ? `${baseUrl}/v1beta/models/${model}:streamGenerateContent?alt=sse&key=${apiKey}`
        : `https://generativelanguage.googleapis.com/v1beta/models/${model}:streamGenerateContent?alt=sse&key=${apiKey}`;

      const contents = messages.map(m => ({
        role: m.role === 'user' ? 'user' : 'model',
        parts: [{ text: m.content }]
      }));

      const geminiRes = await fetch(url, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          contents,
          systemInstruction: { parts: [{ text: systemPrompt }] },
          generationConfig: { temperature: tempVal, maxOutputTokens: maxTokVal }
        })
      });

      if (!geminiRes.ok) {
        const errData = await geminiRes.json();
        sendEvent('error', { message: errData.error?.message || 'Gemini API Error' });
        sendEvent('done', {});
        return res.end();
      }

      const reader = geminiRes.body.getReader();
      const decoder = new TextDecoder();
      let buffer = '';
      let fullText = '';

      while (true) {
        const { done, value } = await reader.read();
        if (done) break;

        buffer += decoder.decode(value, { stream: true });
        const lines = buffer.split('\n');
        buffer = lines.pop() || '';

        for (const line of lines) {
          if (line.startsWith('data: ')) {
            try {
              const data = JSON.parse(line.slice(6));
              const text = data.candidates?.[0]?.content?.parts?.[0]?.text;
              if (text) {
                fullText += text;
                sendEvent('chunk', { content: text });
              }
            } catch (e) { /* skip parse errors */ }
          }
        }
      }

      // Parse any action blocks from the full response
      const actionBlockRegex = /```action\s*([\s\S]*?)```/g;
      const matches = [...fullText.matchAll(actionBlockRegex)];
      const cleanResponse = fullText.replace(actionBlockRegex, '').trim();
      const proposedActions = [];

      for (const match of matches) {
        try {
          const actionData = JSON.parse(match[1].trim());
          if (actionData.action === 'create_transaction' && actionData.data) {
            const { bookId: txnBookId, type, amount, category, note, dateTime, contact, recipientUserId, orgFundId } = actionData.data;
            const book = await prisma.book.findFirst({
              where: { id: txnBookId || contextBookId },
              include: { organization: { include: { members: { where: { userId: req.user.id } } } } }
            });
            if (book && book.organization.members.length > 0) {
              proposedActions.push({
                action: 'create_transaction',
                data: {
                  bookId: book.id, bookName: book.name, orgName: book.organization?.name,
                  type, amount: parseFloat(amount), category: category || 'General',
                  note: note || '', dateTime: dateTime ? new Date(dateTime) : new Date().toISOString(),
                  contact: contact || '', recipientUserId: recipientUserId || null, orgFundId: orgFundId || null,
                },
                valid: true,
              });
            }
          }
          if (actionData.action === 'create_complaint' && actionData.data) {
            const { subject, message, category } = actionData.data;
            if (subject && message) {
              try {
                const complaint = await prisma.complaint.create({
                  data: { userId: req.user.id, subject, message, category: category || 'Other' },
                });
                sendEvent('auto_action', { action: 'create_complaint', subject, id: complaint.id });
              } catch (err) { /* skip */ }
            }
          }
        } catch (e) { /* skip parse errors */ }
      }

      if (proposedActions.length > 0) {
        sendEvent('actions', { actions: proposedActions });
      }

    } else if (provider === 'openai') {
      const url = baseUrl ? `${baseUrl}/v1/chat/completions` : 'https://api.openai.com/v1/chat/completions';
      const formattedMessages = [
        { role: 'system', content: systemPrompt },
        ...messages.map(m => ({ role: m.role, content: m.content }))
      ];

      const openaiRes = await fetch(url, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${apiKey}`
        },
        body: JSON.stringify({
          model,
          messages: formattedMessages,
          temperature: tempVal,
          max_tokens: maxTokVal,
          stream: true
        })
      });

      if (!openaiRes.ok) {
        const errData = await openaiRes.json();
        sendEvent('error', { message: errData.error?.message || 'OpenAI API Error' });
        sendEvent('done', {});
        return res.end();
      }

      const reader = openaiRes.body.getReader();
      const decoder = new TextDecoder();
      let buffer = '';
      let fullText = '';

      while (true) {
        const { done, value } = await reader.read();
        if (done) break;

        buffer += decoder.decode(value, { stream: true });
        const lines = buffer.split('\n');
        buffer = lines.pop() || '';

        for (const line of lines) {
          if (line.startsWith('data: ')) {
            const jsonStr = line.slice(6).trim();
            if (jsonStr === '[DONE]') continue;
            try {
              const data = JSON.parse(jsonStr);
              const content = data.choices?.[0]?.delta?.content || '';
              if (content) {
                fullText += content;
                sendEvent('chunk', { content });
              }
            } catch (e) { /* skip */ }
          }
        }
      }

      // Parse actions (same as gemini)
      const actionBlockRegex = /```action\s*([\s\S]*?)```/g;
      const matches = [...fullText.matchAll(actionBlockRegex)];
      const proposedActions = [];
      for (const match of matches) {
        try {
          const actionData = JSON.parse(match[1].trim());
          if (actionData.action === 'create_transaction' && actionData.data) {
            const { bookId: txnBookId, type, amount, category, note, dateTime, contact, recipientUserId, orgFundId } = actionData.data;
            const book = await prisma.book.findFirst({
              where: { id: txnBookId || contextBookId },
              include: { organization: { include: { members: { where: { userId: req.user.id } } } } }
            });
            if (book && book.organization.members.length > 0) {
              proposedActions.push({
                action: 'create_transaction',
                data: {
                  bookId: book.id, bookName: book.name, orgName: book.organization?.name,
                  type, amount: parseFloat(amount), category: category || 'General',
                  note: note || '', dateTime: dateTime ? new Date(dateTime) : new Date().toISOString(),
                  contact: contact || '', recipientUserId: recipientUserId || null, orgFundId: orgFundId || null,
                },
                valid: true,
              });
            }
          }
          if (actionData.action === 'create_complaint' && actionData.data) {
            const { subject, message, category } = actionData.data;
            if (subject && message) {
              const complaint = await prisma.complaint.create({
                data: { userId: req.user.id, subject, message, category: category || 'Other' },
              });
              sendEvent('auto_action', { action: 'create_complaint', subject, id: complaint.id });
            }
          }
        } catch (e) { /* skip */ }
      }
      if (proposedActions.length > 0) {
        sendEvent('actions', { actions: proposedActions });
      }

    } else if (provider === 'claude') {
      const url = baseUrl ? `${baseUrl}/v1/messages` : 'https://api.anthropic.com/v1/messages';
      const claudeRes = await fetch(url, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'x-api-key': apiKey,
          'anthropic-version': '2023-06-01'
        },
        body: JSON.stringify({
          model,
          max_tokens: maxTokVal,
          temperature: tempVal,
          system: systemPrompt,
          messages: messages.map(m => ({ role: m.role, content: m.content })),
          stream: true
        })
      });

      if (!claudeRes.ok) {
        const errData = await claudeRes.json();
        sendEvent('error', { message: errData.error?.message || 'Claude API Error' });
        sendEvent('done', {});
        return res.end();
      }

      const reader = claudeRes.body.getReader();
      const decoder = new TextDecoder();
      let buffer = '';
      let fullText = '';

      while (true) {
        const { done, value } = await reader.read();
        if (done) break;

        buffer += decoder.decode(value, { stream: true });
        const lines = buffer.split('\n');
        buffer = lines.pop() || '';

        for (const line of lines) {
          if (line.startsWith('data: ')) {
            try {
              const data = JSON.parse(line.slice(6));
              if (data.type === 'content_block_delta' && data.delta?.text) {
                fullText += data.delta.text;
                sendEvent('chunk', { content: data.delta.text });
              }
            } catch (e) { /* skip */ }
          }
        }
      }

      // Parse actions (same as above)
      const actionBlockRegex = /```action\s*([\s\S]*?)```/g;
      const matches = [...fullText.matchAll(actionBlockRegex)];
      const proposedActions = [];
      for (const match of matches) {
        try {
          const actionData = JSON.parse(match[1].trim());
          if (actionData.action === 'create_transaction' && actionData.data) {
            const { bookId: txnBookId, type, amount, category, note, dateTime, contact, recipientUserId, orgFundId } = actionData.data;
            const book = await prisma.book.findFirst({
              where: { id: txnBookId || contextBookId },
              include: { organization: { include: { members: { where: { userId: req.user.id } } } } }
            });
            if (book && book.organization.members.length > 0) {
              proposedActions.push({
                action: 'create_transaction',
                data: {
                  bookId: book.id, bookName: book.name, orgName: book.organization?.name,
                  type, amount: parseFloat(amount), category: category || 'General',
                  note: note || '', dateTime: dateTime ? new Date(dateTime) : new Date().toISOString(),
                  contact: contact || '', recipientUserId: recipientUserId || null, orgFundId: orgFundId || null,
                },
                valid: true,
              });
            }
          }
          if (actionData.action === 'create_complaint' && actionData.data) {
            const { subject, message, category } = actionData.data;
            if (subject && message) {
              const complaint = await prisma.complaint.create({
                data: { userId: req.user.id, subject, message, category: category || 'Other' },
              });
              sendEvent('auto_action', { action: 'create_complaint', subject, id: complaint.id });
            }
          }
        } catch (e) { /* skip */ }
      }
      if (proposedActions.length > 0) {
        sendEvent('actions', { actions: proposedActions });
      }

    } else {
      sendEvent('error', { message: `Unsupported provider: ${provider}` });
      sendEvent('done', {});
      return res.end();
    }

    sendEvent('done', {});
    res.end();

  } catch (error) {
    console.error('[AI Agent Stream] Error:', error);
    if (!res.headersSent) {
      res.status(500).json({ error: 'Internal server error' });
    } else {
      res.write(`data: ${JSON.stringify({ type: 'error', message: 'Internal server error' })}\n\n`);
      res.end();
    }
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// AI TOOLS — Data endpoints for AI agent
// ─────────────────────────────────────────────────────────────────────────────

// Get spending summary by category for a book
app.get('/api/ai/tools/category-summary', authenticateToken, async (req, res) => {
  try {
    const { bookId, startDate, endDate, orgId } = req.query;
    const where = { userId: req.user.id, status: 'active' };
    
    const memberships = await prisma.organizationMember.findMany({ where, include: { organization: { include: { books: true } } } });
    
    let bookIds = [];
    if (bookId) {
      bookIds = [bookId];
    } else if (orgId) {
      const org = memberships.find(m => m.organizationId === orgId);
      if (org) bookIds = org.organization.books.map(b => b.id);
    } else {
      bookIds = memberships.flatMap(m => m.organization.books.map(b => b.id));
    }

    const dateFilter = {};
    if (startDate) dateFilter.gte = new Date(startDate);
    if (endDate) dateFilter.lte = new Date(endDate);

    const transactions = await prisma.transaction.findMany({
      where: {
        bookId: { in: bookIds },
        type: 'expense',
        reconStatus: 'approved',
        ...(Object.keys(dateFilter).length ? { dateTime: dateFilter } : {}),
      },
      select: { category: true, amount: true, dateTime: true },
    });

    const summary = {};
    let total = 0;
    for (const t of transactions) {
      const cat = t.category || 'Other';
      summary[cat] = (summary[cat] || 0) + t.amount;
      total += t.amount;
    }

    const result = Object.entries(summary)
      .map(([category, amount]) => ({
        category, amount: Math.round(amount * 100) / 100,
        percentage: total > 0 ? Math.round((amount / total) * 100) : 0,
        count: transactions.filter(t => (t.category || 'Other') === category).length,
      }))
      .sort((a, b) => b.amount - a.amount);

    res.json({ categories: result, total: Math.round(total * 100) / 100, currency: 'BDT' });
  } catch (error) {
    console.error('[AI Tools] category-summary error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Get all books with balances
app.get('/api/ai/tools/balance-summary', authenticateToken, async (req, res) => {
  try {
    const memberships = await prisma.organizationMember.findMany({
      where: { userId: req.user.id, status: 'active' },
      include: { organization: { include: { books: true } } },
    });

    const books = memberships.flatMap(m =>
      m.organization.books.map(b => ({
        id: b.id,
        name: b.name,
        balance: b.balance,
        organization: m.organization.name,
        isPersonal: m.organization.isPersonal,
        role: m.role,
      }))
    );

    const totalBalance = books.reduce((sum, b) => sum + b.balance, 0);
    res.json({ books, totalBalance, currency: 'BDT' });
  } catch (error) {
    console.error('[AI Tools] balance-summary error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Get recent transactions (with filters)
app.get('/api/ai/tools/recent-transactions', authenticateToken, async (req, res) => {
  try {
    const { bookId, limit, offset, type } = req.query;
    const where = { book: { organization: { members: { some: { userId: req.user.id, status: 'active' } } } } };
    if (bookId) where.bookId = bookId;
    if (type) where.type = type;

    const transactions = await prisma.transaction.findMany({
      where,
      orderBy: { dateTime: 'desc' },
      take: Math.min(parseInt(limit || '20'), 50),
      skip: parseInt(offset || '0'),
      include: { book: { select: { name: true, organization: { select: { name: true } } } } },
    });

    const result = transactions.map(t => ({
      id: t.id, amount: t.amount, type: t.type, category: t.category,
      note: t.note, dateTime: t.dateTime, status: t.reconStatus,
      bookName: t.book.name, orgName: t.book.organization?.name,
    }));

    res.json({ transactions: result, count: result.length });
  } catch (error) {
    console.error('[AI Tools] recent-transactions error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// AI EXECUTE — Run a confirmed action proposed by the AI agent
// ─────────────────────────────────────────────────────────────────────────────
app.post('/api/ai/execute', authenticateToken, async (req, res) => {
  try {
    const { action, data } = req.body;

    if (!action || !data) {
      return res.status(400).json({ error: 'Missing action or data' });
    }

    if (action === 'create_transaction') {
      const { bookId, type, amount, category, note, dateTime, contact, recipientUserId, orgFundId } = data;

      if (!bookId || !type || !amount) {
        return res.status(400).json({ error: 'Missing required transaction fields' });
      }

      const book = await prisma.book.findFirst({
        where: { id: bookId },
        include: { organization: { include: { members: { where: { userId: req.user.id } } } } }
      });

      if (!book || book.organization.members.length === 0) {
        return res.status(403).json({ error: 'Book not found or access denied' });
      }

      const parsedAmount = parseFloat(amount);
      if (!parsedAmount || parsedAmount <= 0) {
        return res.status(400).json({ error: 'Amount must be a positive number' });
      }

      let newBalance = type === 'income'
        ? book.balance + parsedAmount
        : book.balance - parsedAmount;

      // Handle Send type (expense to another user)
      const isSend = type === 'expense' && recipientUserId;

      const txnData = {
        bookId: book.id,
        type,
        amount: parsedAmount,
        category: category || 'General',
        note: note || '',
        contact: contact || null,
        recipientUserId: recipientUserId || null,
        orgFundId: orgFundId || null,
        dateTime: dateTime ? new Date(dateTime) : new Date(),
        status: isSend ? 'pending' : 'approved',
        reconStatus: isSend ? 'pending' : 'approved',
        createdById: req.user.id,
      };

      let transaction;

      if (isSend) {
        // For Send: sender gets pending expense, recipient gets linked pending income
        const recipientBook = await prisma.book.findFirst({
          where: { organization: { members: { some: { userId: recipientUserId, status: 'active' } } }, isDefault: true },
          include: { organization: { select: { name: true } } },
        });

        // Determine fund/org name for the linked transaction note
        let sourceName = book.organization?.name;
        if (!sourceName && orgFundId) {
          const fundTxn = await prisma.transaction.findUnique({
            where: { id: orgFundId },
          });
          if (fundTxn?.linkedTransactionId) {
            const orgTxn = await prisma.transaction.findUnique({
              where: { id: fundTxn.linkedTransactionId },
              include: { book: { include: { organization: { select: { name: true } } } } },
            });
            sourceName = orgTxn?.book?.organization?.name;
          }
        }

        transaction = await prisma.transaction.create({ data: txnData });

        if (recipientBook) {
          const linkedTxn = await prisma.transaction.create({
            data: {
              bookId: recipientBook.id,
              type: 'income',
              amount: parsedAmount,
              category: category || 'Send',
              note: `Received from ${sourceName || 'Unknown'}: ${note || ''}`,
              contact: contact || null,
              orgFundId: orgFundId || null,
              linkedTransactionId: transaction.id,
              dateTime: new Date(),
              status: 'pending',
              reconStatus: 'pending',
              createdById: recipientUserId,
            },
          });
          await prisma.transaction.update({
            where: { id: transaction.id },
            data: { linkedTransactionId: linkedTxn.id },
          });
        }

        broadcast({ type: 'data_changed' });
        return res.json({
          success: true,
          message: `Send of ${parsedAmount} BDT prepared for approval in "${book.name}"`,
          transaction: { id: transaction.id, bookId, type, amount: parsedAmount, status: 'pending' },
          requiresApproval: true,
        });
      }

      // Normal income/expense
      const [txn, _book] = await prisma.$transaction([
        prisma.transaction.create({ data: txnData }),
        prisma.book.update({ where: { id: book.id }, data: { balance: newBalance } }),
      ]);
      transaction = txn;

      broadcast({ type: 'data_changed' });

      return res.json({
        success: true,
        message: `${type === 'income' ? 'Income' : 'Expense'} of ${parsedAmount} BDT created in "${book.name}"`,
        transaction: {
          id: transaction.id,
          bookId: transaction.bookId,
          bookName: book.name,
          type: transaction.type,
          amount: transaction.amount,
          category: transaction.category,
          note: transaction.note,
        },
        newBalance,
      });
    }

    if (action === 'create_complaint') {
      const { subject, message, category } = data;

      if (!subject || !message) {
        return res.status(400).json({ error: 'Subject and message are required' });
      }

      const complaint = await prisma.complaint.create({
        data: {
          userId: req.user.id,
          subject,
          message,
          category: category || 'Other',
        },
      });

      return res.json({
        success: true,
        message: `Complaint "${subject}" filed successfully`,
        complaint: { id: complaint.id, subject: complaint.subject },
      });
    }

    return res.status(400).json({ error: `Unknown action: ${action}` });
  } catch (error) {
    console.error('[AI Execute] Error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// ADMIN — User management & complaints
// ─────────────────────────────────────────────────────────────────────────────
app.get('/api/admin/users', authenticateAdmin, async (req, res) => {
  try {
    const users = await prisma.user.findMany({
      select: { id: true, name: true, email: true, phoneNumber: true, isAdmin: true, avatarUrl: true, createdAt: true },
      orderBy: { createdAt: 'desc' },
    });
    res.json(users);
  } catch (error) {
    console.error('[Admin] Failed to fetch users:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.get('/api/admin/complaints', authenticateAdmin, async (req, res) => {
  try {
    const complaints = await prisma.complaint.findMany({
      include: { user: { select: { id: true, name: true, email: true, phoneNumber: true } } },
      orderBy: { createdAt: 'desc' },
    });
    res.json(complaints);
  } catch (error) {
    console.error('[Admin] Failed to fetch complaints:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.post('/api/admin/complaints', authenticateToken, (req, res) => {
  upload.array('files', 10)(req, res, async (err) => {
    if (err) return res.status(400).json({ error: err.message });

    try {
      const { subject, message, category } = req.body;
      if (!subject || !message) {
        return res.status(400).json({ error: 'Subject and message are required' });
      }

      const imageUrls = [];
      const videoUrls = [];
      if (req.files) {
        for (const file of req.files) {
          const url = `/uploads/${file.filename}`;
          if (file.mimetype.startsWith('video/')) {
            videoUrls.push(url);
          } else {
            imageUrls.push(url);
          }
        }
      }

      const complaint = await prisma.complaint.create({
        data: { userId: req.user.id, subject, message, category: category || null, imageUrls, videoUrls },
      });
      res.status(201).json(complaint);
    } catch (error) {
      console.error('[Admin] Failed to create complaint:', error);
      res.status(500).json({ error: 'Internal server error' });
    }
  });
});

app.put('/api/admin/complaints/:id', authenticateAdmin, async (req, res) => {
  try {
    const { status, priority, assignedTo, response, category } = req.body;
    const data = {};
    if (status !== undefined) data.status = status;
    if (priority !== undefined) data.priority = priority;
    if (assignedTo !== undefined) data.assignedTo = assignedTo;
    if (response !== undefined) data.response = response;
    if (category !== undefined) data.category = category;

    const complaint = await prisma.complaint.update({
      where: { id: req.params.id },
      data,
      include: { user: { select: { id: true, name: true, email: true } } },
    });
    res.json(complaint);
  } catch (error) {
    console.error('[Admin] Failed to update complaint:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// --- SEED ACCOUNT ON STARTUP (CLEAN) ---
const seedUser = async () => {
  try {
    const email = 'rahat@hisabpata.com';
    const existingUser = await prisma.user.findUnique({ where: { email } });
    
    if (!existingUser) {
      console.log('Seeding clean default user: rahat@hisabpata.com / rahat123...');
      const hashedPassword = await bcrypt.hash('rahat123', 10);
      const user = await prisma.user.create({
        data: {
          name: 'Rahat Chowdhury',
          email,
          phoneNumber: '01712345678',
          password: hashedPassword,
          isAdmin: true,
        }
      });

      // Create Personal Org with default book
      const personalOrg = await prisma.organization.create({
        data: { name: `${user.name}'s Personal`, isPersonal: true, inviteCode: null }
      });
      await prisma.organizationMember.create({
        data: { userId: user.id, organizationId: personalOrg.id, role: 'admin', status: 'active' }
      });
      await prisma.book.create({
        data: { name: 'Personal Book', isDefault: true, balance: 0.0, organizationId: personalOrg.id }
      });

      console.log('Clean user successfully seeded! 🚀');
    } else {
      console.log('Default account already exists. Seeding skipped.');
    }
  } catch (err) {
    console.error('Error seeding default user:', err);
  }
};

// WebSocket broadcast helper with user-targeted notifications
const server = http.createServer(app);
const wss = new WebSocketServer({ server });
const userClients = new Map(); // userId -> Set<WebSocket>

wss.on('connection', (ws, req) => {
  let userId = null;

  ws.on('message', (raw) => {
    try {
      const msg = JSON.parse(raw.toString());
      if (msg.type === 'auth') {
        jwt.verify(msg.token, JWT_SECRET_FINAL, (err, decoded) => {
          if (err) return;
          userId = decoded.id;
          if (!userClients.has(userId)) userClients.set(userId, new Set());
          userClients.get(userId).add(ws);
          ws.send(JSON.stringify({ type: 'auth_ok', userId }));
        });
      }
    } catch (e) {
      console.error('WS message error:', e);
    }
  });

  ws.on('close', () => {
    if (userId && userClients.has(userId)) {
      userClients.get(userId).delete(ws);
      if (userClients.get(userId).size === 0) userClients.delete(userId);
    }
  });

  ws.on('error', () => {});
});

function broadcast(data) {
  const msg = JSON.stringify(data);
  wss.clients.forEach(client => {
    try {
      if (client.readyState === 1) client.send(msg);
    } catch (e) {
      console.error('Broadcast error:', e);
    }
  });
}

function broadcastToUser(userId, data) {
  if (!userId) return;
  const msg = JSON.stringify(data);
  const clients = userClients.get(userId);
  if (clients) {
    clients.forEach(client => {
      try { if (client.readyState === 1) client.send(msg); } catch (e) {}
    });
  }
}

function broadcastToUsers(userIds, data) {
  if (!userIds || userIds.length === 0) return;
  const msg = JSON.stringify(data);
  for (const userId of userIds) {
    const clients = userClients.get(userId);
    if (clients) {
      clients.forEach(client => {
        try { if (client.readyState === 1) client.send(msg); } catch (e) {}
      });
    }
  }
}

// Graceful Shutdown
process.on('SIGTERM', async () => {
  console.log('\nSIGTERM received. Shutting down gracefully...');
  wss.close(() => console.log('WebSocket server closed.'));
  server.close(async () => {
    await prisma.$disconnect();
    console.log('Prisma disconnected. Goodbye!');
    process.exit(0);
  });
});
process.on('SIGINT', async () => {
  console.log('\nSIGINT received. Shutting down...');
  wss.close();
  server.close(async () => {
    await prisma.$disconnect();
    process.exit(0);
  });
});

// Start Server
server.listen(PORT, async () => {
  console.log(`\n======================================================`);
  console.log(`Hisab Pata Node.js Backend listening on port ${PORT} 🚀`);
  console.log(`WebSocket ready for realtime sync`);
  console.log(`======================================================\n`);
  if (process.env.NODE_ENV !== 'production' || process.env.SEED_DEFAULT_USER === 'true') {
    await seedUser();
  }
});
