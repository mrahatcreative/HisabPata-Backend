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

const DEFAULT_CATEGORIES = [
  'expense:Send',
  'expense:Transport',
  'expense:Mobile Recharge',
  'expense:Postage',
  'expense:Publication',
  'expense:Office Stationery',
  'expense:Tips',
  'expense:Donation',
  'expense:Others',
  'income:Salary',
  'income:Others'
];

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
app.use('/admin', express.static(path.join(__dirname, 'admin_console')));

// Log requests
app.use((req, res, next) => {
  console.log(`[${new Date().toISOString()}] ${req.method} ${req.path}`);
  next();
});

// Healthcheck endpoint (no auth required)
app.get('/api/health', (_req, res) => {
  const adminKey = (process.env.ADMIN_KEY || '').trim();
  res.json({
    status: 'ok',
    adminKeySet: !!process.env.ADMIN_KEY,
    adminKeyLength: adminKey.length,
  });
});

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
  const expectedKey = (process.env.ADMIN_KEY || '').trim();
  if (!adminKey || adminKey !== expectedKey) {
    console.error(`ADMIN_AUTH_FAIL: provided="${adminKey?.length || 0}chars" expected="${expectedKey?.length || 0}chars" path="${req.path}"`);
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

// Real orgs never auto-approve on create/retry — permission holders approve manually in Approval Center.
// Personal org only: internal personal-book flows skip org queue.
const checkApprovalBypass = async (orgId, userId) => {
  const org = await prisma.organization.findUnique({
    where: { id: orgId },
    select: { isPersonal: true }
  });
  if (!org || org.isPersonal) return true;
  return false;
};

// Which org's approval policy applies (fund org for cross-book vouchers, else book's org)
const resolveApprovalOrgId = async (txn, book) => {
  if (txn.orgFundId) {
    const fundBook = await prisma.book.findUnique({
      where: { id: txn.orgFundId },
      select: { id: true, organizationId: true }
    });
    if (fundBook && fundBook.id !== book.id) {
      return fundBook.organizationId;
    }
    const fundTxn = await prisma.transaction.findUnique({
      where: { id: txn.orgFundId },
      select: { bookId: true }
    });
    if (fundTxn) {
      const fundTxnBook = await prisma.book.findUnique({
        where: { id: fundTxn.bookId },
        select: { organizationId: true }
      });
      if (fundTxnBook) return fundTxnBook.organizationId;
    }
  }
  return book.organizationId;
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

const parsePendingData = (pendingData) => {
  if (!pendingData) return {};
  return typeof pendingData === 'string' ? JSON.parse(pendingData) : pendingData;
};

const CREATOR_PERSONAL_MIRROR_SUFFIX = '_cpm';

const findCreatorPersonalMirror = async (orgTxn, txClient = prisma) => {
  if (!orgTxn?.clientRef) return null;
  return txClient.transaction.findFirst({
    where: { clientRef: orgTxn.clientRef + CREATOR_PERSONAL_MIRROR_SUFFIX }
  });
};

// Org book Send expense ↔ personal book Send income
const resolveOrgDisbursementOrgTxn = async (txn, book) => {
  let resolvedBook = book;
  if (!resolvedBook?.organization) {
    resolvedBook = await prisma.book.findUnique({
      where: { id: txn.bookId },
      include: { organization: true }
    });
  }
  if (!resolvedBook) return null;

  if (!resolvedBook.organization?.isPersonal && txn.type === 'expense' && txn.category === 'Send') {
    return { orgTxn: txn, orgBook: resolvedBook };
  }
  if (resolvedBook.organization?.isPersonal && txn.type === 'income' && txn.category === 'Send' && txn.linkedTransactionId) {
    const linked = await prisma.transaction.findUnique({
      where: { id: txn.linkedTransactionId },
      include: { book: { include: { organization: true } } }
    });
    if (linked?.type === 'expense' && linked?.category === 'Send' && !linked.book?.organization?.isPersonal) {
      return { orgTxn: linked, orgBook: linked.book };
    }
  }
  return null;
};

const userStillActive = async (userId) => {
  if (!userId) return false;
  const user = await prisma.user.findUnique({ where: { id: userId }, select: { id: true } });
  return !!user;
};

const pickOrgRepresentative = (adminIds, excludeId) => adminIds.find((id) => id && id !== excludeId) || null;

const buildP1OrgApprovers = (chain, requesterId) => {
  const requesterIsP1 = requesterId === chain.p1.userId;
  const requesterIsOrg = chain.org.adminIds.includes(requesterId);
  if (requesterIsP1) {
    const rep = pickOrgRepresentative(chain.org.adminIds, requesterId);
    return { requiredApprovers: rep ? [rep] : [], orgApprovalAnyOf: chain.org.adminIds, chainNote: 'degraded_p1_org' };
  }
  if (requesterIsOrg) {
    return {
      requiredApprovers: chain.p1.userId && chain.p1.userId !== requesterId ? [chain.p1.userId] : [],
      orgApprovalAnyOf: [],
      chainNote: 'degraded_p1_org',
    };
  }
  const rep = pickOrgRepresentative(chain.org.adminIds, requesterId);
  return { requiredApprovers: rep ? [rep] : [], orgApprovalAnyOf: chain.org.adminIds, chainNote: 'degraded_p1_org' };
};

const computeRequiredApprovers = (chain, requesterId) => {
  if (!chain || chain.kind === 'solo') {
    return { requiredApprovers: [], orgApprovalAnyOf: [], chainNote: 'solo', isOrphan: true };
  }

  if (chain.kind === 'p1_org') {
    const p1Ok = chain.p1.active && chain.p1.hasEntry;
    const orgOk = chain.org.active && chain.org.hasEntry;
    if (!p1Ok || !orgOk) {
      return { requiredApprovers: [], orgApprovalAnyOf: [], chainNote: 'orphan_dual', isOrphan: true };
    }
    const result = buildP1OrgApprovers(chain, requesterId);
    return { ...result, isOrphan: false };
  }

  if (chain.kind === 'p1_p2') {
    const p1Ok = chain.p1.active && chain.p1.hasEntry;
    const p2Ok = chain.p2.active && chain.p2.hasEntry;
    if (!p1Ok || !p2Ok) {
      return { requiredApprovers: [], orgApprovalAnyOf: [], chainNote: 'orphan_dual', isOrphan: true };
    }
    const otherId = requesterId === chain.p1.userId ? chain.p2.userId : chain.p1.userId;
    return {
      requiredApprovers: otherId && otherId !== requesterId ? [otherId] : [],
      orgApprovalAnyOf: [],
      chainNote: 'dual',
      isOrphan: false,
    };
  }

  if (chain.kind === 'p1_org_p2') {
    const p1Ok = chain.p1.active && chain.p1.hasEntry;
    const p2Ok = chain.p2.active && chain.p2.hasEntry;
    const orgOk = chain.org.active && chain.org.hasEntry;
    const presentLegs = [p1Ok, p2Ok, orgOk].filter(Boolean).length;

    if (presentLegs <= 1) {
      return { requiredApprovers: [], orgApprovalAnyOf: [], chainNote: 'orphan_triple', isOrphan: true };
    }

    if (!orgOk) {
      if (p1Ok && p2Ok) {
        const otherId = requesterId === chain.p1.userId ? chain.p2.userId : chain.p1.userId;
        return {
          requiredApprovers: otherId && otherId !== requesterId ? [otherId] : [],
          orgApprovalAnyOf: [],
          chainNote: 'degraded_p1_p2',
          isOrphan: false,
        };
      }
      return { requiredApprovers: [], orgApprovalAnyOf: [], chainNote: 'orphan_triple', isOrphan: true };
    }

    if (!p2Ok || !chain.p2.active) {
      if (!p1Ok) {
        return { requiredApprovers: [], orgApprovalAnyOf: [], chainNote: 'orphan_triple', isOrphan: true };
      }
      const result = buildP1OrgApprovers(chain, requesterId);
      return { ...result, isOrphan: false };
    }

    if (!p1Ok || !chain.p1.active) {
      if (!p2Ok) {
        return { requiredApprovers: [], orgApprovalAnyOf: [], chainNote: 'orphan_triple', isOrphan: true };
      }
      const requesterIsP2 = requesterId === chain.p2.userId;
      const requesterIsOrg = chain.org.adminIds.includes(requesterId);
      if (requesterIsP2) {
        const rep = pickOrgRepresentative(chain.org.adminIds, requesterId);
        return { requiredApprovers: rep ? [rep] : [], orgApprovalAnyOf: chain.org.adminIds, chainNote: 'degraded_org_p2', isOrphan: false };
      }
      if (requesterIsOrg) {
        return {
          requiredApprovers: chain.p2.userId && chain.p2.userId !== requesterId ? [chain.p2.userId] : [],
          orgApprovalAnyOf: [],
          chainNote: 'degraded_org_p2',
          isOrphan: false,
        };
      }
      const rep = pickOrgRepresentative(chain.org.adminIds, requesterId);
      return {
        requiredApprovers: [chain.p2.userId, rep].filter((id) => id && id !== requesterId),
        orgApprovalAnyOf: chain.org.adminIds,
        chainNote: 'degraded_org_p2',
        isOrphan: false,
      };
    }

    const required = [];
    const requesterIsP1 = requesterId === chain.p1.userId;
    const requesterIsP2 = requesterId === chain.p2.userId;
    const requesterIsOrg = chain.org.adminIds.includes(requesterId);

    if (requesterIsP1) {
      if (chain.p2.userId) required.push(chain.p2.userId);
      const rep = pickOrgRepresentative(chain.org.adminIds, requesterId);
      if (rep) required.push(rep);
    } else if (requesterIsP2) {
      if (chain.p1.userId) required.push(chain.p1.userId);
      const rep = pickOrgRepresentative(chain.org.adminIds, requesterId);
      if (rep) required.push(rep);
    } else if (requesterIsOrg) {
      if (chain.p1.userId) required.push(chain.p1.userId);
      if (chain.p2.userId) required.push(chain.p2.userId);
    } else {
      if (chain.p1.userId) required.push(chain.p1.userId);
      if (chain.p2.userId) required.push(chain.p2.userId);
    }

    return {
      requiredApprovers: [...new Set(required.filter((id) => id && id !== requesterId))],
      orgApprovalAnyOf: chain.org.adminIds,
      chainNote: 'triple',
      isOrphan: false,
    };
  }

  return { requiredApprovers: [], orgApprovalAnyOf: [], chainNote: 'solo', isOrphan: true };
};

const resolveChangeDeleteChain = async (txn, book) => {
  let resolvedBook = book;
  if (!resolvedBook?.organization) {
    resolvedBook = await prisma.book.findUnique({
      where: { id: txn.bookId },
      include: { organization: true },
    });
  }
  if (!resolvedBook) return { kind: 'solo' };

  const disbursement = await resolveOrgDisbursementOrgTxn(txn, resolvedBook);
  if (disbursement) {
    const { orgTxn, orgBook } = disbursement;
    const org = orgBook?.organizationId
      ? await prisma.organization.findUnique({ where: { id: orgBook.organizationId } })
      : null;
    const orgAdminIds = org ? await getOrgAdminUserIds(orgBook.organizationId) : [];
    const personalTxn = orgTxn.linkedTransactionId
      ? await prisma.transaction.findUnique({ where: { id: orgTxn.linkedTransactionId } })
      : null;

    return {
      kind: 'p1_org_p2',
      p1: {
        userId: orgTxn.createdById,
        active: await userStillActive(orgTxn.createdById),
        hasEntry: !!orgTxn?.id,
      },
      p2: {
        userId: orgTxn.recipientUserId,
        active: await userStillActive(orgTxn.recipientUserId),
        hasEntry: !!personalTxn?.id,
      },
      org: {
        active: !!org,
        hasEntry: !!orgTxn?.id && !!org,
        adminIds: orgAdminIds,
      },
    };
  }

  let personalEntry = null;
  let orgEntry = null;
  let p1UserId = txn.createdById;

  if (resolvedBook.organization?.isPersonal && (txn.orgFundId || txn.clientRef)) {
    personalEntry = txn;
    if (txn.clientRef?.endsWith(CREATOR_PERSONAL_MIRROR_SUFFIX)) {
      const baseRef = txn.clientRef.slice(0, -CREATOR_PERSONAL_MIRROR_SUFFIX.length);
      orgEntry = await prisma.transaction.findFirst({ where: { clientRef: baseRef } });
    } else {
      orgEntry = await prisma.transaction.findFirst({
        where: {
          bookId: txn.orgFundId || undefined,
          clientRef: txn.clientRef || undefined,
          amount: txn.amount,
          createdById: txn.createdById,
        },
      });
    }
  } else if (!resolvedBook.organization?.isPersonal) {
    orgEntry = txn;
    personalEntry = await findCreatorPersonalMirror(txn);
    if (!personalEntry && txn.orgFundId) {
      personalEntry = await prisma.transaction.findFirst({
        where: { orgFundId: txn.orgFundId, amount: txn.amount, createdById: txn.createdById },
      });
    }
  }

  if (personalEntry || orgEntry) {
    const orgBookId = orgEntry?.bookId || txn.orgFundId || resolvedBook.id;
    const orgBook = orgBookId
      ? await prisma.book.findUnique({ where: { id: orgBookId }, include: { organization: true } })
      : null;
    const org = orgBook?.organizationId
      ? await prisma.organization.findUnique({ where: { id: orgBook.organizationId } })
      : null;
    const orgAdminIds = org ? await getOrgAdminUserIds(orgBook.organizationId) : [];

    return {
      kind: 'p1_org',
      p1: {
        userId: p1UserId,
        active: await userStillActive(p1UserId),
        hasEntry: !!personalEntry?.id,
      },
      org: {
        active: !!org,
        hasEntry: !!orgEntry?.id && !!org,
        adminIds: orgAdminIds,
      },
    };
  }

  const linked = txn.linkedTransactionId
    ? await prisma.transaction.findUnique({ where: { id: txn.linkedTransactionId } })
    : null;
  const partyA = txn.createdById;
  const partyB = txn.recipientUserId || linked?.recipientUserId || linked?.createdById;

  if (linked || txn.recipientUserId) {
    return {
      kind: 'p1_p2',
      p1: { userId: partyA, active: await userStillActive(partyA), hasEntry: !!txn?.id },
      p2: { userId: partyB, active: await userStillActive(partyB), hasEntry: !!linked?.id },
    };
  }

  return { kind: 'solo' };
};

const getLinkedPartyUserIds = async (txn, book) => {
  const chain = await resolveChangeDeleteChain(txn, book);
  if (chain.kind === 'p1_org_p2') {
    return [...new Set([chain.p1.userId, chain.p2.userId, ...chain.org.adminIds].filter(Boolean))];
  }
  if (chain.kind === 'p1_org') {
    return [...new Set([chain.p1.userId, ...chain.org.adminIds].filter(Boolean))];
  }
  if (chain.kind === 'p1_p2') {
    return [...new Set([chain.p1.userId, chain.p2.userId].filter(Boolean))];
  }
  return txn.createdById ? [txn.createdById] : [];
};

const getRequiredApproversForChangeDelete = async (txn, book, requesterId) => {
  const chain = await resolveChangeDeleteChain(txn, book);
  return computeRequiredApprovers(chain, requesterId).requiredApprovers;
};

const isChangeDeleteFullyApproved = (pendingData) => {
  const pd = parsePendingData(pendingData);
  const required = pd.requiredApprovers || [];
  const orgAnyOf = pd.orgApprovalAnyOf || [];
  const approvals = pd.approvals || [];
  if (required.length === 0) return true;

  const nonOrgRequired = required.filter((id) => !orgAnyOf.includes(id));
  const orgRequired = required.some((id) => orgAnyOf.includes(id));
  const peopleOk = nonOrgRequired.every((id) => approvals.includes(id));
  const orgOk = !orgRequired || orgAnyOf.some((id) => approvals.includes(id));
  return peopleOk && orgOk;
};

const recordChangeDeleteApproval = (pendingData, approverId) => {
  const pd = parsePendingData(pendingData);
  const approvals = [...(pd.approvals || [])];
  if (!approvals.includes(approverId)) approvals.push(approverId);
  return { ...pd, approvals };
};

const buildChangeDeletePendingData = async (txn, book, requesterId, baseData = {}) => {
  const chain = await resolveChangeDeleteChain(txn, book);
  const { requiredApprovers, orgApprovalAnyOf, chainNote, isOrphan } = computeRequiredApprovers(chain, requesterId);
  const partyIds = await getLinkedPartyUserIds(txn, book);
  const requester = await prisma.user.findUnique({ where: { id: requesterId }, select: { name: true } });
  return {
    ...baseData,
    requestedBy: requesterId,
    requesterName: requester?.name || 'Unknown',
    requiredApprovers,
    orgApprovalAnyOf,
    approvals: [],
    partyCount: partyIds.length,
    requiredApprovalCount: requiredApprovers.length,
    chainNote,
    isOrphan: !!isOrphan,
  };
};

const buildChangeDeleteNotification = (pendingData, pendingAction, txn) => {
  const pd = parsePendingData(pendingData);
  const requester = pd.requesterName || 'Someone';
  const required = pd.requiredApprovalCount ?? (pd.requiredApprovers || []).length;
  const approved = (pd.approvals || []).length;
  const progress = required > 0 ? `${approved}/${required}` : null;

  if (pendingAction === 'delete') {
    const amount = pd.oldAmount ?? txn?.amount;
    const note = pd.oldNote ?? txn?.note ?? '';
    if (pd.isOrphan || required === 0) {
      return {
        bn: `${requester} ৳${amount} লেনদেন মুছতে চাচ্ছেন${note ? ` (“${note}”)` : ''}। বিপরীত পক্ষ/এন্ট্রি নেই — অনুমোদন লাগবে না।`,
        en: `${requester} wants to delete ৳${amount}${note ? ` ("${note}")` : ''}. Counterparty entry missing — no approval needed.`,
        shortBn: `মুছে ফেলা (অরফান): ৳${amount}${note ? ` — ${note}` : ''}`,
        shortEn: `Delete (orphan): ৳${amount}${note ? ` — ${note}` : ''}`,
        progress: null,
      };
    }
    return {
      bn: `${requester} ৳${amount} লেনদেন মুছতে চাচ্ছেন${note ? ` (“${note}”)` : ''}। ${required} জনের অনুমোদন লাগবে${progress ? ` (${progress})` : ''}।`,
      en: `${requester} wants to delete ৳${amount}${note ? ` ("${note}")` : ''}. Needs ${required} approval(s)${progress ? ` (${progress})` : ''}.`,
      shortBn: `মুছে ফেলা: ৳${amount}${note ? ` — ${note}` : ''}`,
      shortEn: `Delete: ৳${amount}${note ? ` — ${note}` : ''}`,
      progress,
    };
  }

  const oldAmount = pd.oldAmount ?? txn?.amount;
  const newAmount = pd.newAmount ?? txn?.amount;
  const oldNote = pd.oldNote ?? txn?.note ?? '';
  const newNote = pd.newNote ?? txn?.note ?? '';
  const changes = [];
  if (oldAmount != null && newAmount != null && oldAmount !== newAmount) {
    changes.push(`৳${oldAmount} → ৳${newAmount}`);
  }
  if (oldNote !== newNote) {
    changes.push(`“${oldNote || '—'}” → “${newNote || '—'}”`);
  }
  const changeText = changes.length > 0 ? changes.join(', ') : 'details updated';
  if (pd.isOrphan || required === 0) {
    return {
      bn: `${requester} লেনদেন সম্পাদন করতে চাচ্ছেন: ${changeText}। বিপরীত পক্ষ/এন্ট্রি নেই — অনুমোদন লাগবে না।`,
      en: `${requester} wants to edit: ${changeText}. Counterparty entry missing — no approval needed.`,
      shortBn: `সম্পাদনা (অরফান): ${changeText}`,
      shortEn: `Edit (orphan): ${changeText}`,
      progress: null,
      oldAmount,
      newAmount,
      oldNote,
      newNote,
    };
  }
  return {
    bn: `${requester} লেনদেন সম্পাদন করতে চাচ্ছেন: ${changeText}। ${required} জনের অনুমোদন লাগবে${progress ? ` (${progress})` : ''}।`,
    en: `${requester} wants to edit: ${changeText}. Needs ${required} approval(s)${progress ? ` (${progress})` : ''}.`,
    shortBn: `সম্পাদনা: ${changeText}`,
    shortEn: `Edit: ${changeText}`,
    progress,
    oldAmount,
    newAmount,
    oldNote,
    newNote,
  };
};

const notifyChangeDeleteApprovers = async (txn, pendingAction, pendingData) => {
  const pd = parsePendingData(pendingData);
  const approverIds = new Set([
    ...(pd.requiredApprovers || []).filter((id) => !(pd.approvals || []).includes(id)),
    ...(pd.orgApprovalAnyOf || []).filter((id) => !(pd.approvals || []).includes(id)),
  ]);
  if (approverIds.size === 0) return;
  const summary = buildChangeDeleteNotification(pendingData, pendingAction, txn);
  broadcastToUsers([...approverIds], {
    type: 'change_delete_request',
    pendingAction,
    transactionId: txn.id,
    message: summary,
  });
};

const getUserPersonalBook = async (userId, txClient = prisma) => {
  const membership = await txClient.organizationMember.findFirst({
    where: { userId, status: 'active', organization: { isPersonal: true } },
    include: { organization: { include: { books: { where: { isDefault: true }, take: 1 } } } }
  });
  return membership?.organization?.books?.[0] || null;
};

const createCreatorPersonalMirror = async (tx, {
  orgTxn,
  orgBook,
  creatorPersonalBook,
  userId,
  txnClientRef,
  mirrorType
}) => {
  if (!creatorPersonalBook || creatorPersonalBook.id === orgBook.id) return null;

  const type = mirrorType || orgTxn.type;
  const orgLabel = orgBook.name || 'org';
  const note = type === 'income'
    ? (orgTxn.note ? `${orgTxn.note} [${orgLabel}]` : `[${orgLabel}]`)
    : (orgTxn.note ? `${orgTxn.note} [${orgLabel}]` : `[${orgLabel}]`);

  const mirror = await tx.transaction.create({
    data: {
      bookId: creatorPersonalBook.id,
      amount: orgTxn.amount,
      type,
      note,
      category: orgTxn.category,
      contact: orgTxn.contact,
      recipientUserId: orgTxn.recipientUserId || null,
      recipientOrgId: orgTxn.recipientOrgId || null,
      orgFundId: orgBook.id,
      createdById: userId,
      reconStatus: orgTxn.reconStatus,
      imageUrl: orgTxn.imageUrl,
      clientRef: txnClientRef + CREATOR_PERSONAL_MIRROR_SUFFIX,
      chainId: orgTxn.chainId || null,
      chainType: orgTxn.chainType || null
    }
  });

  const balanceOp = type === 'income' ? { increment: orgTxn.amount } : { decrement: orgTxn.amount };
  await tx.book.update({ where: { id: creatorPersonalBook.id }, data: { balance: balanceOp } });
  return mirror;
};

const maybeMirrorOrgTxnToCreatorPersonal = async (tx, {
  orgTxn,
  orgBook,
  userId,
  txnClientRef,
  mirrorType,
  skipMirror = false
}) => {
  if (skipMirror || orgTxn.type !== 'expense' || orgBook.organization?.isPersonal) return null;
  if (!(await hasAdminOrEditorAccess(orgBook.organizationId, userId))) return null;
  const personalBook = await getUserPersonalBook(userId, tx);
  if (!personalBook) return null;
  return createCreatorPersonalMirror(tx, {
    orgTxn,
    orgBook,
    creatorPersonalBook: personalBook,
    userId,
    txnClientRef,
    mirrorType
  });
};

const syncCreatorPersonalMirrorStatus = async (tx, orgTxn, status, historyEntry, extraData = {}) => {
  const mirror = await findCreatorPersonalMirror(orgTxn, tx);
  if (!mirror) return;
  const cur = await tx.transaction.findUnique({
    where: { id: mirror.id },
    select: { version: true, updateHistory: true }
  });
  if (!cur) return;
  const data = {
    reconStatus: status,
    version: { increment: 1 },
    ...extraData
  };
  if (historyEntry) {
    data.updateHistory = [...(cur.updateHistory || []), historyEntry];
  }
  await tx.transaction.updateMany({
    where: { id: mirror.id, version: cur.version },
    data
  });
};

const rejectCreatorPersonalMirror = async (tx, orgTxn, rejectHistoryEntry) => {
  const mirror = await findCreatorPersonalMirror(orgTxn, tx);
  if (!mirror || mirror.reconStatus === 'rejected') return;
  const cur = await tx.transaction.findUnique({
    where: { id: mirror.id },
    select: { version: true, updateHistory: true }
  });
  if (!cur) return;
  await tx.transaction.updateMany({
    where: { id: mirror.id, version: cur.version },
    data: {
      reconStatus: 'rejected',
      version: { increment: 1 },
      updateHistory: [...(cur.updateHistory || []), rejectHistoryEntry]
    }
  });
  const balanceAdj = mirror.type === 'expense' ? mirror.amount : -mirror.amount;
  await tx.book.update({
    where: { id: mirror.bookId },
    data: { balance: { increment: balanceAdj } }
  });
};

const resolveOrgSourceTxnForMirror = async (txn, txClient = prisma) => {
  const isRealOrgBook = async (bookId) => {
    const b = await txClient.book.findUnique({
      where: { id: bookId },
      include: { organization: { select: { isPersonal: true } } }
    });
    return b && !b.organization.isPersonal;
  };
  if (txn.type === 'expense' && await isRealOrgBook(txn.bookId)) return txn;
  if (txn.linkedTransactionId) {
    const linked = await txClient.transaction.findUnique({ where: { id: txn.linkedTransactionId } });
    if (linked?.type === 'expense' && await isRealOrgBook(linked.bookId)) return linked;
  }
  return null;
};

// Find mirror transaction in parent book for sub-book sync
const findMirrorTxn = async (txn, book) => {
  if (!book.parentBookId) return null;
  // First try by clientRef
  if (txn.clientRef) {
    const mirror = await prisma.transaction.findFirst({
      where: { bookId: book.parentBookId, clientRef: txn.clientRef }
    });
    if (mirror) return mirror;
  }
  // Fallback: match by attributes (amount, type, and sourceSubBookId)
  return prisma.transaction.findFirst({
    where: {
      bookId: book.parentBookId,
      amount: txn.amount,
      type: txn.type,
      sourceSubBookId: txn.bookId,
      note: { contains: `[${book.name}]` }
    }
  });
};

// Generate a UUID-like chain ID
const generateChainId = () => {
  return 'chain_' + Date.now().toString(36) + '_' + Math.random().toString(36).substring(2, 10);
};

// All transactions in a personal Send + org-fund triple entry (chainType fund_send)
const getFundSendChain = async (txn, txClient = prisma) => {
  if (txn.chainType === 'fund_send' && txn.chainId) {
    return txClient.transaction.findMany({ where: { chainId: txn.chainId } });
  }
  return null;
};

const syncFundSendChainStatus = async (tx, txn, status, historyEntry, extraData = {}) => {
  const chain = await getFundSendChain(txn, tx);
  if (!chain) return false;
  for (const t of chain) {
    const cur = await tx.transaction.findUnique({
      where: { id: t.id },
      select: { version: true, updateHistory: true }
    });
    if (!cur) throw new Error('Chain transaction not found');
    const data = {
      reconStatus: status,
      version: { increment: 1 },
      ...extraData
    };
    if (historyEntry) {
      data.updateHistory = [...(cur.updateHistory || []), historyEntry];
    }
    const upd = await tx.transaction.updateMany({
      where: { id: t.id, version: cur.version },
      data
    });
    if (upd.count === 0) throw new Error(`Concurrency conflict on fund_send chain ${t.id}`);
  }
  return true;
};

const rejectFundSendChain = async (tx, txn, rejectHistoryEntry) => {
  const chain = await getFundSendChain(txn, tx);
  if (!chain) return false;
  for (const ct of chain) {
    if (ct.reconStatus === 'rejected') continue;
    const cur = await tx.transaction.findUnique({
      where: { id: ct.id },
      select: { version: true, updateHistory: true }
    });
    if (!cur) throw new Error('Chain transaction not found');
    const upd = await tx.transaction.updateMany({
      where: { id: ct.id, version: cur.version },
      data: {
        reconStatus: 'rejected',
        pendingAction: null,
        pendingData: null,
        counterProposedAmount: null,
        counterProposedBy: null,
        version: { increment: 1 },
        updateHistory: [...(cur.updateHistory || []), rejectHistoryEntry]
      }
    });
    if (upd.count === 0) throw new Error('Concurrency conflict on fund_send reject');
    const balanceAdj = ct.type === 'expense' ? ct.amount : -ct.amount;
    await tx.book.update({
      where: { id: ct.bookId },
      data: { balance: { increment: balanceAdj } }
    });
  }
  return true;
};

const resolveFundSendChainParts = (chain) => {
  const recipientTxn = chain.find(t => t.type === 'income');
  const fundOrgTxn = chain.find(t => t.type === 'expense' && t.bookId === t.orgFundId);
  const personalTxn = chain.find(t => t.type === 'expense' && t.id !== fundOrgTxn?.id);
  return { personalTxn, fundOrgTxn, recipientTxn };
};

const updateFundSendTxnStatus = async (tx, t, status, historyEntry, extraData = {}) => {
  const cur = await tx.transaction.findUnique({
    where: { id: t.id },
    select: { version: true, updateHistory: true }
  });
  if (!cur) throw new Error('Chain transaction not found');
  const data = {
    reconStatus: status,
    version: { increment: 1 },
    ...extraData
  };
  if (historyEntry) {
    data.updateHistory = [...(cur.updateHistory || []), historyEntry];
  }
  const upd = await tx.transaction.updateMany({
    where: { id: t.id, version: cur.version },
    data
  });
  if (upd.count === 0) throw new Error(`Concurrency conflict on fund_send update ${t.id}`);
};

// Org approved on fund_send — recipient may have already accepted (parallel flow)
const approveFundSendOrg = async (tx, txn, approveHistoryEntry) => {
  const chain = await getFundSendChain(txn, tx);
  if (!chain) return null;
  const { personalTxn, fundOrgTxn, recipientTxn } = resolveFundSendChainParts(chain);
  const clearCounter = { counterProposedAmount: null, counterProposedBy: null };

  if (recipientTxn?.reconStatus === 'pending_org') {
    for (const t of chain) {
      await updateFundSendTxnStatus(tx, t, 'approved', approveHistoryEntry, clearCounter);
    }
    return { final: true };
  }

  for (const t of [personalTxn, fundOrgTxn, recipientTxn]) {
    if (!t) continue;
    await updateFundSendTxnStatus(tx, t, 'pending_recipient', approveHistoryEntry, clearCounter);
  }
  return { final: false };
};

// Recipient accepted on fund_send — org may still be pending (parallel flow)
const approveFundSendRecipient = async (tx, txn, approveHistoryEntry) => {
  const chain = await getFundSendChain(txn, tx);
  if (!chain) return null;
  const { personalTxn, fundOrgTxn, recipientTxn } = resolveFundSendChainParts(chain);
  const clearCounter = { counterProposedAmount: null, counterProposedBy: null };
  const orgStillPending =
    personalTxn?.reconStatus === 'pending_org' || fundOrgTxn?.reconStatus === 'pending_org';

  if (orgStillPending && recipientTxn) {
    await updateFundSendTxnStatus(tx, recipientTxn, 'pending_org', approveHistoryEntry, clearCounter);
    return { final: false };
  }

  for (const t of chain) {
    await updateFundSendTxnStatus(tx, t, 'approved', approveHistoryEntry, clearCounter);
  }
  return { final: true };
};

const fundSendRetryStatuses = (bypassOrgApproval, isSelfSend) => {
  if (isSelfSend && bypassOrgApproval) {
    return { personal: 'approved', fundOrg: 'approved', recipient: 'approved' };
  }
  if (bypassOrgApproval) {
    return { personal: 'pending_recipient', fundOrg: 'pending_recipient', recipient: 'pending_recipient' };
  }
  return { personal: 'pending_org', fundOrg: 'pending_org', recipient: 'pending_recipient' };
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
  } else if (txn.recipientOrgId) {
    const org = await prisma.organization.findUnique({ where: { id: txn.recipientOrgId }, select: { name: true } });
    recipientName = org?.name || null;
  }
  let fundName = null;
  if (txn.orgFundId) {
    const fundTxn = await prisma.transaction.findUnique({ where: { id: txn.orgFundId } });
    if (fundTxn) {
      if (fundTxn.linkedTransactionId) {
        const orgTxn = await prisma.transaction.findUnique({ where: { id: fundTxn.linkedTransactionId }, include: { book: { include: { organization: { select: { name: true } } } } } });
        fundName = orgTxn?.book?.organization?.name || null;
      }
    } else {
      const fundBook = await prisma.book.findUnique({ where: { id: txn.orgFundId }, include: { organization: true } });
      fundName = fundBook?.organization?.name || null;
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

  let approverName = null;
  let approverAvatarUrl = null;
  let rejecterName = null;
  let rejecterAvatarUrl = null;

  if (txn.updateHistory && Array.isArray(txn.updateHistory)) {
    const approveAction = [...txn.updateHistory].reverse().find(h => h && h.action === 'approve');
    if (approveAction) {
      approverName = approveAction.userName || 'Unknown';
      if (approveAction.userId) {
        const u = await prisma.user.findUnique({ where: { id: approveAction.userId }, select: { avatarUrl: true } });
        approverAvatarUrl = u?.avatarUrl || null;
      }
    }
    const rejectAction = [...txn.updateHistory].reverse().find(h => h && h.action === 'reject');
    if (rejectAction) {
      rejecterName = rejectAction.userName || 'Unknown';
      if (rejectAction.userId) {
        const u = await prisma.user.findUnique({ where: { id: rejectAction.userId }, select: { avatarUrl: true } });
        rejecterAvatarUrl = u?.avatarUrl || null;
      }
    }
  }

  return {
    ...txn,
    recipientName,
    fundName,
    creatorName,
    creatorAvatarUrl,
    approverName,
    approverAvatarUrl,
    rejecterName,
    rejecterAvatarUrl,
    chainId: txn.chainId,
    chainType: txn.chainType,
    isLiability: txn.isLiability,
    adjustedAmount: txn.adjustedAmount
  };
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
        categories: DEFAULT_CATEGORIES,
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

// ─────────────────────────────────────────────────────────────────────────────
// USER AI CONFIG — per-account cloud storage for AI agent
// ─────────────────────────────────────────────────────────────────────────────
const AI_CONFIG_PROVIDERS = new Set(['gemini', 'openai', 'claude']);

function normalizeAiConfigPayload(body = {}) {
  const provider = typeof body.provider === 'string' ? body.provider.trim().toLowerCase() : '';
  const apiKey = typeof body.apiKey === 'string' ? body.apiKey.trim() : '';
  const selectedModel = typeof body.selectedModel === 'string' ? body.selectedModel.trim() : '';
  const workingModels = Array.isArray(body.workingModels)
    ? body.workingModels.map((m) => String(m).trim()).filter(Boolean)
    : [];
  const baseUrl = typeof body.baseUrl === 'string' ? body.baseUrl.trim() : '';
  const temperature = body.temperature != null ? parseFloat(body.temperature) : 0.7;
  const maxTokens = body.maxTokens != null ? parseInt(body.maxTokens, 10) : 2048;

  if (!AI_CONFIG_PROVIDERS.has(provider)) {
    return { error: 'Invalid provider. Use gemini, openai, or claude.' };
  }
  if (!apiKey) {
    return { error: 'API key is required' };
  }
  if (!selectedModel && workingModels.length === 0) {
    return { error: 'At least one model must be configured' };
  }

  return {
    config: {
      provider,
      apiKey,
      selectedModel: selectedModel || workingModels[0],
      workingModels,
      baseUrl,
      temperature: Number.isFinite(temperature) ? temperature : 0.7,
      maxTokens: Number.isFinite(maxTokens) ? maxTokens : 512,
      updatedAt: new Date().toISOString(),
    },
  };
}

async function loadUserAiConfig(userId) {
  const user = await prisma.user.findUnique({
    where: { id: userId },
    select: { aiConfig: true },
  });
  return user?.aiConfig || null;
}

function resolveAiRequestConfig(body, storedConfig) {
  const cfg = storedConfig && typeof storedConfig === 'object' ? storedConfig : {};
  return {
    provider: body.provider || cfg.provider,
    apiKey: body.apiKey || cfg.apiKey,
    model: body.model || cfg.selectedModel,
    baseUrl: body.baseUrl || cfg.baseUrl || null,
    temperature: body.temperature != null ? parseFloat(body.temperature) : cfg.temperature,
    maxTokens: body.maxTokens != null ? parseInt(body.maxTokens, 10) : cfg.maxTokens,
  };
}

app.get('/api/user/ai-config', authenticateToken, async (req, res) => {
  try {
    const cfg = await loadUserAiConfig(req.user.id);
    if (!cfg || !cfg.apiKey) {
      return res.json({ configured: false, config: null });
    }
    return res.json({ configured: true, config: cfg });
  } catch (error) {
    console.error('[AI Config] Fetch error:', error);
    res.status(500).json({ error: 'Server error fetching AI configuration' });
  }
});

app.put('/api/user/ai-config', authenticateToken, async (req, res) => {
  try {
    const normalized = normalizeAiConfigPayload(req.body);
    if (normalized.error) {
      return res.status(400).json({ error: normalized.error });
    }

    await prisma.user.update({
      where: { id: req.user.id },
      data: { aiConfig: normalized.config },
    });

    res.json({ message: 'AI configuration saved', config: normalized.config });
  } catch (error) {
    console.error('[AI Config] Save error:', error);
    res.status(500).json({ error: 'Server error saving AI configuration' });
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
        id: { not: req.user.id },
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
      where: {
        userId: req.user.id,
        status: 'active',
        organization: { isPersonal: false }
      },
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
    const pendingMemberships = user.memberships.filter(m => m.status === 'pending');

    const orgIds = activeMemberships.map(m => m.organizationId);
    const books = await prisma.book.findMany({
      where: { organizationId: { in: orgIds } },
      include: { organization: { select: { id: true, name: true, isPersonal: true, imageUrl: true } } }
    });

    const booksWithRole = books.map(book => {
      const membership = activeMemberships.find(m => m.organizationId === book.organizationId);
      return {
        ...book,
        role: membership?.role || 'member',
        permissions: membership?.permissions || [],
        status: 'active'
      };
    });

    // Include mock pending books for pending memberships so they show in the list with a pending state
    const pendingOrgIds = pendingMemberships.map(m => m.organizationId);
    const pendingOrgs = pendingOrgIds.length > 0 ? await prisma.organization.findMany({
      where: { id: { in: pendingOrgIds } },
      select: { id: true, name: true, imageUrl: true, isPersonal: true }
    }) : [];

    const pendingBooks = pendingOrgs.map(org => ({
      id: `pending_${org.id}`,
      name: org.name,
      organizationId: org.id,
      organization: { id: org.id, name: org.name, isPersonal: org.isPersonal, imageUrl: org.imageUrl },
      role: 'member',
      permissions: [],
      balance: 0.0,
      isDefault: false,
      parentBookId: null,
      status: 'pending'
    }));

    res.json([...booksWithRole, ...pendingBooks]);
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

// Create Transaction (supports org fund handshake for "Send" category and book-based vouchers)
app.post('/api/transactions', authenticateToken, async (req, res) => {
  try {
    const { bookId, amount, type, note, category, contact, recipientUserId, recipientOrgId, orgFundId, imageUrl, clientRef } = req.body;

    if (!bookId || !amount || !type) {
      return res.status(400).json({ error: 'BookId, amount, and type are required' });
    }

    const parsedAmount = parseFloat(amount);
    if (!parsedAmount || parsedAmount <= 0) {
      return res.status(400).json({ error: 'Amount must be a positive number' });
    }

    const txnClientRef = clientRef || 'cr_' + Date.now() + '_' + Math.random().toString(36).substring(2, 10);
    const isSend = type === 'expense' && category === 'Send';
    const isOrgSend = isSend && !!recipientOrgId;
    const isVoucher = !!orgFundId;

    const book = await prisma.book.findUnique({ where: { id: bookId }, include: { organization: { select: { isPersonal: true } } } });
    if (!book) {
      return res.status(404).json({ error: 'Ledger book not found' });
    }

    if (!(await hasBookAccess(book, req.user.id))) {
      return res.status(403).json({ error: 'Not authorized to use this book' });
    }

    if (!book.organization.isPersonal && !(await hasAdminOrEditorAccess(book.organizationId, req.user.id))) {
      return res.status(403).json({
        error: 'Members must record org expenses from their personal book with an org fund selected'
      });
    }

    // Org book: Send-only for expense. Other categories → personal book + org fund.
    if (!book.organization.isPersonal && type === 'expense' && category !== 'Send') {
      return res.status(400).json({
        error: 'Organization books only support Send for expenses. Use your personal book with this organization as fund for other categories.'
      });
    }

    // --- ORG-TO-ORG SEND FLOW (expense with category "Send" + recipientOrgId) ---
    if (isOrgSend) {
      const recipientBook = await prisma.book.findFirst({
        where: { organizationId: recipientOrgId, isDefault: true }
      });
      if (!recipientBook) {
        return res.status(400).json({ error: 'Recipient organization has no default book' });
      }

      // Determine bypass status for source and destination orgs
      const bypassSourceOrgApproval = await checkApprovalBypass(book.organizationId, req.user.id);
      const bypassRecipientOrgApproval = await checkApprovalBypass(recipientOrgId, req.user.id);

      const initialStatus = !bypassSourceOrgApproval
        ? 'pending_org'
        : (!bypassRecipientOrgApproval ? 'pending_recipient' : 'approved');

      const result = await prisma.$transaction(async (prisma) => {
        const sourceTxn = await prisma.transaction.create({
          data: {
            bookId,
            amount: parsedAmount,
            type: 'expense',
            note: note || `Transfer to organization`,
            category: 'Send',
            contact,
            recipientOrgId,
            createdById: req.user.id,
            reconStatus: initialStatus,
            imageUrl,
            clientRef: txnClientRef
          }
        });
        const recipientTxn = await prisma.transaction.create({
          data: {
            bookId: recipientBook.id,
            amount: parsedAmount,
            type: 'income',
            note: 'Org fund transfer: ' + (note || ''),
            category: 'Send',
            contact,
            recipientOrgId: book.organizationId,
            createdById: req.user.id,
            reconStatus: initialStatus,
            imageUrl,
            clientRef: txnClientRef
          }
        });

        await prisma.book.update({ where: { id: bookId }, data: { balance: { decrement: parsedAmount } } });
        await prisma.book.update({ where: { id: recipientBook.id }, data: { balance: { increment: parsedAmount } } });
        await prisma.transaction.update({ where: { id: sourceTxn.id }, data: { linkedTransactionId: recipientTxn.id } });
        await prisma.transaction.update({ where: { id: recipientTxn.id }, data: { linkedTransactionId: sourceTxn.id } });
        await maybeMirrorOrgTxnToCreatorPersonal(prisma, {
          orgTxn: sourceTxn,
          orgBook: book,
          userId: req.user.id,
          txnClientRef
        });
        return sourceTxn;
      });

      broadcast({ type: "data_changed" });
      const enriched = await enrichTxn(result);

      if (initialStatus === 'pending_recipient') {
        const recipientAdmins = await prisma.organizationMember.findMany({
          where: { organizationId: recipientOrgId, status: 'active', OR: [{ role: 'admin' }, { permissions: { has: 'edit_all' } }] },
          select: { userId: true }
        });
        const adminIds = recipientAdmins.map(a => a.userId);
        broadcastToUsers(adminIds, { type: "pending_send_received", transaction: enriched });
      }

      return res.status(201).json({ transaction: enriched, isHandshake: true, approvalBypassed: bypassSourceOrgApproval && bypassRecipientOrgApproval });
    }

    // --- PERSONAL FUNDED SEND (personal book + Send + org fund book + recipient) ---
    if (isSend && book.organization.isPersonal && orgFundId && (recipientUserId || recipientOrgId)) {
      const fundBook = await prisma.book.findUnique({
        where: { id: orgFundId },
        include: { organization: { select: { isPersonal: true, id: true } } }
      });
      const isFundOrgBook = fundBook && !fundBook.organization.isPersonal && fundBook.id !== bookId;

      if (isFundOrgBook) {
        let recipientBook = null;
        if (recipientUserId) {
          const recipientMembership = await prisma.organizationMember.findFirst({
            where: { userId: recipientUserId, organization: { isPersonal: true } },
            include: { organization: { include: { books: { where: { isDefault: true } } } } }
          });
          if (!recipientMembership || recipientMembership.organization.books.length === 0) {
            return res.status(400).json({ error: 'Recipient has no personal book' });
          }
          recipientBook = recipientMembership.organization.books[0];
        } else {
          recipientBook = await prisma.book.findFirst({
            where: { organizationId: recipientOrgId, isDefault: true }
          });
          if (!recipientBook) {
            return res.status(400).json({ error: 'Recipient organization has no default book' });
          }
        }

        const bypassFundOrgApproval = await checkApprovalBypass(fundBook.organizationId, req.user.id);
        const isSelfSend = recipientUserId === req.user.id;
        const retryStatuses = fundSendRetryStatuses(bypassFundOrgApproval, isSelfSend);
        const personalStatus = retryStatuses.personal;
        const fundOrgStatus = retryStatuses.fundOrg;
        const recipientStatus = retryStatuses.recipient;

        const chainId = generateChainId();
        const chainType = 'fund_send';

        const result = await prisma.$transaction(async (prisma) => {
          const personalTxn = await prisma.transaction.create({
            data: {
              bookId,
              amount: parsedAmount,
              type: 'expense',
              note: note || '',
              category: 'Send',
              contact,
              recipientUserId: recipientUserId || null,
              recipientOrgId: recipientOrgId || null,
              orgFundId: fundBook.id,
              createdById: req.user.id,
              reconStatus: personalStatus,
              imageUrl,
              chainId,
              chainType,
              clientRef: txnClientRef
            }
          });

          const fundOrgTxn = await prisma.transaction.create({
            data: {
              bookId: fundBook.id,
              amount: parsedAmount,
              type: 'expense',
              note: note ? `${note} (fund send)` : 'Fund send',
              category: 'Send',
              contact,
              recipientUserId: recipientUserId || null,
              recipientOrgId: recipientOrgId || null,
              orgFundId: fundBook.id,
              createdById: req.user.id,
              reconStatus: fundOrgStatus,
              imageUrl,
              chainId,
              chainType,
              clientRef: txnClientRef,
              linkedTransactionId: personalTxn.id
            }
          });

          const recipientTxn = await prisma.transaction.create({
            data: {
              bookId: recipientBook.id,
              amount: parsedAmount,
              type: 'income',
              note: recipientUserId
                ? `Org fund send: ${note || ''}`
                : `Org fund transfer: ${note || ''}`,
              category: 'Send',
              contact,
              recipientUserId: recipientUserId ? req.user.id : null,
              recipientOrgId: recipientOrgId ? fundBook.organizationId : null,
              orgFundId: fundBook.id,
              createdById: req.user.id,
              reconStatus: recipientStatus,
              imageUrl,
              chainId,
              chainType,
              clientRef: txnClientRef
            }
          });

          await prisma.book.update({ where: { id: bookId }, data: { balance: { decrement: parsedAmount } } });
          await prisma.book.update({ where: { id: fundBook.id }, data: { balance: { decrement: parsedAmount } } });
          await prisma.book.update({ where: { id: recipientBook.id }, data: { balance: { increment: parsedAmount } } });

          await prisma.transaction.update({
            where: { id: personalTxn.id },
            data: { linkedTransactionId: recipientTxn.id }
          });
          await prisma.transaction.update({
            where: { id: recipientTxn.id },
            data: { linkedTransactionId: personalTxn.id }
          });

          return personalTxn;
        });

        broadcast({ type: 'data_changed' });
        const enriched = await enrichTxn(result);

        if (recipientStatus === 'pending_recipient' && !isSelfSend) {
          if (recipientUserId) {
            broadcastToUser(recipientUserId, { type: 'pending_send_received', transaction: enriched });
          } else if (recipientOrgId) {
            const recipientAdmins = await prisma.organizationMember.findMany({
              where: {
                organizationId: recipientOrgId,
                status: 'active',
                OR: [{ role: 'admin' }, { permissions: { has: 'edit_all' } }]
              },
              select: { userId: true }
            });
            broadcastToUsers(recipientAdmins.map(a => a.userId), {
              type: 'pending_send_received',
              transaction: enriched
            });
          }
        }

        return res.status(201).json({
          transaction: enriched,
          isHandshake: true,
          approvalBypassed: bypassFundOrgApproval
        });
      }
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
      let bypassOrgApproval = await checkApprovalBypass(book.organizationId, req.user.id);
      const isSelfSend = recipientUserId === req.user.id;
      const initialStatus = (isSelfSend && bypassOrgApproval) ? 'approved' : (bypassOrgApproval ? 'pending_recipient' : 'pending_org');

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

      // Customize source note for splits
      let sourceNote = note;
      if (orgFundId && fundTxnParent) {
        const senderName = req.user.name || 'A user';
        const recipientUser = await prisma.user.findUnique({ where: { id: recipientUserId }, select: { name: true } });
        const recipientName = recipientUser?.name || 'another member';
        const transferInfo = `Transferred to ${recipientName} from ${senderName}`;
        sourceNote = note ? `${note} (${transferInfo})` : transferInfo;
      }

      const result = await prisma.$transaction(async (prisma) => {
        const sourceTxn = await prisma.transaction.create({
          data: { bookId, amount: parsedAmount, type: 'expense', note: sourceNote, category: 'Send', contact, recipientUserId, createdById: req.user.id, reconStatus: initialStatus, imageUrl, chainId, chainType, orgFundId, clientRef: txnClientRef }
        });
        const recipientTxn = await prisma.transaction.create({
          data: { bookId: recipientBook.id, amount: parsedAmount, type: 'income', note: note || '', category: 'Send', contact, recipientUserId: req.user.id, linkedTransactionId: null, createdById: req.user.id, reconStatus: initialStatus, chainId, chainType }
        });
        await prisma.book.update({ where: { id: bookId }, data: { balance: { decrement: parsedAmount } } });
        await prisma.book.update({ where: { id: recipientBook.id }, data: { balance: { increment: parsedAmount } } });
        await prisma.transaction.update({ where: { id: sourceTxn.id }, data: { linkedTransactionId: recipientTxn.id } });
        await prisma.transaction.update({ where: { id: recipientTxn.id }, data: { linkedTransactionId: sourceTxn.id } });
        await maybeMirrorOrgTxnToCreatorPersonal(prisma, {
          orgTxn: sourceTxn,
          orgBook: book,
          userId: req.user.id,
          txnClientRef,
          skipMirror: isSelfSend
        });
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

      // Notify recipient immediately if org approval was bypassed (skip for already-approved self-sends)
      if (bypassOrgApproval && initialStatus !== 'approved') {
        broadcastToUser(recipientUserId, { type: "pending_send_received", transaction: enriched });
      }
      return res.status(201).json({ transaction: enriched, isHandshake: true, approvalBypassed: bypassOrgApproval });
    }

    // --- VOUCHER FLOW ---
    if (isVoucher) {
      let isVoucherTxn = false;
      let isVoucherBook = false;
      let targetBook = null;
      let origDisbursement = null;

      origDisbursement = await prisma.transaction.findUnique({ where: { id: orgFundId } });
      if (origDisbursement) {
        isVoucherTxn = true;
      } else {
        targetBook = await prisma.book.findUnique({ where: { id: orgFundId } });
        if (targetBook) {
          isVoucherBook = true;
        } else {
          return res.status(404).json({ error: 'Original disbursement or target book not found' });
        }
      }

      if (isVoucherTxn) {
        const origBook = await prisma.book.findUnique({ where: { id: origDisbursement.bookId } });
        if (!origBook || origBook.organizationId !== book.organizationId) {
          return res.status(400).json({ error: 'Voucher must reference a disbursement from the same organization' });
        }

        const bypass = await checkApprovalBypass(book.organizationId, req.user.id);
        const voucherStatus = bypass ? 'approved' : 'pending_org';

        const [txn, updatedBook] = await prisma.$transaction([
          prisma.transaction.create({ data: { bookId, amount: parsedAmount, type: 'expense', note, category, contact, orgFundId, createdById: req.user.id, reconStatus: voucherStatus, imageUrl, clientRef: txnClientRef } }),
          prisma.book.update({ where: { id: bookId }, data: { balance: { decrement: parsedAmount } } })
        ]);

        broadcast({ type: "data_changed" });
        const enriched = await enrichTxn(txn);
        return res.status(201).json({ transaction: enriched, book: updatedBook, isVoucher: true });
      }

      if (isVoucherBook) {
        const bypass = await checkApprovalBypass(targetBook.organizationId, req.user.id);
        const voucherStatus = bypass ? 'approved' : 'pending_org';

        const [txn, updatedBook] = await prisma.$transaction([
          prisma.transaction.create({
            data: {
              bookId,
              amount: parsedAmount,
              type: 'expense',
              note,
              category,
              contact,
              orgFundId, // Sangeet Academy Book ID
              createdById: req.user.id,
              reconStatus: voucherStatus,
              imageUrl,
              clientRef: txnClientRef
            }
          }),
          prisma.book.update({ where: { id: bookId }, data: { balance: { decrement: parsedAmount } } })
        ]);

        if (bypass) {
          // If bypassed immediately, apply the voucher expense in Sangeet Academy
          await prisma.$transaction([
            // Decrement Sangeet Academy's book balance
            prisma.book.update({ where: { id: targetBook.id }, data: { balance: { decrement: parsedAmount } } }),
            // Create an expense transaction in Sangeet Academy's book
            prisma.transaction.create({
              data: {
                bookId: targetBook.id,
                amount: parsedAmount,
                type: 'expense',
                note: note || '',
                category: category || 'Voucher',
                contact,
                orgFundId: targetBook.id,
                createdById: req.user.id,
                reconStatus: 'approved',
                clientRef: txnClientRef,
                imageUrl
              }
            })
          ]);
        }

        broadcast({ type: "data_changed" });
        const enriched = await enrichTxn(txn);
        return res.status(201).json({ transaction: enriched, book: await prisma.book.findUnique({ where: { id: bookId } }), isVoucher: true });
      }
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
    if (book.parentBookId) {
      const mirrorBalanceOp = type === 'income' ? { increment: parsedAmount } : { decrement: parsedAmount };
      const transactionResult = await prisma.$transaction(async (tx) => {
        const createdTxn = await tx.transaction.create({
          data: {
            bookId,
            amount: parsedAmount, type, note, category, contact,
            createdById: req.user.id, reconStatus: initialStatus, imageUrl, clientRef: txnClientRef
          }
        });
        await tx.book.update({ where: { id: bookId }, data: { balance: balanceOp } });
        await tx.book.update({ where: { id: book.parentBookId }, data: { balance: mirrorBalanceOp } });
        await tx.transaction.create({
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
            clientRef: txnClientRef
          }
        });
        await maybeMirrorOrgTxnToCreatorPersonal(tx, {
          orgTxn: createdTxn,
          orgBook: book,
          userId: req.user.id,
          txnClientRef
        });
        return createdTxn;
      });
      broadcast({ type: "data_changed" });
      const enriched = await enrichTxn(transactionResult);
      return res.status(201).json({ transaction: enriched, book: await prisma.book.findUnique({ where: { id: bookId } }), mirrorBook: await prisma.book.findUnique({ where: { id: book.parentBookId } }) });
    }

    const createResult = await prisma.$transaction(async (tx) => {
      const transaction = await tx.transaction.create({
        data: { bookId, amount: parsedAmount, type, note, category, contact, createdById: req.user.id, reconStatus: initialStatus, imageUrl, clientRef: txnClientRef }
      });
      await tx.book.update({ where: { id: bookId }, data: { balance: balanceOp } });
      await maybeMirrorOrgTxnToCreatorPersonal(tx, {
        orgTxn: transaction,
        orgBook: book,
        userId: req.user.id,
        txnClientRef
      });
      const updatedBook = await tx.book.findUnique({ where: { id: bookId } });
      return { transaction, updatedBook };
    });

    broadcast({ type: "data_changed" });
    const enriched = await enrichTxn(createResult.transaction);
    res.status(201).json({ transaction: enriched, book: createResult.updatedBook });
  } catch (error) {
    console.error('Create transaction error:', error);
    res.status(500).json({ error: 'Server error creating transaction' });
  }
});

// --- EDIT TRANSACTION ---
app.put('/api/transactions/:id', authenticateToken, async (req, res) => {
  try {
    const { amount, type, note, category, contact, recipientUserId, imageUrl, orgFundId } = req.body;
    const txnId = req.params.id;

    const txn = await prisma.transaction.findUnique({ where: { id: txnId } });
    if (!txn) return res.status(404).json({ error: 'Transaction not found' });

    const book = await prisma.book.findUnique({ where: { id: txn.bookId }, include: { organization: { select: { isPersonal: true } } } });
    if (!book) return res.status(404).json({ error: 'Book not found' });

    if (!(await hasAdminOrEditorAccess(book.organizationId, req.user.id))) {
      return res.status(403).json({ error: 'Only admins or editors can edit transactions' });
    }

    const finalType = type !== undefined ? type : txn.type;
    const finalCategory = category !== undefined ? category : txn.category;
    if (!book.organization.isPersonal && finalType === 'expense' && finalCategory !== 'Send') {
      return res.status(400).json({
        error: 'Organization books only support Send for expenses. Use your personal book with this organization as fund for other categories.'
      });
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
    if (orgFundId !== undefined) {
      if (orgFundId === null || orgFundId === '') {
        changes.orgFundId = null;
      } else {
        const fundBook = await prisma.book.findUnique({ where: { id: orgFundId } });
        if (!fundBook) return res.status(400).json({ error: 'Invalid fund source' });
        changes.orgFundId = orgFundId;
      }
    }

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
    const requiredApprovers = txn.reconStatus === 'approved'
      ? await getRequiredApproversForChangeDelete(txn, book, req.user.id)
      : [];
    const needsLinkedApproval = requiredApprovers.length > 0;

    // Personal org — edit directly when no linked-party approval is required
    const editOrg = await prisma.organization.findUnique({ where: { id: book.organizationId }, select: { isPersonal: true } });
    const isManualIncome = txn.type === 'income' && !txn.linkedTransactionId;
    if ((editOrg?.isPersonal || isManualIncome) && (txn.reconStatus !== 'approved' || !needsLinkedApproval)) {
      // Personal book or manual income: direct update; skip balance adj on rejected (reject already restored)
      let personalBalAdj = 0;
      if (
        txn.reconStatus !== 'rejected' &&
        changes.amount !== undefined &&
        changes.amount !== txn.amount
      ) {
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

        // Sub-book mirror check
        const mirror = await findMirrorTxn(txn, book);
        if (mirror) {
          const mirrorChanges = { ...changes };
          if (changes.note !== undefined) {
            mirrorChanges.note = changes.note ? (changes.note + ' [' + book.name + ']') : ('[' + book.name + ']');
          }
          await prisma.transaction.update({
            where: { id: mirror.id },
            data: mirrorChanges
          });
          if (personalBalAdj !== 0) {
            await prisma.book.update({ where: { id: book.parentBookId }, data: { balance: { increment: personalBalAdj } } });
          }
        }

        // Sync linked transaction on direct edit when no multi-party approval is needed
        if (txn.linkedTransactionId && !needsLinkedApproval) {
          const linkedTxn = await prisma.transaction.findUnique({ where: { id: txn.linkedTransactionId } });
          if (linkedTxn) {
            const linkedChanges = {};
            if (changes.amount !== undefined) linkedChanges.amount = parsedAmount;
            if (changes.note !== undefined) linkedChanges.note = changes.note;
            if (Object.keys(linkedChanges).length > 0) {
              let linkedBalAdj = 0;
              if (changes.amount !== undefined && changes.amount !== linkedTxn.amount) {
                if (linkedTxn.type === 'income') linkedBalAdj = parsedAmount - linkedTxn.amount;
                else if (linkedTxn.type === 'expense') linkedBalAdj = linkedTxn.amount - parsedAmount;
              }
              await prisma.transaction.update({
                where: { id: txn.linkedTransactionId },
                data: {
                  ...linkedChanges,
                  updateHistory: [
                    ...(linkedTxn.updateHistory || []),
                    { timestamp: new Date().toISOString(), userId: req.user.id, userName: user?.name || 'Unknown', action: 'edit (linked)', changes: { old: { amount: linkedTxn.amount, note: linkedTxn.note }, new: linkedChanges } },
                  ],
                },
              });
              if (linkedBalAdj !== 0) {
                const linkedBook = await prisma.book.findUnique({ where: { id: linkedTxn.bookId } });
                if (linkedBook) {
                  await prisma.book.update({ where: { id: linkedTxn.bookId }, data: { balance: { increment: linkedBalAdj } } });
                }
              }
            }
          }
        }

        return updatedTxn;
      });
      broadcast({ type: 'data_changed' });
      const enrichedPersonal = await enrichTxn(personalUpdated);
      return res.json({ transaction: enrichedPersonal, message: 'Transaction updated' });
    } else if (txn.reconStatus === 'approved') {
      if (!needsLinkedApproval) {
        let balanceAdjustment = 0;
        if (changes.amount !== undefined && changes.amount !== txn.amount) {
          if (txn.type === 'expense') balanceAdjustment = txn.amount - parsedAmount;
          else if (txn.type === 'income') balanceAdjustment = parsedAmount - txn.amount;
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
            await prisma.book.update({ where: { id: book.id }, data: { balance: { increment: balanceAdjustment } } });
          }
          if (txn.linkedTransactionId) {
            const linkedTxn = await prisma.transaction.findUnique({ where: { id: txn.linkedTransactionId } });
            if (linkedTxn) {
              const linkedChanges = {};
              if (changes.amount !== undefined) linkedChanges.amount = parsedAmount;
              if (changes.note !== undefined) linkedChanges.note = changes.note;
              if (Object.keys(linkedChanges).length > 0) {
                let linkedBalAdj = 0;
                if (changes.amount !== undefined && changes.amount !== linkedTxn.amount) {
                  if (linkedTxn.type === 'income') linkedBalAdj = parsedAmount - linkedTxn.amount;
                  else if (linkedTxn.type === 'expense') linkedBalAdj = linkedTxn.amount - parsedAmount;
                }
                await prisma.transaction.update({
                  where: { id: txn.linkedTransactionId },
                  data: {
                    ...linkedChanges,
                    updateHistory: [
                      ...(linkedTxn.updateHistory || []),
                      { timestamp: new Date().toISOString(), userId: req.user.id, userName: user?.name || 'Unknown', action: 'edit (linked)', changes: { old: { amount: linkedTxn.amount, note: linkedTxn.note }, new: linkedChanges } },
                    ],
                  },
                });
                if (linkedBalAdj !== 0) {
                  await prisma.book.update({ where: { id: linkedTxn.bookId }, data: { balance: { increment: linkedBalAdj } } });
                }
              }
            }
          }
          const mirror = await findMirrorTxn(txn, book);
          if (mirror) {
            const mirrorChanges = {};
            if (changes.amount !== undefined) mirrorChanges.amount = parsedAmount;
            if (changes.note !== undefined) {
              mirrorChanges.note = changes.note ? (changes.note + ' [' + book.name + ']') : ('[' + book.name + ']');
            }
            if (Object.keys(mirrorChanges).length > 0) {
              await prisma.transaction.update({ where: { id: mirror.id }, data: mirrorChanges });
            }
            if (balanceAdjustment !== 0) {
              await prisma.book.update({ where: { id: book.parentBookId }, data: { balance: { increment: balanceAdjustment } } });
            }
          }
          return updatedTxn;
        });
        broadcast({ type: 'data_changed' });
        const enriched = await enrichTxn(updated);
        return res.json({ transaction: enriched, message: 'Transaction updated' });
      }

      // Reverse current balance to compute the pre-txn balance
      let preTxnBalance = book.balance;
      if (txn.type === 'expense') {
        preTxnBalance += txn.amount;
      } else if (txn.type === 'income') {
        preTxnBalance -= txn.amount;
      }

      // Store old data for potential revert
      const pendingData = await buildChangeDeletePendingData(txn, book, req.user.id, {
        oldAmount: txn.amount,
        oldType: txn.type,
        oldCategory: txn.category,
        oldNote: txn.note,
        oldRecipientUserId: txn.recipientUserId,
        newAmount: changes.amount !== undefined ? parsedAmount : txn.amount,
        newNote: changes.note !== undefined ? changes.note : txn.note,
        newCategory: changes.category !== undefined ? changes.category : txn.category,
      });

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

            const linkedChanges = {};
            if (changes.amount !== undefined) linkedChanges.amount = parsedAmount;
            if (changes.note !== undefined) linkedChanges.note = note;

            await prisma.transaction.update({
              where: { id: txn.linkedTransactionId },
              data: {
                ...linkedChanges,
                reconStatus: 'pending',
                pendingAction: 'edit',
                pendingData,
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

        // Sync to sub-book parent mirror transaction if it exists
        const mirror = await findMirrorTxn(txn, book);
        if (mirror) {
          if (mirror.reconStatus === 'approved') {
            const mirrorBalanceOp = mirror.type === 'income'
              ? { decrement: mirror.amount }
              : { increment: mirror.amount };
            await prisma.book.update({
              where: { id: book.parentBookId },
              data: { balance: mirrorBalanceOp }
            });

            const mirrorChanges = {};
            if (changes.amount !== undefined) mirrorChanges.amount = parsedAmount;
            if (changes.note !== undefined) {
              mirrorChanges.note = changes.note ? (changes.note + ' [' + book.name + ']') : ('[' + book.name + ']');
            }

            await prisma.transaction.update({
              where: { id: mirror.id },
              data: {
                ...mirrorChanges,
                reconStatus: 'pending',
                pendingAction: 'edit',
                pendingData: {
                  oldAmount: mirror.amount,
                  oldType: mirror.type,
                  oldCategory: mirror.category,
                  oldNote: mirror.note,
                  requestedBy: req.user.id
                },
                updateHistory: [
                  ...(mirror.updateHistory || []),
                  {
                    timestamp: new Date().toISOString(),
                    userId: req.user.id,
                    userName: user?.name || 'Unknown',
                    action: 'edit (mirror)',
                    changes: { old: { amount: mirror.amount, note: mirror.note }, new: mirrorChanges }
                  }
                ]
              }
            });
          }
        }

        return updatedTxn;
      });

      broadcast({ type: 'data_changed' });
      await notifyChangeDeleteApprovers(updated, 'edit', pendingData);
      const enriched = await enrichTxn(updated);
      const summary = buildChangeDeleteNotification(pendingData, 'edit', updated);
      return res.json({
        transaction: enriched,
        message: 'Edit submitted for approval',
        notification: summary,
      });
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

        // Sync to sub-book parent mirror transaction if it exists
        const mirror = await findMirrorTxn(txn, book);
        if (mirror) {
          const mirrorChanges = {};
          if (changes.amount !== undefined) mirrorChanges.amount = parsedAmount;
          if (changes.note !== undefined) {
            mirrorChanges.note = changes.note ? (changes.note + ' [' + book.name + ']') : ('[' + book.name + ']');
          }
          if (Object.keys(mirrorChanges).length > 0) {
            await prisma.transaction.update({
              where: { id: mirror.id },
              data: mirrorChanges
            });
          }
          if (balanceAdjustment !== 0) {
            await prisma.book.update({
              where: { id: book.parentBookId },
              data: { balance: { increment: balanceAdjustment } }
            });
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

// --- CHECK TRANSACTION DELETE STATUS (counterparty existence) ---
app.get('/api/transactions/:id/delete-info', authenticateToken, async (req, res) => {
  try {
    const txnId = req.params.id;
    const txn = await prisma.transaction.findUnique({ where: { id: txnId } });
    if (!txn) return res.status(404).json({ error: 'Transaction not found' });

    const book = await prisma.book.findUnique({ where: { id: txn.bookId } });
    if (!book) return res.status(404).json({ error: 'Book not found' });

    const result = {
      hasCounterparty: false,
      counterpartyExists: false,
      counterpartyType: null,
      counterpartyName: null,
      needsApproval: false,
      requiredApproverCount: 0,
      canInstantDelete: true,
    };

    // Check linkedTransactionId (paired income/expense)
    if (txn.linkedTransactionId) {
      result.hasCounterparty = true;
      const linkedTxn = await prisma.transaction.findUnique({ where: { id: txn.linkedTransactionId } });
      if (linkedTxn) {
        const linkedBook = await prisma.book.findUnique({ where: { id: linkedTxn.bookId } });
        if (linkedBook) {
          result.counterpartyExists = true;
          result.counterpartyType = 'book';
          result.counterpartyName = linkedBook.name;
          // Need approval from other side
          result.needsApproval = txn.reconStatus === 'approved';
        }
      }
    }

    // Check recipientOrgId (org-to-org send)
    if (txn.recipientOrgId) {
      result.hasCounterparty = true;
      const recipientOrg = await prisma.organization.findUnique({ where: { id: txn.recipientOrgId } });
      if (recipientOrg) {
        result.counterpartyExists = true;
        result.counterpartyType = 'org';
        result.counterpartyName = recipientOrg.name;
        result.needsApproval = txn.reconStatus === 'approved';
      }
    }

    // Check orgFundId (fund transfer source)
    if (txn.orgFundId) {
      result.hasCounterparty = true;
      const fundBook = await prisma.book.findUnique({ where: { id: txn.orgFundId } });
      if (fundBook) {
        result.counterpartyExists = true;
        result.counterpartyType = 'fund';
        result.counterpartyName = fundBook.name;
        result.needsApproval = txn.reconStatus === 'approved';
      }
    }

    // Check recipientUserId (for personal recipient books)
    if (txn.recipientUserId && !txn.recipientOrgId) {
      result.hasCounterparty = true;
      const recipientUser = await prisma.user.findUnique({ where: { id: txn.recipientUserId } });
      if (recipientUser) {
        // Check if the recipient user has any active personal book
        const userPersonalBooks = await prisma.book.findMany({
          where: {
            organization: { isPersonal: true },
            organization: { members: { some: { userId: txn.recipientUserId } } }
          },
          take: 1
        });
        if (userPersonalBooks.length > 0) {
          result.counterpartyExists = true;
          result.counterpartyType = 'user';
          result.counterpartyName = recipientUser.name;
        }
      }
    }

    if (txn.reconStatus === 'approved') {
      const requiredApprovers = await getRequiredApproversForChangeDelete(txn, book, req.user.id);
      result.requiredApproverCount = requiredApprovers.length;
      result.needsApproval = requiredApprovers.length > 0;
      result.canInstantDelete = requiredApprovers.length === 0;
    }

    return res.json(result);
  } catch (error) {
    console.error('Delete info error:', error);
    res.status(500).json({ error: 'Server error' });
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
    const org = await prisma.organization.findUnique({ where: { id: book.organizationId }, select: { isPersonal: true } });
    const isManualIncome = txn.type === 'income' && !txn.linkedTransactionId;
    const requiredApprovers = txn.reconStatus === 'approved'
      ? await getRequiredApproversForChangeDelete(txn, book, req.user.id)
      : [];

    const executeHardDelete = async () => {
      await prisma.$transaction(async (prisma) => {
        let balanceAdjustment = 0;
        if (txn.type === 'expense') balanceAdjustment = txn.amount;
        else if (txn.type === 'income') balanceAdjustment = -txn.amount;
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
        const mirror = await findMirrorTxn(txn, book);
        if (mirror) {
          let mirrorAdj = mirror.type === 'income' ? -mirror.amount : mirror.amount;
          await prisma.book.update({ where: { id: book.parentBookId }, data: { balance: { increment: mirrorAdj } } });
          await prisma.transaction.delete({ where: { id: mirror.id } });
        }
        await prisma.transaction.delete({ where: { id: txnId } });
      });
      broadcast({ type: 'data_changed' });
    };

    // Manual personal income or no linked parties — delete immediately
    if (isManualIncome || (txn.reconStatus === 'approved' && requiredApprovers.length === 0)) {
      await executeHardDelete();
      return res.json({ message: 'Transaction deleted' });
    }

    if (txn.reconStatus === 'approved') {
      let reversedBalance = book.balance;
      if (txn.type === 'expense') {
        reversedBalance += txn.amount;
      } else if (txn.type === 'income') {
        reversedBalance -= txn.amount;
      }

      const pendingData = await buildChangeDeletePendingData(txn, book, req.user.id, {
        oldAmount: txn.amount,
        oldType: txn.type,
        oldCategory: txn.category,
        oldNote: txn.note,
        oldRecipientUserId: txn.recipientUserId,
        oldLinkedTransactionId: txn.linkedTransactionId,
        oldOrgFundId: txn.orgFundId,
      });

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
                pendingData,
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

        // Sync deletion to parent sub-book mirror transaction if it exists
        const mirror = await findMirrorTxn(txn, book);
        if (mirror) {
          if (mirror.reconStatus === 'approved') {
            let mirrorReversed = mirror.type === 'income' ? -mirror.amount : mirror.amount;
            await prisma.book.update({
              where: { id: book.parentBookId },
              data: { balance: { increment: mirrorReversed } },
            });

            await prisma.transaction.update({
              where: { id: mirror.id },
              data: {
                reconStatus: 'pending',
                pendingAction: 'delete',
                pendingData: {
                  oldAmount: mirror.amount,
                  oldType: mirror.type,
                  oldCategory: mirror.category,
                  oldNote: mirror.note,
                  requestedBy: req.user.id,
                },
                updateHistory: [
                  ...(mirror.updateHistory || []),
                  {
                    timestamp: new Date().toISOString(),
                    userId: req.user.id,
                    userName: user?.name || 'Unknown',
                    action: 'delete_request (mirror)',
                    changes: { old: { amount: mirror.amount, type: mirror.type, category: mirror.category, note: mirror.note } },
                  },
                ],
              },
            });
          }
        }
      });

      broadcast({ type: 'data_changed' });
      const refreshedTxn = await prisma.transaction.findUnique({ where: { id: txnId } });
      await notifyChangeDeleteApprovers(refreshedTxn || txn, 'delete', pendingData);
      const summary = buildChangeDeleteNotification(pendingData, 'delete', refreshedTxn || txn);
      return res.json({ message: 'Delete request submitted for approval', notification: summary });
    } else {
      await executeHardDelete();
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

    // Fetch details of user taking action to save in updateHistory
    const user = await prisma.user.findUnique({ where: { id: req.user.id }, select: { name: true } });
    const userName = user?.name || 'Unknown';
    const approveHistoryEntry = {
      timestamp: new Date().toISOString(),
      userId: req.user.id,
      userName,
      action: 'approve'
    };
    const rejectHistoryEntry = {
      timestamp: new Date().toISOString(),
      userId: req.user.id,
      userName,
      action: 'reject'
    };

    // Verify caller is admin/editor of the transaction's org
    // OR that the caller is the recipient of this or the linked transaction (user or org admin/editor)
    let isRecipient = false;
    if (txn.recipientUserId) {
      isRecipient = txn.recipientUserId === req.user.id;
    } else if (txn.recipientOrgId) {
      isRecipient = await checkPermission(txn.recipientOrgId, req.user.id, 'edit_all');
    }
    if (!isRecipient && txn.linkedTransactionId) {
      const linked = await prisma.transaction.findUnique({ where: { id: txn.linkedTransactionId }, select: { recipientUserId: true, recipientOrgId: true } });
      if (linked) {
        if (linked.recipientUserId) {
          isRecipient = linked.recipientUserId === req.user.id;
        } else if (linked.recipientOrgId) {
          isRecipient = await checkPermission(linked.recipientOrgId, req.user.id, 'edit_all');
        }
      }
    }

    // Also check if the caller is admin/editor of the fund's org (for vouchers from personal books)
    let hasFundOrgAccess = false;
    if (txn.orgFundId) {
      const fundBook = await prisma.book.findUnique({ where: { id: txn.orgFundId }, select: { organizationId: true } });
      if (fundBook) {
        hasFundOrgAccess = await hasAdminOrEditorAccess(fundBook.organizationId, req.user.id);
      } else {
        const fundTxn = await prisma.transaction.findUnique({ where: { id: txn.orgFundId }, select: { bookId: true } });
        if (fundTxn) {
          const fundTxnBook = await prisma.book.findUnique({ where: { id: fundTxn.bookId }, select: { organizationId: true } });
          if (fundTxnBook) {
            hasFundOrgAccess = await hasAdminOrEditorAccess(fundTxnBook.organizationId, req.user.id);
          }
        }
      }
    }

    if (!isRecipient && !(await hasAdminOrEditorAccess(txnBook.organizationId, req.user.id)) && !hasFundOrgAccess) {
      return res.status(403).json({ error: 'Only admins, editors, or the recipient can approve/reject transactions' });
    }

    // Edit/delete requests: requester cannot self-approve; only listed parties can approve
    if (txn.pendingAction && ['edit', 'delete'].includes(txn.pendingAction)) {
      const pendingDataObj = parsePendingData(txn.pendingData);
      if (pendingDataObj.requestedBy === req.user.id) {
        return res.status(403).json({ error: 'You cannot approve or reject your own edit/delete request.' });
      }
      const required = pendingDataObj.requiredApprovers || [];
      const orgAnyOf = pendingDataObj.orgApprovalAnyOf || [];
      if (required.length > 0 || orgAnyOf.length > 0) {
        const canApprove = required.includes(req.user.id) || orgAnyOf.includes(req.user.id);
        if (!canApprove) {
          return res.status(403).json({ error: 'You are not authorized to approve this edit/delete request.' });
        }
      }
    }

    // 2. Check if this is a pending_recipient creation step and the caller is NOT the recipient.
    if (action === 'approve' && txn.reconStatus === 'pending_recipient') {
      let recipientUserId = null;
      let recipientOrgId = null;
      if (txn.type === 'expense' && txn.category === 'Send') {
        recipientUserId = txn.recipientUserId;
        recipientOrgId = txn.recipientOrgId;
      } else if (txn.linkedTransactionId) {
        const linked = await prisma.transaction.findUnique({ where: { id: txn.linkedTransactionId } });
        if (linked && linked.type === 'expense' && linked.category === 'Send') {
          recipientUserId = linked.recipientUserId;
          recipientOrgId = linked.recipientOrgId;
        }
      }

      let isAuthorizedRecipient = false;
      if (recipientUserId) {
        isAuthorizedRecipient = req.user.id === recipientUserId;
      } else if (recipientOrgId) {
        isAuthorizedRecipient = await checkPermission(recipientOrgId, req.user.id, 'edit_all');
      }

      if (!isAuthorizedRecipient) {
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
          data: {
            amount: finalAmount,
            reconStatus: 'approved',
            counterProposedAmount: null,
            counterProposedBy: null,
            updateHistory: [...(sourceTxn.updateHistory || []), approveHistoryEntry]
          }
        }),
        prisma.transaction.update({
          where: { id: recipientTxn.id },
          data: {
            amount: finalAmount,
            reconStatus: 'approved',
            counterProposedAmount: null,
            counterProposedBy: null,
            updateHistory: [...(recipientTxn.updateHistory || []), approveHistoryEntry]
          }
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
          const updatedPendingData = recordChangeDeleteApproval(txn.pendingData, req.user.id);
          if (!isChangeDeleteFullyApproved(updatedPendingData)) {
            await prisma.$transaction(async (tx) => {
              await tx.transaction.update({
                where: { id: txnId },
                data: {
                  pendingData: updatedPendingData,
                  updateHistory: [...(txn.updateHistory || []), approveHistoryEntry]
                }
              });
              if (txn.linkedTransactionId) {
                await tx.transaction.update({
                  where: { id: txn.linkedTransactionId },
                  data: { pendingData: updatedPendingData }
                });
              }
            });
            broadcast({ type: 'data_changed' });
            const remaining = (updatedPendingData.requiredApprovers || []).filter((id) => !(updatedPendingData.approvals || []).includes(id));
            return res.json({ message: `Edit approval recorded. Waiting for ${remaining.length} more approval(s).` });
          }

          await prisma.$transaction(async (tx) => {
            const current = await tx.transaction.findUnique({ where: { id: txnId }, select: { version: true, updateHistory: true } });
            if (!current) throw new Error('Transaction not found');
            const upd1 = await tx.transaction.updateMany({
              where: { id: txnId, version: current.version },
              data: {
                reconStatus: 'approved',
                pendingAction: null,
                pendingData: null,
                version: { increment: 1 },
                updateHistory: [...(current.updateHistory || []), approveHistoryEntry]
              }
            });
            if (upd1.count === 0) throw new Error('Concurrency conflict on edit-approve');

            if (txn.linkedTransactionId) {
              const linkedCurrent = await tx.transaction.findUnique({ where: { id: txn.linkedTransactionId }, select: { version: true, updateHistory: true } });
              if (linkedCurrent) {
                const upd2 = await tx.transaction.updateMany({
                  where: { id: txn.linkedTransactionId, version: linkedCurrent.version },
                  data: {
                    reconStatus: 'approved',
                    pendingAction: null,
                    pendingData: null,
                    version: { increment: 1 },
                    updateHistory: [...(linkedCurrent.updateHistory || []), approveHistoryEntry]
                  }
                });
                if (upd2.count === 0) throw new Error('Concurrency conflict on linked edit-approve');
              }
            }

            // Sync approval to parent sub-book mirror transaction
            const mirror = await findMirrorTxn(txn, txnBook);
            if (mirror) {
              const mirrorCurrent = await tx.transaction.findUnique({ where: { id: mirror.id }, select: { version: true } });
              if (mirrorCurrent) {
                await tx.transaction.updateMany({
                  where: { id: mirror.id, version: mirrorCurrent.version },
                  data: { reconStatus: 'approved', pendingAction: null, pendingData: null, version: { increment: 1 } }
                });
                const updatedMirror = await tx.transaction.findUnique({ where: { id: mirror.id } });
                if (updatedMirror) {
                  const mirrorDelta = updatedMirror.type === 'expense' ? -updatedMirror.amount : updatedMirror.amount;
                  await tx.book.update({
                    where: { id: txnBook.parentBookId },
                    data: { balance: { increment: mirrorDelta } }
                  });
                }
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
          const updatedPendingData = recordChangeDeleteApproval(txn.pendingData, req.user.id);
          if (!isChangeDeleteFullyApproved(updatedPendingData)) {
            await prisma.$transaction(async (tx) => {
              await tx.transaction.update({
                where: { id: txnId },
                data: {
                  pendingData: updatedPendingData,
                  updateHistory: [...(txn.updateHistory || []), approveHistoryEntry]
                }
              });
              if (txn.linkedTransactionId) {
                await tx.transaction.update({
                  where: { id: txn.linkedTransactionId },
                  data: { pendingData: updatedPendingData }
                });
              }
            });
            broadcast({ type: 'data_changed' });
            const remaining = (updatedPendingData.requiredApprovers || []).filter((id) => !(updatedPendingData.approvals || []).includes(id));
            return res.json({ message: `Delete approval recorded. Waiting for ${remaining.length} more approval(s).` });
          }

          await prisma.$transaction(async (tx) => {
            if (txn.linkedTransactionId) {
              const linked = await tx.transaction.findUnique({ where: { id: txn.linkedTransactionId } });
              if (linked) {
                await tx.transaction.delete({ where: { id: linked.id } });
              }
            }

            // Sync deletion to parent sub-book mirror transaction if it exists
            const mirror = await findMirrorTxn(txn, txnBook);
            if (mirror) {
              await tx.transaction.delete({ where: { id: mirror.id } });
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
        if (txn.chainType === 'fund_send' && txn.type === 'income') {
          return res.status(400).json({ error: 'Fund organization must approve the send first' });
        }

        const isSend = txn.category === 'Send' && txn.linkedTransactionId;
        if (isSend || (txn.category === 'Send' && (txn.recipientUserId || txn.recipientOrgId))) {
          const isSelfSend = txn.recipientUserId === txn.createdById;
          const nextStatus = isSelfSend ? 'approved' : 'pending_recipient';

          // Send: advance fund_send chain (parallel org + recipient) or linked pair
          let fundSendOrgResult = null;
          await prisma.$transaction(async (tx) => {
            if (txn.chainType === 'fund_send' && txn.chainId) {
              fundSendOrgResult = await approveFundSendOrg(tx, txn, approveHistoryEntry);
              return;
            }

            const main = await tx.transaction.findUnique({ where: { id: txnId }, select: { version: true, updateHistory: true } });
            if (!main) throw new Error('Transaction not found');
            const upd1 = await tx.transaction.updateMany({
              where: { id: txnId, version: main.version },
              data: {
                reconStatus: nextStatus,
                version: { increment: 1 },
                updateHistory: [...(main.updateHistory || []), approveHistoryEntry]
              }
            });
            if (upd1.count === 0) throw new Error('Concurrency conflict on pending_org advance');

            if (txn.linkedTransactionId) {
              const linked = await tx.transaction.findUnique({ where: { id: txn.linkedTransactionId }, select: { version: true, updateHistory: true } });
              if (linked) {
                const upd2 = await tx.transaction.updateMany({
                  where: { id: txn.linkedTransactionId, version: linked.version },
                  data: {
                    reconStatus: nextStatus,
                    version: { increment: 1 },
                    updateHistory: [...(linked.updateHistory || []), approveHistoryEntry]
                  }
                });
                if (upd2.count === 0) throw new Error('Concurrency conflict on linked pending_org advance');
              }
            }

            const orgSource = await resolveOrgSourceTxnForMirror(txn, tx);
            if (orgSource && orgSource.chainType !== 'fund_send') {
              await syncCreatorPersonalMirrorStatus(tx, orgSource, nextStatus, approveHistoryEntry);
            }
          });

          if (fundSendOrgResult?.final) {
            broadcast({ type: 'data_changed' });
            return res.json({ message: 'Org approved, transaction completed' });
          }
          if (fundSendOrgResult && !fundSendOrgResult.final) {
            broadcast({ type: 'data_changed' });
            return res.json({ message: 'Org approved, waiting for recipient acceptance' });
          }

          // Notify recipient that org approval passed
          if (txn.recipientUserId && !isSelfSend) {
            broadcastToUser(txn.recipientUserId, { type: 'pending_send_received', transaction: txn });
          } else if (txn.recipientOrgId) {
            const recipientAdmins = await prisma.organizationMember.findMany({
              where: { organizationId: txn.recipientOrgId, status: 'active', OR: [{ role: 'admin' }, { permissions: { has: 'edit_all' } }] },
              select: { userId: true }
            });
            const adminIds = recipientAdmins.map(a => a.userId);
            const enriched = await enrichTxn(txn);
            broadcastToUsers(adminIds, { type: "pending_send_received", transaction: enriched });
          }
          broadcast({ type: "data_changed" });
          return res.json({ message: isSelfSend ? 'Org approved, transaction completed' : 'Org approved, waiting for recipient acceptance' });
        } else {
          // Check if it is a book-based voucher
          if (txn.orgFundId) {
            const targetBook = await prisma.book.findUnique({ where: { id: txn.orgFundId } });
            if (targetBook) {
              await prisma.$transaction([
                prisma.transaction.update({
                  where: { id: txnId, version: txn.version },
                  data: {
                    reconStatus: 'approved',
                    version: { increment: 1 },
                    updateHistory: [...(txn.updateHistory || []), approveHistoryEntry]
                  }
                }),
                prisma.book.update({ where: { id: targetBook.id }, data: { balance: { decrement: txn.amount } } }),
                prisma.transaction.create({
                  data: {
                    bookId: targetBook.id,
                    amount: txn.amount,
                    type: 'expense',
                    note: txn.note || '',
                    category: txn.category || 'Voucher',
                    contact: txn.contact,
                    orgFundId: targetBook.id,
                    createdById: txn.createdById,
                    reconStatus: 'approved',
                    clientRef: txn.clientRef,
                    imageUrl: txn.imageUrl
                  }
                })
              ]);
              broadcast({ type: "data_changed" });
              const updated = await prisma.transaction.findUnique({ where: { id: txnId } });
              return res.json({ transaction: updated, message: 'Voucher approved' });
            }
          }

          // General expense/voucher: approve directly with version lock
          const updated = await prisma.$transaction(async (tx) => {
            const approvedTxn = await updateTxnWithVersion(txnId, txn.version, {
              reconStatus: 'approved',
              updateHistory: [...(txn.updateHistory || []), approveHistoryEntry]
            }, tx);
            const orgSource = await resolveOrgSourceTxnForMirror(txn, tx);
            if (orgSource) {
              await syncCreatorPersonalMirrorStatus(tx, orgSource, 'approved', approveHistoryEntry);
            }
            return approvedTxn;
          });
          broadcast({ type: 'data_changed' });
          return res.json({ transaction: updated, message: 'Transaction approved' });
        }
      }

      // --- PENDING_RECIPIENT → approve (green) ---
      if (txn.reconStatus === 'pending_recipient') {
        let fundSendRecipientResult = null;
        await prisma.$transaction(async (tx) => {
          if (txn.chainType === 'fund_send' && txn.chainId) {
            fundSendRecipientResult = await approveFundSendRecipient(tx, txn, approveHistoryEntry);
          } else {
            const main = await tx.transaction.findUnique({ where: { id: txnId }, select: { version: true, updateHistory: true } });
          if (!main) throw new Error('Transaction not found');
          const upd1 = await tx.transaction.updateMany({
            where: { id: txnId, version: main.version },
            data: {
              reconStatus: 'approved',
              counterProposedAmount: null,
              counterProposedBy: null,
              version: { increment: 1 },
              updateHistory: [...(main.updateHistory || []), approveHistoryEntry]
            }
          });
          if (upd1.count === 0) throw new Error('Concurrency conflict on pending_recipient approve');

          if (txn.linkedTransactionId) {
            const linked = await tx.transaction.findUnique({ where: { id: txn.linkedTransactionId }, select: { version: true, updateHistory: true } });
            if (linked) {
              const upd2 = await tx.transaction.updateMany({
                where: { id: txn.linkedTransactionId, version: linked.version },
                data: {
                  reconStatus: 'approved',
                  counterProposedAmount: null,
                  counterProposedBy: null,
                  version: { increment: 1 },
                  updateHistory: [...(linked.updateHistory || []), approveHistoryEntry]
                }
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

          const orgSource = await resolveOrgSourceTxnForMirror(txn, tx);
          if (orgSource && orgSource.chainType !== 'fund_send') {
            const mirrorStatus =
              fundSendRecipientResult && !fundSendRecipientResult.final ? 'pending_org' : 'approved';
            await syncCreatorPersonalMirrorStatus(tx, orgSource, mirrorStatus, approveHistoryEntry, {
              counterProposedAmount: null,
              counterProposedBy: null
            });
          }
          }
        });

        if (fundSendRecipientResult && !fundSendRecipientResult.final) {
          broadcast({ type: 'data_changed' });
          return res.json({ message: 'Accepted, waiting for organization approval' });
        }

        // Broadcast deficit adjustment notification outside txn (non-critical)
        if (txn.type === 'income' && (fundSendRecipientResult?.final !== false)) {
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

      // fund_send: reject entire chain atomically
      if (txn.chainType === 'fund_send' && txn.chainId) {
        await prisma.$transaction(async (tx) => {
          await rejectFundSendChain(tx, txn, rejectHistoryEntry);
        });
        broadcast({ type: 'data_changed' });
        return res.json({ message: 'Fund send rejected' });
      }

      // ── Atomic reject with linked transaction rollback ──
      await prisma.$transaction(async (tx) => {
        // Version-locked reject of main transaction
        const mainCurrent = await tx.transaction.findUnique({ where: { id: txnId }, select: { version: true, updateHistory: true } });
        if (!mainCurrent) throw new Error('Transaction not found');
        const updMain = await tx.transaction.updateMany({
          where: { id: txnId, version: mainCurrent.version },
          data: {
            reconStatus: 'rejected',
            pendingAction: null,
            pendingData: null,
            counterProposedAmount: null,
            counterProposedBy: null,
            isLiability: isLiabilityReject || undefined,
            version: { increment: 1 },
            updateHistory: [...(mainCurrent.updateHistory || []), rejectHistoryEntry]
          }
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
                data: {
                  reconStatus: 'rejected',
                  isLiability: true,
                  pendingAction: null,
                  pendingData: null,
                  counterProposedAmount: null,
                  counterProposedBy: null,
                  version: { increment: 1 },
                  updateHistory: [...(linked.updateHistory || []), rejectHistoryEntry]
                }
              });
              if (updLink.count === 0) throw new Error('Concurrency conflict on linked liability reject');
            } else if (['pending_org', 'pending_recipient', 'pending'].includes(linked.reconStatus)) {
              // Normal rollback: reject linked + reverse its balance atomically
              const updLink = await tx.transaction.updateMany({
                where: { id: txn.linkedTransactionId, version: linkedVersion },
                data: {
                  reconStatus: 'rejected',
                  pendingAction: null,
                  pendingData: null,
                  counterProposedAmount: null,
                  counterProposedBy: null,
                  version: { increment: 1 },
                  updateHistory: [...(linked.updateHistory || []), rejectHistoryEntry]
                }
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

        const orgSource = await resolveOrgSourceTxnForMirror(txn, tx);
        if (orgSource && orgSource.chainType !== 'fund_send') {
          await rejectCreatorPersonalMirror(tx, orgSource, rejectHistoryEntry);
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

    const approvalOrgId = await resolveApprovalOrgId(txn, book);
    const bypassOrgApproval = await checkApprovalBypass(approvalOrgId, req.user.id);
    const isSend = txn.category === 'Send';
    const newStatus = isSend
      ? (bypassOrgApproval ? 'pending_recipient' : 'pending_org')
      : (bypassOrgApproval ? 'approved' : 'pending_org');

    const updated = await prisma.$transaction(async (tx) => {
      const main = await tx.transaction.findUnique({ where: { id: txnId }, select: { version: true } });
      if (!main) throw new Error('Transaction not found');

      if (txn.chainType === 'fund_send' && txn.chainId) {
        const chainTxns = await tx.transaction.findMany({ where: { chainId: txn.chainId } });
        const { personalTxn, fundOrgTxn, recipientTxn } = resolveFundSendChainParts(chainTxns);
        const isSelfSend = personalTxn?.recipientUserId === personalTxn?.createdById;
        const statuses = fundSendRetryStatuses(bypassOrgApproval, isSelfSend);

        for (const ct of chainTxns) {
          const targetStatus =
            ct.id === recipientTxn?.id ? statuses.recipient
            : ct.id === fundOrgTxn?.id ? statuses.fundOrg
            : statuses.personal;
          const cur = await tx.transaction.findUnique({ where: { id: ct.id }, select: { version: true } });
          const updC = await tx.transaction.updateMany({
            where: { id: ct.id, version: cur.version },
            data: {
              reconStatus: targetStatus,
              pendingAction: null,
              pendingData: null,
              counterProposedAmount: null,
              counterProposedBy: null,
              isLiability: false,
              version: { increment: 1 }
            }
          });
          if (updC.count === 0) throw new Error('Concurrency conflict on fund_send retry');
        }

        for (const ct of chainTxns) {
          const balanceDelta = ct.type === 'expense' ? -ct.amount : ct.amount;
          await tx.book.update({
            where: { id: ct.bookId },
            data: { balance: { increment: balanceDelta } }
          });
        }
      } else {
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

        if (isSend) {
          const balanceDelta = txn.type === 'expense' ? -txn.amount : txn.amount;
          await tx.book.update({
            where: { id: txn.bookId },
            data: { balance: { increment: balanceDelta } }
          });
          const linkedFull = await tx.transaction.findUnique({ where: { id: txn.linkedTransactionId } });
          if (linkedFull) {
            const linkedBalanceDelta = linkedFull.type === 'income' ? linkedFull.amount : -linkedFull.amount;
            await tx.book.update({
              where: { id: linkedFull.bookId },
              data: { balance: { increment: linkedBalanceDelta } }
            });
          }
        }
      }
      }

      // Re-apply balance (reject had reversed it) for non-send expenses
      if (!isSend) {
        const balanceDelta = txn.type === 'expense' ? -txn.amount : txn.amount;
        await tx.book.update({
          where: { id: txn.bookId },
          data: { balance: { increment: balanceDelta } }
        });

        // Bypass on fund org: mirror expense into org book (same as create voucher flow)
        if (bypassOrgApproval && newStatus === 'approved' && txn.orgFundId) {
          const targetBook = await tx.book.findUnique({ where: { id: txn.orgFundId } });
          if (targetBook && targetBook.id !== txn.bookId) {
            await tx.book.update({
              where: { id: targetBook.id },
              data: { balance: { decrement: txn.amount } }
            });
            await tx.transaction.create({
              data: {
                bookId: targetBook.id,
                amount: txn.amount,
                type: 'expense',
                note: txn.note || '',
                category: txn.category || 'Voucher',
                contact: txn.contact,
                orgFundId: targetBook.id,
                createdById: txn.createdById,
                reconStatus: 'approved',
                clientRef: txn.clientRef,
                imageUrl: txn.imageUrl
              }
            });
          }
        }
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

    // Enrich with recipient names and fund info using the shared helper
    const enriched = await Promise.all(transactions.map(txn => enrichTxn(txn)));

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
          reconStatus: { in: ['pending_org', 'pending_recipient', 'pending'] },
          OR: [
            {
              bookId: { in: adminBookIds },
              OR: [
                { category: 'Send' },
                { orgFundId: { not: null } },
                { recipientOrgId: { not: null } },
                { pendingAction: { not: null } }
              ]
            },
            {
              bookId: { notIn: adminBookIds },
              orgFundId: { in: adminBookIds }
            }
          ]
        },
        orderBy: { createdAt: 'desc' }
      });

      for (const txn of pendingTxns) {
        const isFundVoucher = txn.orgFundId && !adminBookIds.includes(txn.bookId);
        const book = await prisma.book.findUnique({ where: { id: txn.bookId }, include: { organization: true } });

        // Recipient-side income on personal book (linked org Send) — not an admin creation-approval item
        if (!txn.pendingAction && book?.organization?.isPersonal && txn.type === 'income' && txn.category === 'Send' && txn.linkedTransactionId) {
          const linkedSource = await prisma.transaction.findUnique({
            where: { id: txn.linkedTransactionId },
            include: { book: { include: { organization: { select: { isPersonal: true } } } } }
          });
          if (linkedSource?.type === 'expense' && linkedSource?.category === 'Send' && !linkedSource.book?.organization?.isPersonal) {
            continue;
          }
        }

        // Edit/delete requests: only show to required approvers who have not yet approved
        if (txn.pendingAction && ['edit', 'delete'].includes(txn.pendingAction)) {
          const pd = parsePendingData(txn.pendingData);
          if (pd.requestedBy === user.id) continue;
          const required = pd.requiredApprovers || [];
          const orgAnyOf = pd.orgApprovalAnyOf || [];
          if (required.length > 0 || orgAnyOf.length > 0) {
            const canSee = required.includes(user.id) || orgAnyOf.includes(user.id);
            if (!canSee) continue;
            if ((pd.approvals || []).includes(user.id)) continue;
            if (orgAnyOf.includes(user.id) && orgAnyOf.some((id) => (pd.approvals || []).includes(id))) continue;
          }
        }

        let recipientName = null;
        if (txn.recipientUserId) {
          const u = await prisma.user.findUnique({ where: { id: txn.recipientUserId }, select: { name: true } });
          recipientName = u?.name || null;
        } else if (txn.recipientOrgId) {
          const org = await prisma.organization.findUnique({ where: { id: txn.recipientOrgId }, select: { name: true } });
          recipientName = org?.name || null;
        }
        if (txn.orgFundId) {
          const orig = await prisma.transaction.findUnique({ where: { id: txn.orgFundId } });
          if (orig) {
            if (orig.recipientUserId) {
              const u = await prisma.user.findUnique({ where: { id: orig.recipientUserId }, select: { name: true } });
              recipientName = u?.name || null;
            } else if (orig.recipientOrgId) {
              const org = await prisma.organization.findUnique({ where: { id: orig.recipientOrgId }, select: { name: true } });
              recipientName = org?.name || null;
            }
          }
        }

        let bookName = book?.name || 'Unknown';
        let orgName = book?.organization?.name || 'Unknown';

        if (isFundVoucher) {
          const fundBook = await prisma.book.findUnique({ where: { id: txn.orgFundId }, include: { organization: true } });
          if (fundBook) {
            bookName = fundBook.name;
            orgName = fundBook.organization?.name || 'Unknown';
          }
        }

        const actionLabel = txn.pendingAction === 'delete'
          ? 'Delete Request'
          : txn.pendingAction === 'edit'
            ? 'Edit Approval'
            : (txn.category === 'Send' || txn.recipientOrgId) ? 'Disbursement Approval' : 'Voucher Approval';

        let senderName = null;
        const sender = await prisma.user.findUnique({ where: { id: txn.createdById }, select: { name: true } });
        senderName = sender?.name || null;

        let message = txn.note || '';
        let requesterName = null;
        let approvalProgress = null;
        let changeSummaryBn = null;
        let changeSummaryEn = null;
        let oldAmount = null;
        let newAmount = null;
        let oldNote = null;
        let newNote = null;
        let requiredApprovalCount = null;

        if (txn.pendingAction && ['edit', 'delete'].includes(txn.pendingAction)) {
          const pd = parsePendingData(txn.pendingData);
          requesterName = pd.requesterName || null;
          requiredApprovalCount = pd.requiredApprovalCount ?? (pd.requiredApprovers || []).length;
          const summary = buildChangeDeleteNotification(txn.pendingData, txn.pendingAction, txn);
          changeSummaryBn = summary.bn;
          changeSummaryEn = summary.en;
          message = summary.shortBn;
          approvalProgress = summary.progress;
          oldAmount = summary.oldAmount ?? pd.oldAmount ?? null;
          newAmount = summary.newAmount ?? txn.amount ?? null;
          oldNote = summary.oldNote ?? pd.oldNote ?? null;
          newNote = summary.newNote ?? txn.note ?? null;
        }

        result.push({
          type: (txn.category === 'Send' || txn.recipientOrgId) ? 'disbursement_approval' : 'voucher_approval',
          id: txn.id,
          refId: txn.id,
          title: actionLabel,
          message,
          amount: txn.amount,
          category: txn.category,
          recipientName,
          bookName,
          orgName,
          createdAt: txn.createdAt,
          pendingAction: txn.pendingAction,
          reconStatus: txn.reconStatus,
          counterProposedAmount: txn.counterProposedAmount,
          counterProposedBy: txn.counterProposedBy,
          senderName,
          requesterName,
          approvalProgress,
          changeSummaryBn,
          changeSummaryEn,
          oldAmount,
          newAmount,
          oldNote,
          newNote,
          requiredApprovalCount,
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
        category: 'Send'
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
        categories: DEFAULT_CATEGORIES,
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

    const target = await prisma.organizationMember.findUnique({ where: { id: req.params.memberId } });
    if (!target) return res.status(404).json({ error: 'Member not found' });

    if (target.role === 'admin' && role !== 'admin') {
      const adminCount = await prisma.organizationMember.count({
        where: {
          organizationId: req.params.orgId,
          role: 'admin',
          status: 'active'
        }
      });
      if (adminCount <= 1) {
        return res.status(400).json({ error: 'At least one admin must remain in the organization' });
      }
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

// Remove Member / Leave Organization
app.delete('/api/org/:orgId/members/:memberId', authenticateToken, async (req, res) => {
  try {
    const callerMembership = await prisma.organizationMember.findUnique({
      where: { userId_organizationId: { userId: req.user.id, organizationId: req.params.orgId } }
    });
    if (!callerMembership || callerMembership.status !== 'active') {
      return res.status(403).json({ error: 'Not an active member of this organization' });
    }

    const target = await prisma.organizationMember.findUnique({ where: { id: req.params.memberId } });
    if (!target) return res.status(404).json({ error: 'Member not found' });

    const isSelf = target.userId === req.user.id;

    // If not self, caller must be admin or have manage_members permission
    if (!isSelf && callerMembership.role !== 'admin' && !(callerMembership.permissions || []).includes('manage_members')) {
      return res.status(403).json({ error: 'Only admins or users with manage_members permission can remove members' });
    }

    // If target is admin, make sure they are not the last admin
    if (target.role === 'admin') {
      const adminCount = await prisma.organizationMember.count({
        where: {
          organizationId: req.params.orgId,
          role: 'admin',
          status: 'active'
        }
      });
      if (adminCount <= 1) {
        return res.status(400).json({ error: 'At least one admin must remain in the organization' });
      }
    }

    await prisma.organizationMember.delete({ where: { id: req.params.memberId } });
    res.json({ message: isSelf ? 'You left the organization' : 'Member removed' });
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

    // Collect IDs of transactions being deleted (for cleaning up linkedTransactionId)
    const deletingTxnIds = (await prisma.transaction.findMany({
      where: { bookId: { in: bookIds } },
      select: { id: true }
    })).map(t => t.id);

    // Clean up orphaned references in other books' transactions
    await prisma.$transaction([
      // Clear recipientOrgId in transactions that were sent TO this org
      prisma.transaction.updateMany({
        where: { recipientOrgId: req.params.orgId },
        data: { recipientOrgId: null }
      }),
      // Clear orgFundId in transactions that used this org's books as fund source
      prisma.transaction.updateMany({
        where: { orgFundId: { in: bookIds } },
        data: { orgFundId: null }
      }),
      // Clear linkedTransactionId pointing to deleted transactions
      prisma.transaction.updateMany({
        where: { linkedTransactionId: { in: deletingTxnIds } },
        data: { linkedTransactionId: null }
      }),
      // Delete org's own members, transactions, and books
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

// ─── AI Agent Helpers ───────────────────────────────────────────────────────
const AI_ACTION_BLOCK_REGEX = /```action\s*([\s\S]*?)```/g;

const stripAiActionBlocks = (text) => (text || '').replace(AI_ACTION_BLOCK_REGEX, '').trim();

const getLastUserMessage = (messages) => {
  const last = [...(messages || [])].reverse().find(m => m.role === 'user');
  return (last?.content || '').trim();
};

const extractTransactionPreviewNotes = (aiResponseText) => {
  const regex = /\[DATA type:transactions\]([\s\S]*?)\[\/DATA\]/g;
  const previews = [];
  for (const match of aiResponseText.matchAll(regex)) {
    try {
      const items = JSON.parse(match[1].trim());
      if (Array.isArray(items)) {
        for (const item of items) {
          if (item && typeof item === 'object') previews.push(item);
        }
      }
    } catch (_) { /* skip malformed preview blocks */ }
  }
  return previews;
};

const resolveAiTransactionNote = ({ note, description, amount, previewNotes, lastUserMessage, category }) => {
  const direct = (note || description || '').trim();
  if (direct) return direct;

  const parsedAmount = parseFloat(amount);
  if (Number.isFinite(parsedAmount) && previewNotes?.length) {
    const match = previewNotes.find(
      p => p?.note && Math.abs(parseFloat(p.amount) - parsedAmount) < 0.01
    );
    if (match?.note) return String(match.note).trim();
    if (previewNotes.length === 1 && previewNotes[0]?.note) {
      return String(previewNotes[0].note).trim();
    }
  }

  if (lastUserMessage) return lastUserMessage;
  return (category || 'General').trim();
};

const detectAiIntent = (messages) => {
  const lastUser = [...(messages || [])].reverse().find(m => m.role === 'user');
  const q = (lastUser?.content || '').toLowerCase();
  if (/(balance|ব্যালেন্স|balence|মোট ব্যালেন্স|total balance|কত টাকা আছে|how much money)/i.test(q)) {
    return 'balance';
  }
  if (/(category|ক্যাটাগরি|খরচের হার|spending breakdown|বিভাগে খরচ|কোন খাতে)/i.test(q)) {
    return 'category';
  }
  if (/(recent|সাম্প্রতিক|latest|গত|last \d+|লেনদেন দেখ|transaction list|লেনদেন তালিকা)/i.test(q)) {
    return 'recent';
  }
  if (/(help|সাহায্য|কী কর|ki korte|how to|কিভাবে)/i.test(q) && !/\d/.test(q)) {
    return 'help';
  }
  if (/\d/.test(q) && /(খরচ|expense|income|আয়|লেনদেন|record|যোগ|add|rickshaw|রিকশা|bazar|বাজার|send|পাঠ)/i.test(q)) {
    return 'transaction';
  }
  return 'general';
};

const AI_LLM_HISTORY_LIMIT = 6;
const AI_LLM_CONTENT_LIMIT = 1800;

const truncateAiMessagesForLlm = (messages, maxCount = AI_LLM_HISTORY_LIMIT) => {
  if (!Array.isArray(messages)) return [];
  return messages.slice(-maxCount).map(m => ({
    role: m.role,
    content: String(m.content || '').slice(0, AI_LLM_CONTENT_LIMIT),
  }));
};

const resolveAiMaxTokens = (maxTokens) => {
  const parsed = maxTokens != null ? parseInt(maxTokens, 10) : 512;
  if (!Number.isFinite(parsed)) return 512;
  return Math.min(Math.max(parsed, 128), 1024);
};

const saveAiChatTurn = async ({ userId, userMessage, assistantMessage, bookId, model, provider, intent }) => {
  const userText = String(userMessage || '').trim();
  const assistantText = String(assistantMessage || '').trim();
  if (!userId || !userText || !assistantText) return;
  try {
    await prisma.aiChatMessage.createMany({
      data: [
        { userId, role: 'user', content: userText, bookId: bookId || null, model: model || null, provider: provider || null, intent: intent || null },
        { userId, role: 'assistant', content: assistantText, bookId: bookId || null, model: model || null, provider: provider || null, intent: intent || null },
      ],
    });
  } catch (error) {
    console.error('[AI Chat] Failed to save turn:', error);
  }
};

const tryOffTopicAiResponse = (messages, agentCtx) => {
  const lastUserMessage = getLastUserMessage(messages);
  const { intent } = agentCtx;
  if (intent !== 'general') return { handled: false };

  const appRelated = /(hisab|হিসাব|pata|পাতা|balance|ব্যালেন্স|transaction|লেনদেন|book|খাতা|org|সংগঠন|send|expense|income|খরচ|আয়|category|approval|অনুমোদন|টাকা|taka|ledger|account|fund|rickshaw|বাজার|salary|বেতন|personal|member|admin|editor)/i;
  if (appRelated.test(lastUserMessage || '')) return { handled: false };

  const isBn = isBanglaMessage(lastUserMessage);
  const text = isBn
    ? 'আমি শুধু হিসাব পাতা অ্যাপের হিসাব, খাতা ও লেনদেন নিয়ে সাহায্য করি। ব্যালেন্স, খরচ বা লেনদেন যোগ করতে বলুন।'
    : 'I only help with Hisab Pata books, balances, and transactions. Ask about your balance, spending, or adding a transaction.';
  return { handled: true, cleanResponse: text, proposedActions: [] };
};

const isBanglaMessage = (text) => /[\u0980-\u09FF]/.test(text || '');

const CATEGORY_KEYWORDS = [
  { keys: ['rickshaw', 'রিকশা', 'bus', 'বাস', 'transport', 'যাতায়াত', 'pathao', 'uber', 'cng'], cat: 'Transport' },
  { keys: ['food', 'খাবার', 'breakfast', 'lunch', 'dinner', 'snack', 'নাস্তা'], cat: 'Food' },
  { keys: ['bazar', 'বাজার', 'market', 'grocery', 'সবজি'], cat: 'Shopping' },
  { keys: ['bill', 'বিল', 'electric', 'gas', 'internet', 'mobile'], cat: 'Bills' },
  { keys: ['salary', 'বেতন', 'income', 'আয়', 'donation', 'দান'], cat: 'Income' },
  { keys: ['medicine', 'doctor', 'চিকিৎসা', 'hospital'], cat: 'Medical' },
  { keys: ['education', 'school', 'college', 'শিক্ষা', 'book'], cat: 'Education' },
];

const parseTransactionHints = (text, booksWithOrg, defaultBookId) => {
  const q = (text || '').toLowerCase();
  const amountMatch = (text || '').match(/(\d+(?:[.,]\d+)?)\s*(?:টাকা|taka|tk|bdt|৳)?/i);
  const amount = amountMatch ? parseFloat(String(amountMatch[1]).replace(',', '')) : null;

  let type = 'expense';
  if (/(income|আয়|salary|বেতন|received|পেলাম|জমা|donation|দান)/i.test(text || '')) {
    type = 'income';
  }

  let category = type === 'income' ? 'Income' : 'General';
  for (const { keys, cat } of CATEGORY_KEYWORDS) {
    if (keys.some(k => q.includes(k.toLowerCase()))) {
      category = cat;
      break;
    }
  }

  let matchedEntry = null;
  for (const entry of booksWithOrg) {
    const name = entry.book.name.toLowerCase();
    if (name.length > 2 && q.includes(name)) {
      matchedEntry = entry;
      break;
    }
  }
  if (!matchedEntry && /(personal|পার্সোনাল|personal book|নিজের)/i.test(text || '')) {
    matchedEntry = booksWithOrg.find(x => x.isPersonal) || null;
  }
  if (!matchedEntry && defaultBookId) {
    matchedEntry = booksWithOrg.find(x => x.book.id === defaultBookId) || null;
  }

  return {
    amount,
    type,
    category,
    bookId: matchedEntry?.book.id || null,
    bookName: matchedEntry?.book.name || null,
    orgName: matchedEntry?.orgName || null,
    isPersonal: matchedEntry?.isPersonal ?? null,
  };
};

const resolveBookFromMessage = (text, booksWithOrg, defaultBookId) => {
  const hints = parseTransactionHints(text, booksWithOrg, defaultBookId);
  return hints.bookId || defaultBookId || null;
};

const formatTransactionsDataBlock = (transactions) => {
  const payload = transactions.map(t => ({
    note: t.note || t.category || '',
    amount: t.amount,
    type: t.type || 'expense',
    category: t.category || 'General',
  }));
  return `[DATA type:transactions]\n${JSON.stringify(payload)}\n[/DATA]`;
};

const buildTransactionAction = (hints, lastUserMessage, bookRecord) => ({
  action: 'create_transaction',
  data: {
    bookId: bookRecord.id,
    bookName: bookRecord.name,
    orgName: bookRecord.organization?.name || 'Unknown',
    type: hints.type,
    amount: hints.amount,
    category: hints.category,
    note: resolveAiTransactionNote({
      note: '',
      description: '',
      amount: hints.amount,
      previewNotes: [{ note: lastUserMessage, amount: hints.amount }],
      lastUserMessage,
      category: hints.category,
    }),
    dateTime: new Date().toISOString(),
    contact: '',
    recipientUserId: null,
    orgFundId: null,
  },
  valid: true,
});

const tryDeterministicAiResponse = async (messages, agentCtx, userId) => {
  const lastUserMessage = getLastUserMessage(messages);
  const isBn = isBanglaMessage(lastUserMessage);
  const { intent, serverToolData, contextBookId, booksWithOrg, recentTxns, pendingApprovalCount } = agentCtx;

  if (intent === 'balance' && serverToolData.balanceBlock) {
    const books = serverToolData.balanceBooks || [];
    const total = books.reduce((sum, b) => sum + (b.balance || 0), 0);
    const text = isBn
      ? `আপনার ${books.length}টি খাতার মোট ব্যালেন্স ৳${Math.round(total)}।`
      : `Total balance across ${books.length} book(s): ৳${Math.round(total)}.`;
    return {
      handled: true,
      cleanResponse: `${text}\n\n${serverToolData.balanceBlock}`,
      proposedActions: [],
    };
  }

  if (intent === 'category' && serverToolData.categoryBlock) {
    const text = isBn
      ? 'আপনার approved খরচের ক্যাটাগরি breakdown নিচে দেখুন।'
      : 'Here is your approved spending breakdown by category.';
    return {
      handled: true,
      cleanResponse: `${text}\n\n${serverToolData.categoryBlock}`,
      proposedActions: [],
    };
  }

  if (intent === 'recent' && recentTxns?.length) {
    const preview = recentTxns.slice(0, 12).map(t => ({
      note: t.note || t.category || '',
      amount: t.amount,
      type: t.type,
      category: t.category,
    }));
    const text = isBn
      ? `সর্বশেষ ${preview.length}টি লেনদেন নিচে দেখুন।`
      : `Here are your latest ${preview.length} transactions.`;
    return {
      handled: true,
      cleanResponse: `${text}\n\n${formatTransactionsDataBlock(preview)}`,
      proposedActions: [],
    };
  }

  if (intent === 'help') {
    const text = isBn
      ? 'আপনি বলতে পারেন: "আমার ব্যালেন্স দেখাও", "ক্যাটাগরি অনুযায়ী খরচ", "personal book-এ ৫০ টাকা rickshaw খরচ"। লেনদেন approve করতে হবে।'
      : 'Try: "show my balance", "spending by category", or "add 50 taka rickshaw expense to personal book". Transactions need your approval.';
    return { handled: true, cleanResponse: text, proposedActions: [] };
  }

  if (intent === 'transaction' && agentCtx.transactionHints?.amount && agentCtx.transactionHints?.bookId) {
    const hints = agentCtx.transactionHints;
    const book = await prisma.book.findFirst({
      where: { id: hints.bookId },
      include: { organization: { include: { members: { where: { userId } } } } },
    });
    if (book && book.organization.members.length > 0) {
      const action = buildTransactionAction(hints, lastUserMessage, book);
      const preview = formatTransactionsDataBlock([{
        note: action.data.note,
        amount: action.data.amount,
        type: action.data.type,
        category: action.data.category,
      }]);
      const text = isBn
        ? `${book.name} খাতায় ৳${hints.amount} ${hints.type === 'income' ? 'আয়' : 'খরচ'} approval-এর জন্য প্রস্তুত।`
        : `Ready to add ৳${hints.amount} ${hints.type} to "${book.name}" for your approval.`;
      return {
        handled: true,
        cleanResponse: `${text}\n\n${preview}`,
        proposedActions: [action],
      };
    }
  }

  return { handled: false };
};

const fetchAiCategorySummary = async (userId, bookId) => {
  const memberships = await prisma.organizationMember.findMany({
    where: { userId, status: 'active' },
    include: { organization: { include: { books: true } } },
  });
  const bookIds = bookId
    ? [bookId]
    : memberships.flatMap(m => m.organization.books.map(b => b.id));
  const transactions = await prisma.transaction.findMany({
    where: { bookId: { in: bookIds }, type: 'expense', reconStatus: 'approved' },
    select: { category: true, amount: true },
  });
  const summary = {};
  let total = 0;
  for (const t of transactions) {
    const cat = t.category || 'Other';
    summary[cat] = (summary[cat] || 0) + t.amount;
    total += t.amount;
  }
  return Object.entries(summary)
    .map(([category, amount]) => ({
      category,
      amount: Math.round(amount * 100) / 100,
      percentage: total > 0 ? Math.round((amount / total) * 100) : 0,
      count: transactions.filter(t => (t.category || 'Other') === category).length,
    }))
    .sort((a, b) => b.amount - a.amount);
};

const formatBalanceDataBlock = (books) => {
  const payload = books.map(b => ({ book: b.name, balance: b.balance, org: b.organization }));
  return `[DATA type:balance]\n${JSON.stringify(payload)}\n[/DATA]`;
};

const formatCategoryDataBlock = (categories) => {
  const payload = categories.map(c => ({
    category: c.category,
    amount: c.amount,
    count: c.count,
    percentage: c.percentage,
  }));
  return `[DATA type:category]\n${JSON.stringify(payload)}\n[/DATA]`;
};

const prepareAiAgentRequest = async (userId, bookId, messages) => {
  const userOrgs = await prisma.organizationMember.findMany({
    where: { userId, status: 'active' },
    include: { organization: { include: { books: true } } },
  });

  const booksWithOrg = userOrgs.flatMap(m =>
    m.organization.books.map(b => ({
      book: b,
      orgName: m.organization.name,
      isPersonal: m.organization.isPersonal,
      role: m.role,
    }))
  );

  const allBooks = booksWithOrg.map(x => x.book);
  let contextBookId = resolveBookFromMessage(getLastUserMessage(messages), booksWithOrg, bookId);
  if (!contextBookId && allBooks.length > 0) {
    contextBookId = (allBooks.find(b => b.isDefault) || allBooks[0]).id;
  }

  const recentTxns = contextBookId
    ? await prisma.transaction.findMany({
        where: { bookId: contextBookId },
        orderBy: { dateTime: 'desc' },
        take: 8,
      })
    : [];

  const pendingApprovalCount = await prisma.transaction.count({
    where: {
      reconStatus: { in: ['pending_org', 'pending_recipient', 'pending'] },
      book: { organization: { members: { some: { userId, status: 'active' } } } },
    },
  });

  const userData = await prisma.user.findUnique({ where: { id: userId } });
  const intent = detectAiIntent(messages);
  const lastUserMessage = getLastUserMessage(messages);
  const booksForAiTxn = booksWithOrg.filter(({ role, isPersonal }) =>
    isPersonal || role === 'admin' || role === 'editor'
  );
  const transactionHints = parseTransactionHints(lastUserMessage, booksForAiTxn, contextBookId);
  const activeBookEntry = booksWithOrg.find(x => x.book.id === contextBookId);
  const recommendedTemperature = ['balance', 'category', 'recent', 'transaction', 'help'].includes(intent) ? 0.2 : 0.45;

  const orgSummary = userOrgs
    .filter(m => !m.organization.isPersonal)
    .map(m => `Org:"${m.organization.name}" Role:${m.role}`)
    .join(' | ') || 'None';

  const booksSummary = booksWithOrg
    .map(({ book, orgName, isPersonal, role }) =>
      `- ID:${book.id} Name:"${book.name}" Balance:${book.balance} BDT Org:"${isPersonal ? 'Personal' : orgName}" Role:${role}`)
    .join('\n');

  const txnSummary = recentTxns
    .map(t => `${t.type} ${t.amount} ${t.category || ''} ${(t.note || '').slice(0, 40)}`)
    .join(' | ') || 'None';

  const serverToolData = {};
  const balanceBooks = booksWithOrg.map(({ book, orgName, isPersonal }) => ({
    name: book.name,
    balance: book.balance,
    organization: isPersonal ? 'Personal' : orgName,
  }));

  if (intent === 'balance') {
    serverToolData.balanceBlock = formatBalanceDataBlock(balanceBooks);
    serverToolData.balanceBooks = balanceBooks;
  }
  if (intent === 'category') {
    const categories = await fetchAiCategorySummary(userId, contextBookId);
    serverToolData.categoryBlock = formatCategoryDataBlock(categories);
  }

  const hintsSection = transactionHints.amount
    ? `PARSED FROM USER MESSAGE: amount=${transactionHints.amount} type=${transactionHints.type} category=${transactionHints.category} bookId=${transactionHints.bookId || 'MISSING'} bookName="${transactionHints.bookName || ''}"`
    : 'PARSED FROM USER MESSAGE: amount not detected';

  const verifiedDataSection = [
    intent === 'balance' && serverToolData.balanceBlock
      ? `VERIFIED BALANCE DATA (copy this DATA block exactly, do not invent numbers):\n${serverToolData.balanceBlock}`
      : null,
    intent === 'category' && serverToolData.categoryBlock
      ? `VERIFIED CATEGORY DATA (copy this DATA block exactly, do not invent numbers):\n${serverToolData.categoryBlock}`
      : null,
  ].filter(Boolean).join('\n\n');

  const today = new Date().toISOString().split('T')[0];
  const systemPrompt = `You are Hisab Pata AI — finance assistant ONLY for the Hisab Pata ledger app.

SCOPE (strict):
- Answer ONLY about this app's books, balances, transactions, categories, approvals, org rules.
- If the user asks anything unrelated (general knowledge, other apps, coding, news, jokes), refuse in ONE short sentence and redirect to app finance tasks.
- Never discuss other products or your underlying AI model.

RULES:
- Personal org is not a real organization. Org book outflow is Send only.
- Never say a transaction is saved; say it is ready for user approval.
- Use book IDs from USER BOOKS for transaction actions.

USER: ${userData?.name || 'User'}
ACTIVE BOOK: ${activeBookEntry ? `"${activeBookEntry.book.name}" (${activeBookEntry.book.id})` : 'None'}
PENDING APPROVALS: ${pendingApprovalCount}
ORGS: ${orgSummary}
BOOKS:
${booksSummary || 'None'}
RECENT TXNS: ${txnSummary}
${hintsSection}
${verifiedDataSection ? `\nVERIFIED DATA:\n${verifiedDataSection}\n` : ''}

TRANSACTIONS: use PARSED values when bookId exists; otherwise ask which book (names only). note is required from user's words.

RESPONSE:
- Plain text, no markdown. Max 2 short sentences (Bangla or English).
- Include VERIFIED DATA blocks unchanged for balance/category.
- For new transactions with amount+book: add [DATA type:transactions] preview + action block:
\`\`\`action
{"action":"create_transaction","data":{"bookId":"<id>","type":"expense","amount":500,"category":"Transport","note":"...","dateTime":"${today}"}}
\`\`\`

DATA formats:
[DATA type:balance] [{"book":"Name","balance":1000,"org":"OrgName"}] [/DATA]
[DATA type:category] [{"category":"Food","amount":500,"count":3,"percentage":40}] [/DATA]
[DATA type:transactions] [{"note":"...","amount":50,"type":"expense","category":"Transport"}] [/DATA]

If amount or book missing, ask ONE clarifying question. No action blocks yet.`;

  return {
    systemPrompt,
    contextBookId,
    intent,
    serverToolData,
    booksWithOrg,
    recentTxns,
    pendingApprovalCount,
    transactionHints,
    recommendedTemperature,
  };
};

const parseAiAgentActions = async (aiResponseText, contextBookId, userId, { onComplaint, lastUserMessage, previewNotes } = {}) => {
  const matches = [...aiResponseText.matchAll(AI_ACTION_BLOCK_REGEX)];
  let cleanResponse = stripAiActionBlocks(aiResponseText);
  const proposedActions = [];
  const txnPreviews = previewNotes || extractTransactionPreviewNotes(aiResponseText);
  const userMsg = lastUserMessage || '';

  for (const match of matches) {
    try {
      const actionData = JSON.parse(match[1].trim());
      if (actionData.action === 'create_transaction' && actionData.data) {
        const { bookId: txnBookId, type, amount, category, note, dateTime, contact, recipientUserId, orgFundId, description } = actionData.data;
        const resolvedNote = resolveAiTransactionNote({
          note,
          description,
          amount,
          previewNotes: txnPreviews,
          lastUserMessage: userMsg,
          category,
        });
        const book = await prisma.book.findFirst({
          where: { id: txnBookId || contextBookId },
          include: { organization: { include: { members: { where: { userId } } } } },
        });
        if (!book || book.organization.members.length === 0) {
          proposedActions.push({
            action: 'create_transaction',
            data: { ...actionData.data, note: resolvedNote },
            valid: false,
            reason: 'Book not found or access denied',
          });
        } else {
          proposedActions.push({
            action: 'create_transaction',
            data: {
              bookId: book.id,
              bookName: book.name,
              orgName: book.organization?.name || 'Unknown',
              type,
              amount: parseFloat(amount),
              category: category || 'General',
              note: resolvedNote,
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
              data: { userId, subject, message, category: category || 'Other' },
            });
            if (onComplaint) {
              onComplaint({ subject, id: complaint.id });
            } else {
              cleanResponse += `\n\nআপনার রিপোর্ট "${subject}" জমা হয়েছে।`;
            }
          } catch (err) {
            console.error('[AI Agent] Auto-execute complaint failed:', err);
          }
        }
      }
    } catch (parseErr) {
      console.error('[AI Agent] Action parse error:', parseErr);
    }
  }

  return { cleanResponse, proposedActions };
};

const finalizeAiAgentResponse = async (aiResponseText, { contextBookId, userId, intent, serverToolData, onComplaint, messages }) => {
  const lastUserMessage = getLastUserMessage(messages);
  const previewNotes = extractTransactionPreviewNotes(aiResponseText);
  const { cleanResponse: baseClean, proposedActions } = await parseAiAgentActions(
    aiResponseText,
    contextBookId,
    userId,
    { onComplaint, lastUserMessage, previewNotes }
  );
  let cleanResponse = baseClean;

  if (intent === 'balance' && serverToolData?.balanceBlock && !cleanResponse.includes('[DATA type:balance]')) {
    cleanResponse = cleanResponse
      ? `${cleanResponse}\n\n${serverToolData.balanceBlock}`
      : serverToolData.balanceBlock;
  }
  if (intent === 'category' && serverToolData?.categoryBlock && !cleanResponse.includes('[DATA type:category]')) {
    cleanResponse = cleanResponse
      ? `${cleanResponse}\n\n${serverToolData.categoryBlock}`
      : serverToolData.categoryBlock;
  }

  return { cleanResponse: cleanResponse.trim(), proposedActions };
};

const emitAiStreamFinal = async (sendEvent, fullText, agentCtx, userId, messages, meta = {}) => {
  const { cleanResponse, proposedActions } = await finalizeAiAgentResponse(fullText, {
    ...agentCtx,
    userId,
    messages,
    onComplaint: ({ subject, id }) => sendEvent('auto_action', { action: 'create_complaint', subject, id }),
  });
  if (proposedActions.length > 0) sendEvent('actions', { actions: proposedActions });
  sendEvent('clean', { response: cleanResponse });
  await saveAiChatTurn({
    userId,
    userMessage: getLastUserMessage(messages),
    assistantMessage: cleanResponse,
    bookId: agentCtx.contextBookId,
    model: meta.model || null,
    provider: meta.provider || null,
    intent: agentCtx.intent || null,
  });
};

// ─────────────────────────────────────────────────────────────────────────────
// AGENTIC AI ROUTE — Tool Calling & Action Execution
// ─────────────────────────────────────────────────────────────────────────────
app.post('/api/ai/agent', authenticateToken, async (req, res) => {
  try {
    const storedConfig = await loadUserAiConfig(req.user.id);
    const resolved = resolveAiRequestConfig(req.body, storedConfig);
    const { provider, apiKey, model, baseUrl, messages, bookId, orgId, temperature, maxTokens } = {
      ...req.body,
      provider: resolved.provider,
      apiKey: resolved.apiKey,
      model: resolved.model,
      baseUrl: resolved.baseUrl,
      temperature: resolved.temperature,
      maxTokens: resolved.maxTokens,
    };

    if (!provider || !apiKey || !model || !messages) {
      return res.status(400).json({ error: 'Missing required fields: provider, apiKey, model, messages' });
    }

    const agentCtx = await prepareAiAgentRequest(req.user.id, bookId, messages);
    const { systemPrompt, contextBookId, intent, serverToolData, recommendedTemperature } = agentCtx;
    const llmMessages = truncateAiMessagesForLlm(messages);

    const deterministic = await tryDeterministicAiResponse(messages, agentCtx, req.user.id);
    if (deterministic.handled) {
      await saveAiChatTurn({
        userId: req.user.id,
        userMessage: getLastUserMessage(messages),
        assistantMessage: deterministic.cleanResponse,
        bookId: contextBookId,
        model,
        provider,
        intent,
      });
      return res.json({
        response: deterministic.cleanResponse,
        proposedActions: deterministic.proposedActions || [],
      });
    }

    const offTopic = tryOffTopicAiResponse(messages, agentCtx);
    if (offTopic.handled) {
      await saveAiChatTurn({
        userId: req.user.id,
        userMessage: getLastUserMessage(messages),
        assistantMessage: offTopic.cleanResponse,
        bookId: contextBookId,
        model,
        provider,
        intent: 'off_topic',
      });
      return res.json({
        response: offTopic.cleanResponse,
        proposedActions: [],
      });
    }

    const tempVal = temperature != null ? parseFloat(temperature) : recommendedTemperature;
    const maxTokVal = resolveAiMaxTokens(maxTokens);

    // ── Forward to AI Provider ──
    let aiResponseText = '';

    if (provider === 'gemini') {
      const url = baseUrl
        ? `${baseUrl}/v1beta/models/${model}:generateContent?key=${apiKey}`
        : `https://generativelanguage.googleapis.com/v1beta/models/${model}:generateContent?key=${apiKey}`;

      const contents = llmMessages.map(m => ({
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
        ...llmMessages.map(m => ({ role: m.role, content: m.content }))
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
          messages: llmMessages.map(m => ({ role: m.role, content: m.content }))
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

    const { cleanResponse, proposedActions } = await finalizeAiAgentResponse(aiResponseText, {
      contextBookId,
      userId: req.user.id,
      intent,
      serverToolData,
      messages,
    });

    await saveAiChatTurn({
      userId: req.user.id,
      userMessage: getLastUserMessage(messages),
      assistantMessage: cleanResponse,
      bookId: contextBookId,
      model,
      provider,
      intent,
    });

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
    const storedConfig = await loadUserAiConfig(req.user.id);
    const resolved = resolveAiRequestConfig(req.body, storedConfig);
    const { provider, apiKey, model, baseUrl, messages, bookId, orgId, temperature, maxTokens } = {
      ...req.body,
      provider: resolved.provider,
      apiKey: resolved.apiKey,
      model: resolved.model,
      baseUrl: resolved.baseUrl,
      temperature: resolved.temperature,
      maxTokens: resolved.maxTokens,
    };

    if (!provider || !apiKey || !model || !messages) {
      return res.status(400).json({ error: 'Missing required fields: provider, apiKey, model, messages' });
    }

    const agentCtx = await prepareAiAgentRequest(req.user.id, bookId, messages);
    const { systemPrompt, contextBookId, intent, recommendedTemperature } = agentCtx;
    const llmMessages = truncateAiMessagesForLlm(messages);

    // ── Set up SSE ──
    res.setHeader('Content-Type', 'text/event-stream');
    res.setHeader('Cache-Control', 'no-cache');
    res.setHeader('Connection', 'keep-alive');
    res.flushHeaders();

    const sendEvent = (type, data) => {
      res.write(`data: ${JSON.stringify({ type, ...data })}\n\n`);
    };

    const deterministic = await tryDeterministicAiResponse(messages, agentCtx, req.user.id);
    if (deterministic.handled) {
      await saveAiChatTurn({
        userId: req.user.id,
        userMessage: getLastUserMessage(messages),
        assistantMessage: deterministic.cleanResponse,
        bookId: contextBookId,
        model,
        provider,
        intent,
      });
      sendEvent('clean', { response: deterministic.cleanResponse });
      if (deterministic.proposedActions?.length) {
        sendEvent('actions', { actions: deterministic.proposedActions });
      }
      sendEvent('done', {});
      return res.end();
    }

    const offTopic = tryOffTopicAiResponse(messages, agentCtx);
    if (offTopic.handled) {
      await saveAiChatTurn({
        userId: req.user.id,
        userMessage: getLastUserMessage(messages),
        assistantMessage: offTopic.cleanResponse,
        bookId: contextBookId,
        model,
        provider,
        intent: 'off_topic',
      });
      sendEvent('clean', { response: offTopic.cleanResponse });
      sendEvent('done', {});
      return res.end();
    }

    const tempVal = temperature != null ? parseFloat(temperature) : recommendedTemperature;
    const maxTokVal = resolveAiMaxTokens(maxTokens);

    if (provider === 'gemini') {
      const url = baseUrl
        ? `${baseUrl}/v1beta/models/${model}:streamGenerateContent?alt=sse&key=${apiKey}`
        : `https://generativelanguage.googleapis.com/v1beta/models/${model}:streamGenerateContent?alt=sse&key=${apiKey}`;

      const contents = llmMessages.map(m => ({
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

      await emitAiStreamFinal(sendEvent, fullText, agentCtx, req.user.id, messages, { model, provider });

    } else if (provider === 'openai') {
      const url = baseUrl ? `${baseUrl}/v1/chat/completions` : 'https://api.openai.com/v1/chat/completions';
      const formattedMessages = [
        { role: 'system', content: systemPrompt },
        ...llmMessages.map(m => ({ role: m.role, content: m.content }))
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

      await emitAiStreamFinal(sendEvent, fullText, agentCtx, req.user.id, messages, { model, provider });

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
          messages: llmMessages.map(m => ({ role: m.role, content: m.content })),
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

      await emitAiStreamFinal(sendEvent, fullText, agentCtx, req.user.id, messages, { model, provider });

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
      const { bookId, type, amount, category, note, description, dateTime, contact, recipientUserId, orgFundId } = data;
      const resolvedNote = (note || description || '').trim();

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
        note: resolvedNote,
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

app.get('/api/admin/ai-chats', authenticateAdmin, async (req, res) => {
  try {
    const limit = Math.min(parseInt(req.query.limit, 10) || 100, 500);
    const userId = req.query.userId;
    const where = userId ? { userId } : {};
    const messages = await prisma.aiChatMessage.findMany({
      where,
      include: { user: { select: { id: true, name: true, email: true, phoneNumber: true } } },
      orderBy: { createdAt: 'desc' },
      take: limit,
    });
    res.json(messages);
  } catch (error) {
    console.error('[Admin] Failed to fetch AI chats:', error);
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

// --- ADMIN: List all organizations ---
app.get('/api/admin/orgs', authenticateAdmin, async (req, res) => {
  try {
    const orgs = await prisma.organization.findMany({
      include: {
        _count: { select: { members: true, books: true } },
        members: { where: { role: 'admin', status: 'active' }, include: { user: { select: { id: true, name: true, email: true } } } }
      },
      orderBy: { createdAt: 'desc' },
    });
    const result = orgs.map(o => ({
      id: o.id, name: o.name, isPersonal: o.isPersonal, inviteCode: o.inviteCode,
      approvalPolicy: o.approvalPolicy, createdAt: o.createdAt,
      memberCount: o._count.members, bookCount: o._count.books,
      admins: o.members.map(m => ({ id: m.user.id, name: m.user.name, email: m.user.email }))
    }));
    res.json(result);
  } catch (error) {
    console.error('[Admin] Failed to fetch orgs:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// --- ADMIN: List members of an organization ---
app.get('/api/admin/orgs/:id/members', authenticateAdmin, async (req, res) => {
  try {
    const members = await prisma.organizationMember.findMany({
      where: { organizationId: req.params.id },
      include: { user: { select: { id: true, name: true, email: true, phoneNumber: true, isAdmin: true } } },
      orderBy: { createdAt: 'desc' },
    });
    res.json(members.map(m => ({
      id: m.id, userId: m.userId, role: m.role, status: m.status, permissions: m.permissions, createdAt: m.createdAt,
      user: m.user
    })));
  } catch (error) {
    console.error('[Admin] Failed to fetch members:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// --- ADMIN: Remove member from organization ---
app.delete('/api/admin/orgs/:id/members/:memberId', authenticateAdmin, async (req, res) => {
  try {
    const member = await prisma.organizationMember.findUnique({ where: { id: req.params.memberId } });
    if (!member) return res.status(404).json({ error: 'Member not found' });
    if (member.organizationId !== req.params.id) return res.status(400).json({ error: 'Member does not belong to this org' });
    await prisma.organizationMember.delete({ where: { id: req.params.memberId } });
    res.json({ message: 'Member removed' });
  } catch (error) {
    console.error('[Admin] Failed to remove member:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// --- ADMIN: Delete organization ---
app.delete('/api/admin/orgs/:id', authenticateAdmin, async (req, res) => {
  try {
    const org = await prisma.organization.findUnique({ where: { id: req.params.id } });
    if (!org) return res.status(404).json({ error: 'Organization not found' });

    const bookIds = (await prisma.book.findMany({ where: { organizationId: req.params.id }, select: { id: true } })).map(b => b.id);
    const txnIds = bookIds.length > 0
      ? (await prisma.transaction.findMany({ where: { bookId: { in: bookIds } }, select: { id: true } })).map(t => t.id)
      : [];

    await prisma.$transaction([
      prisma.transaction.updateMany({ where: { recipientOrgId: req.params.id }, data: { recipientOrgId: null } }),
      ...(bookIds.length > 0 ? [prisma.transaction.updateMany({ where: { orgFundId: { in: bookIds } }, data: { orgFundId: null } })] : []),
      ...(txnIds.length > 0 ? [prisma.transaction.updateMany({ where: { linkedTransactionId: { in: txnIds } }, data: { linkedTransactionId: null } })] : []),
      prisma.organizationMember.deleteMany({ where: { organizationId: req.params.id } }),
      ...(bookIds.length > 0 ? [prisma.transaction.deleteMany({ where: { bookId: { in: bookIds } } })] : []),
      ...(bookIds.length > 0 ? [prisma.book.deleteMany({ where: { organizationId: req.params.id } })] : []),
      prisma.organization.delete({ where: { id: req.params.id } }),
    ]);

    res.json({ message: 'Organization deleted successfully' });
  } catch (error) {
    console.error('[Admin] Failed to delete org:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// --- ADMIN: Delete user ---
app.delete('/api/admin/users/:id', authenticateAdmin, async (req, res) => {
  try {
    const user = await prisma.user.findUnique({ where: { id: req.params.id } });
    if (!user) return res.status(404).json({ error: 'User not found' });

    // Delete user's complaints, memberships, transactions, books, personal orgs
    await prisma.complaint.deleteMany({ where: { userId: req.params.id } });
    await prisma.organizationMember.deleteMany({ where: { userId: req.params.id } });

    // Find and delete user's personal orgs and their data
    const personalOrgs = await prisma.organization.findMany({ where: { isPersonal: true, members: { some: { userId: req.params.id } } } });
    for (const org of personalOrgs) {
      await prisma.transaction.deleteMany({ where: { book: { organizationId: org.id } } });
      await prisma.book.deleteMany({ where: { organizationId: org.id } });
      await prisma.organizationMember.deleteMany({ where: { organizationId: org.id } });
      await prisma.organization.delete({ where: { id: org.id } });
    }

    await prisma.user.delete({ where: { id: req.params.id } });
    res.json({ message: 'User deleted' });
  } catch (error) {
    console.error('[Admin] Failed to delete user:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// --- ADMIN: System-wide analytics ---
app.get('/api/admin/stats', authenticateAdmin, async (req, res) => {
  try {
    const [userCount, orgCount, bookCount, txnCount, totalExpense, totalIncome] = await Promise.all([
      prisma.user.count(),
      prisma.organization.count(),
      prisma.book.count(),
      prisma.transaction.count(),
      prisma.transaction.aggregate({ _sum: { amount: true }, where: { type: 'expense', reconStatus: 'approved' } }),
      prisma.transaction.aggregate({ _sum: { amount: true }, where: { type: 'income', reconStatus: 'approved' } }),
    ]);

    const orgTypeCounts = await prisma.organization.groupBy({
      by: ['isPersonal'],
      _count: true,
    });

    const memberCount = await prisma.organizationMember.count({ where: { status: 'active' } });
    const pendingMemberCount = await prisma.organizationMember.count({ where: { status: 'pending' } });

    res.json({
      totalUsers: userCount,
      totalOrganizations: orgCount,
      personalOrgs: orgTypeCounts.find(o => o.isPersonal)?._count || 0,
      groupOrgs: orgTypeCounts.find(o => !o.isPersonal)?._count || 0,
      totalBooks: bookCount,
      totalTransactions: txnCount,
      totalExpense: totalExpense._sum.amount || 0,
      totalIncome: totalIncome._sum.amount || 0,
      activeMembers: memberCount,
      pendingMembers: pendingMemberCount,
    });
  } catch (error) {
    console.error('[Admin] Failed to fetch stats:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// --- ADMIN: System status ---
app.get('/api/admin/system', authenticateAdmin, async (req, res) => {
  try {
    let dbOk = false;
    try {
      await prisma.$queryRaw`SELECT 1`;
      dbOk = true;
    } catch (e) { dbOk = false; }

    const memory = process.memoryUsage();
    res.json({
      status: dbOk ? 'healthy' : 'degraded',
      nodeVersion: process.version,
      platform: process.platform,
      uptime: process.uptime(),
      memory: {
        rss: Math.round(memory.rss / 1024 / 1024),
        heapTotal: Math.round(memory.heapTotal / 1024 / 1024),
        heapUsed: Math.round(memory.heapUsed / 1024 / 1024),
      },
      database: dbOk ? 'connected' : 'disconnected',
      env: process.env.NODE_ENV || 'development',
      timestamp: new Date().toISOString(),
    });
  } catch (error) {
    console.error('[Admin] Failed to fetch system status:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// --- ADMIN: Reset database (DANGER: deletes all data) ---
app.post('/api/admin/reset', authenticateAdmin, async (req, res) => {
  try {
    // Delete in correct order to respect foreign keys
    await prisma.transaction.deleteMany();
    await prisma.book.deleteMany();
    await prisma.organizationMember.deleteMany();
    await prisma.organization.deleteMany();
    await prisma.complaint.deleteMany();
    await prisma.user.deleteMany();
    res.json({ message: 'Database reset complete. Seed account will be recreated on restart.' });
  } catch (error) {
    console.error('[Admin] Failed to reset database:', error);
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

  ws.on('error', () => { });
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
      try { if (client.readyState === 1) client.send(msg); } catch (e) { }
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
        try { if (client.readyState === 1) client.send(msg); } catch (e) { }
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
