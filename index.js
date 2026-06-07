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
const sharp = require('sharp');
const { S3Client, PutObjectCommand, GetObjectCommand } = require('@aws-sdk/client-s3');

// ─── S3-Compatible Object Storage (SeaweedFS S3 / MinIO / Cloudflare R2) ─────
// Set STORAGE_S3_ENDPOINT in .env to enable. Falls back to local /uploads.
// Folder structure under bucket:
//   profile-pictures/  → user profile photos
//   org-profile/       → organization logos
//   vouchers/          → transaction/voucher attachments
//   audio/             → voice notes
//   files/             → generic fallback
const s3Endpoint  = process.env.STORAGE_S3_ENDPOINT  ? process.env.STORAGE_S3_ENDPOINT.replace(/\/$/, '') : '';
const s3Bucket    = process.env.STORAGE_S3_BUCKET    || 'hisabpata';
const s3AccessKey = (process.env.STORAGE_S3_ACCESS_KEY || '').trim();
const s3SecretKey = (process.env.STORAGE_S3_SECRET_KEY || '').trim();
const s3Region    = process.env.STORAGE_S3_REGION     || 'us-east-1';
const s3ForcePathStyle = process.env.STORAGE_S3_FORCE_PATH_STYLE !== 'false';
const useS3       = !!s3Endpoint;

let s3Client = null;
function getS3Client() {
  if (!useS3) return null;
  if (!s3Client) {
    s3Client = new S3Client({
      endpoint: s3Endpoint,
      region: s3Region,
      forcePathStyle: s3ForcePathStyle,
      credentials: s3AccessKey && s3SecretKey
        ? { accessKeyId: s3AccessKey, secretAccessKey: s3SecretKey }
        : undefined,
    });
  }
  return s3Client;
}

const S3_FOLDERS = {
  'profile-pictures': 'profile-pictures',
  'org-profile':      'org-profile',
  'vouchers':         'vouchers',
  'audio':            'audio',
  'files':            'files',
};

function resolveS3Folder(requestedFolder, mimetype, filename) {
  if (requestedFolder && S3_FOLDERS[requestedFolder]) return S3_FOLDERS[requestedFolder];
  if (!mimetype) mimetype = '';
  if (mimetype.startsWith('audio/') || /\.(m4a|mp3|wav|aac|ogg|opus)$/i.test(filename)) return 'audio';
  return 'files';
}

// Upload local file to S3. Returns stored key (folder/filename) or null.
async function uploadToS3(localPath, filename, mimetype, folder) {
  if (!useS3) return null;
  const client = getS3Client();
  if (!client) return null;
  try {
    const resolvedFolder = resolveS3Folder(folder, mimetype, filename);
    let key              = `${resolvedFolder}/${filename}`;
    let contentType      = mimetype || 'application/octet-stream';
    let fileBuffer       = fs.readFileSync(localPath);

    if (contentType.startsWith('image/')) {
      try {
        fileBuffer = await sharp(fileBuffer)
          .webp({ quality: 85 })
          .toBuffer();
        contentType = 'image/webp';
        const newFilename = filename.replace(/\.[^/.]+$/, '.webp');
        key = `${resolvedFolder}/${newFilename}`;
      } catch (err) {
        console.error('Sharp compression failed, falling back to original:', err);
      }
    }

    await client.send(new PutObjectCommand({
      Bucket: s3Bucket,
      Key: key,
      Body: fileBuffer,
      ContentType: contentType,
    }));
    try { fs.unlinkSync(localPath); } catch (e) {}
    return key;
  } catch (error) {
    console.error('[S3 Storage] Upload error:', error?.message || error);
    return null;
  }
}

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
  limits: { fileSize: 100 * 1024 * 1024 }, // 100MB limit
  fileFilter: (req, file, cb) => {
    const filetypes = /jpeg|jpg|png|gif|webp|mp4|mov|avi|mkv|quicktime|mp3|m4a|wav|aac|ogg|webm|x-m4a/;
    const mimetype = filetypes.test(file.mimetype) || file.mimetype.includes('audio/');
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
// S3 proxy: /uploads/:folder/:filename → streams from S3 bucket
if (useS3) {
  app.get('/uploads/:folder/:filename', async (req, res, next) => {
    try {
      const client = getS3Client();
      if (!client) return next();
      const key = `${req.params.folder}/${req.params.filename}`;
      const result = await client.send(new GetObjectCommand({
        Bucket: s3Bucket,
        Key: key,
      }));
      if (!result.Body) return next();
      if (result.ContentType) res.setHeader('Content-Type', result.ContentType);
      if (result.ContentLength) res.setHeader('Content-Length', String(result.ContentLength));
      res.setHeader('Cache-Control', 'public, max-age=31536000');
      result.Body.pipe(res);
    } catch (e) { next(); }
  });
}
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
    storage: {
      mode: useS3 ? 's3' : 'local',
      bucket: useS3 ? s3Bucket : null,
      endpointConfigured: !!s3Endpoint,
      credentialsConfigured: !!(s3AccessKey && s3SecretKey),
      forcePathStyle: useS3 ? s3ForcePathStyle : null,
    },
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

// ─── BanglaSpeechAPI (Faster-Whisper Bengali ASR) ───────────────────────────
// Deploy BanglaSpeechAPI/server.py (e.g. stotext.shilpigosthi.com). Set in .env:
//   ASR_BASE_URL=https://stotext.shilpigosthi.com
//   ASR_API_KEY=<VALID_API_KEYS from BanglaSpeechAPI .env>
function getAsrConfig() {
  const base = (process.env.ASR_BASE_URL || 'https://stotext.shilpigosthi.com').replace(/\/$/, '');
  const key = (process.env.ASR_API_KEY || '').trim();
  return { base, key, enabled: !!key };
}

async function transcribeWithBanglaSpeechApi(filePath, originalName, mimeType) {
  const { base, key, enabled } = getAsrConfig();
  if (!enabled) return null;

  try {
    const buffer = fs.readFileSync(filePath);
    const form = new FormData();
    const blob = new Blob([buffer], { type: mimeType || 'audio/m4a' });
    form.append('audio_file', blob, originalName || 'audio.m4a');

    const asrRes = await fetch(`${base}/asr`, {
      method: 'POST',
      headers: { 'x-api-key': key },
      body: form,
      signal: AbortSignal.timeout(120000),
    });

    const body = (await asrRes.text()).trim();
    if (!asrRes.ok) {
      console.error('[ASR] HTTP', asrRes.status, body.slice(0, 300));
      return null;
    }
    if (!body || body.startsWith('Error:')) {
      console.error('[ASR] Empty or error body:', body.slice(0, 200));
      return null;
    }
    return body;
  } catch (err) {
    console.error('[ASR] Request failed:', err.message || err);
    return null;
  }
}

// Upload Endpoint (requires authentication, max 5MB, key: 'file')
app.post('/api/upload', authenticateToken, (req, res) => {
  upload.single('file')(req, res, async (err) => {
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

    let fileUrl = `/uploads/${req.file.filename}`;
    let storage = useS3 ? 's3' : 'local';
    if (useS3) {
      // Caller can pass ?folder=profile-pictures / org-profile / vouchers etc.
      const requestedFolder = req.query.folder || req.body?.folder || null;
      const storedPath = await uploadToS3(req.file.path, req.file.filename, req.file.mimetype, requestedFolder);
      if (storedPath) {
        fileUrl = `/uploads/${storedPath}`;
      } else {
        console.error('[Upload] S3 enabled but upload failed; file kept at', req.file.path);
        return res.status(502).json({
          error: 'Cloud storage upload failed. Check STORAGE_S3_* settings on the server.',
        });
      }
    }
    res.json({ imageUrl: fileUrl, storage });
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
    select: { isPersonal: true, approvalPolicy: true, whitelistedUserIds: true }
  });
  if (!org || org.isPersonal) return true;
  if (org.approvalPolicy === 'GLOBALLY_OFF') return true;
  if (org.approvalPolicy === 'CONDITIONAL_ON') {
    return (org.whitelistedUserIds || []).includes(userId);
  }
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

// Personal expense (org fund) ↔ mirrored expense on org book — same clientRef, not always linkedTransactionId.
const findFundVoucherPairedTxn = async (txn, book, txClient = prisma) => {
  if (!txn?.clientRef) return null;
  let resolvedBook = book;
  if (!resolvedBook?.organization) {
    resolvedBook = await txClient.book.findUnique({
      where: { id: txn.bookId },
      include: { organization: true }
    });
  }
  if (!resolvedBook) return null;

  const cpm = await findCreatorPersonalMirror(txn, txClient);
  if (cpm) return cpm;

  if (resolvedBook.organization?.isPersonal && txn.orgFundId) {
    return txClient.transaction.findFirst({
      where: {
        bookId: txn.orgFundId,
        clientRef: txn.clientRef,
        createdById: txn.createdById
      }
    });
  }

  if (!resolvedBook.organization?.isPersonal) {
    return txClient.transaction.findFirst({
      where: {
        orgFundId: txn.bookId,
        clientRef: txn.clientRef,
        createdById: txn.createdById,
        book: { organization: { isPersonal: true } }
      }
    });
  }
  return null;
};

const reverseTxnBalanceForRemoval = (txn) => {
  if (txn.type === 'expense') return txn.amount;
  if (txn.type === 'income') return -txn.amount;
  return 0;
};

const applyTxnBalanceForAddition = (txn) => {
  if (txn.type === 'expense') return -txn.amount;
  if (txn.type === 'income') return txn.amount;
  return 0;
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

// Linked edit/delete: counterparty on the other book/leg (Send, fund_send, org disbursement, mirrors).
const txnHasLinkedChangeDeleteApproval = (txn) =>
  !!(
    txn.linkedTransactionId ||
    txn.category === 'Send' ||
    txn.chainType === 'fund_send' ||
    txn.recipientUserId ||
    txn.orgFundId
  );

const getChangeDeleteCounterpartyUserId = async (txn, book, requesterId) => {
  const disbursement = await resolveOrgDisbursementOrgTxn(txn, book);
  if (disbursement) {
    const { orgTxn } = disbursement;
    const onOrgExpenseLeg =
      txn.id === orgTxn.id ||
      (txn.bookId === orgTxn.bookId && txn.type === 'expense' && txn.category === 'Send');
    if (onOrgExpenseLeg) return orgTxn.recipientUserId || null;
    if (txn.type === 'income' && txn.category === 'Send') return orgTxn.createdById || null;
    if (requesterId === orgTxn.createdById) return orgTxn.recipientUserId || null;
    if (requesterId === orgTxn.recipientUserId) return orgTxn.createdById || null;
    return orgTxn.recipientUserId || orgTxn.createdById || null;
  }

  const pairedFund = await findFundVoucherPairedTxn(txn, book);
  if (pairedFund) {
    let resolvedBook = book;
    if (!resolvedBook?.organization) {
      resolvedBook = await prisma.book.findUnique({
        where: { id: txn.bookId },
        include: { organization: true }
      });
    }
    if (resolvedBook?.organization?.isPersonal && txn.orgFundId) {
      const fundBook = await prisma.book.findUnique({ where: { id: txn.orgFundId } });
      if (fundBook?.organizationId) {
        const adminIds = await getOrgAdminUserIds(fundBook.organizationId);
        const rep = pickOrgRepresentative(adminIds, requesterId);
        if (rep) return rep;
      }
    } else if (!resolvedBook?.organization?.isPersonal) {
      if (pairedFund.createdById && pairedFund.createdById !== requesterId) return pairedFund.createdById;
      if (txn.createdById && txn.createdById !== requesterId) return txn.createdById;
    }
  }

  if (txn.linkedTransactionId) {
    const linked = await prisma.transaction.findUnique({
      where: { id: txn.linkedTransactionId },
      select: { id: true, createdById: true, recipientUserId: true },
    });
    if (linked) {
      if (linked.createdById && linked.createdById !== requesterId) return linked.createdById;
      if (linked.recipientUserId && linked.recipientUserId !== requesterId) return linked.recipientUserId;
      if (txn.recipientUserId && txn.recipientUserId !== requesterId) return txn.recipientUserId;
      if (txn.createdById && txn.createdById !== requesterId) return txn.createdById;
    }
  }

  if (txn.recipientUserId && txn.recipientUserId !== requesterId) return txn.recipientUserId;
  if (txn.createdById && txn.createdById !== requesterId) return txn.createdById;
  return null;
};

const userStillActive = async (userId) => {
  if (!userId) return false;
  const user = await prisma.user.findUnique({ where: { id: userId }, select: { id: true } });
  return !!user;
};

const pickOrgRepresentative = (adminIds, excludeId) => adminIds.find((id) => id && id !== excludeId) || null;

// Linked modify/delete: require the other party. Orphan when leg/user/org gone (see computeRequiredApprovers).
// Dual-book same user (e.g. org Send → own personal): still require counterparty-leg confirmation.
const finalizeLinkedChangeDeleteApprovers = (candidateIds, requesterId, chain) => {
  let required = [...new Set(candidateIds.filter((id) => id && id !== requesterId))];
  const dualLegs =
    chain.p1?.hasEntry &&
    chain.p2?.hasEntry &&
    chain.p1?.active &&
    chain.p2?.active &&
    chain.p1?.userId &&
    chain.p1.userId === chain.p2?.userId;
  if (required.length === 0 && dualLegs) {
    required = [chain.p2.userId];
  }
  return required;
};

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
      requiredApprovers: finalizeLinkedChangeDeleteApprovers(otherId ? [otherId] : [], requesterId, chain),
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
          requiredApprovers: finalizeLinkedChangeDeleteApprovers(otherId ? [otherId] : [], requesterId, chain),
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
          requiredApprovers: finalizeLinkedChangeDeleteApprovers(
            [chain.p1.userId, chain.p2.userId].filter(Boolean),
            requesterId,
            chain
          ),
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
      requiredApprovers: finalizeLinkedChangeDeleteApprovers(required, requesterId, chain),
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
  let counterparty = await getChangeDeleteCounterpartyUserId(txn, book, requesterId);
  if (!counterparty && txn.linkedTransactionId) {
    const linked = await prisma.transaction.findUnique({
      where: { id: txn.linkedTransactionId },
      select: { createdById: true, recipientUserId: true },
    });
    if (linked?.createdById && linked.createdById !== requesterId) counterparty = linked.createdById;
    else if (linked?.recipientUserId && linked.recipientUserId !== requesterId) {
      counterparty = linked.recipientUserId;
    }
  }
  if (counterparty) return [counterparty];
  // Always try chain resolution as fallback — even for linked transactions
  const chain = await resolveChangeDeleteChain(txn, book);
  const computed = computeRequiredApprovers(chain, requesterId);
  if (computed.requiredApprovers.length > 0) return computed.requiredApprovers;

  // Real organization book fallback: require approval from org admins/editors
  if (book.organizationId) {
    const org = await prisma.organization.findUnique({
      where: { id: book.organizationId },
      select: { isPersonal: true }
    });
    if (org && !org.isPersonal) {
      const bypass = await checkApprovalBypass(book.organizationId, requesterId);
      if (!bypass) {
        const admins = await prisma.organizationMember.findMany({
          where: {
            organizationId: book.organizationId,
            status: 'active',
            OR: [
              { role: 'admin' },
              { permissions: { has: 'edit_all' } }
            ]
          },
          select: { userId: true }
        });
        const adminIds = admins.map(a => a.userId).filter(id => id !== requesterId);
        if (adminIds.length > 0) {
          return adminIds;
        }
      }
    }
  }

  return [];
};

const mustUseChangeDeleteApprovalFlow = async (txn, book, requesterId) => {
  if (book.organizationId) {
    const org = await prisma.organization.findUnique({
      where: { id: book.organizationId },
      select: { isPersonal: true }
    });
    if (org && !org.isPersonal) {
      const bypass = await checkApprovalBypass(book.organizationId, requesterId);
      if (!bypass) {
        return true;
      }
    }
  }

  const pairedFund = await findFundVoucherPairedTxn(txn, book);
  if (
    txn.type === 'income' &&
    !txn.linkedTransactionId &&
    !txn.orgFundId &&
    !pairedFund &&
    txn.category !== 'Send' &&
    !txn.recipientUserId &&
    txn.chainType !== 'fund_send'
  ) {
    return false;
  }
  if (txnHasLinkedChangeDeleteApproval(txn) || pairedFund) return true;
  const required = await getRequiredApproversForChangeDelete(txn, book, requesterId);
  return required.length > 0;
};

const isChangeDeleteFullyApproved = (pendingData) => {
  const pd = parsePendingData(pendingData);
  const required = pd.requiredApprovers || [];
  const orgAnyOf = pd.orgApprovalAnyOf || [];
  const approvals = pd.approvals || [];
  const legApprovals = pd.legApprovals || [];

  if (pd.dualLegSameUser) {
    const otherLegId = pd.pairedTransactionId || pd.linkedTransactionId;
    const fromId = pd.requestedFromTxnId;
    if (otherLegId && fromId) {
      return legApprovals.includes(otherLegId) && !legApprovals.includes(fromId);
    }
    return false;
  }

  if (required.length === 0) return false;

  const nonOrgRequired = required.filter((id) => !orgAnyOf.includes(id));
  const orgRequired = required.some((id) => orgAnyOf.includes(id));
  const peopleOk = nonOrgRequired.every((id) => approvals.includes(id));
  const orgOk = !orgRequired || orgAnyOf.some((id) => approvals.includes(id));
  return peopleOk && orgOk;
};

const recordChangeDeleteApproval = (pendingData, approverId, approvingTxnId) => {
  const pd = parsePendingData(pendingData);
  const approvals = [...(pd.approvals || [])];
  if (!approvals.includes(approverId)) approvals.push(approverId);
  const legApprovals = [...(pd.legApprovals || [])];
  if (approvingTxnId && !legApprovals.includes(approvingTxnId)) legApprovals.push(approvingTxnId);
  return { ...pd, approvals, legApprovals };
};

const buildChangeDeletePendingData = async (txn, book, requesterId, baseData = {}) => {
  const chain = await resolveChangeDeleteChain(txn, book);
  let requiredApprovers = await getRequiredApproversForChangeDelete(txn, book, requesterId);
  const computed = computeRequiredApprovers(chain, requesterId);
  const { orgApprovalAnyOf, chainNote, isOrphan } = computed;
  if (requiredApprovers.length === 0 && computed.requiredApprovers?.length) {
    requiredApprovers = computed.requiredApprovers;
  }
  const partyIds = await getLinkedPartyUserIds(txn, book);
  const requester = await prisma.user.findUnique({ where: { id: requesterId }, select: { name: true } });
  const pairedFund = await findFundVoucherPairedTxn(txn, book);
  const dualLegSameUser =
    (requiredApprovers.length === 1 && requiredApprovers[0] === requesterId) ||
    (!!pairedFund && pairedFund.createdById === requesterId && txn.createdById === requesterId);

  let finalOrgApprovalAnyOf = orgApprovalAnyOf;
  if (finalOrgApprovalAnyOf.length === 0 && book.organizationId) {
    const org = await prisma.organization.findUnique({
      where: { id: book.organizationId },
      select: { isPersonal: true }
    });
    if (org && !org.isPersonal) {
      finalOrgApprovalAnyOf = requiredApprovers;
    }
  }

  return {
    ...baseData,
    requestedBy: requesterId,
    requesterName: requester?.name || 'Unknown',
    requestedFromTxnId: txn.id,
    linkedTransactionId: txn.linkedTransactionId || null,
    pairedTransactionId: pairedFund?.id || null,
    requiredApprovers,
    orgApprovalAnyOf: finalOrgApprovalAnyOf,
    approvals: [],
    legApprovals: [],
    partyCount: partyIds.length,
    requiredApprovalCount: requiredApprovers.length,
    chainNote,
    isOrphan: !!isOrphan && !txnHasLinkedChangeDeleteApproval(txn),
    dualLegSameUser,
  };
};

const getCounterpartLegsForChangeDelete = async (txn, book, txClient = prisma) => {
  const legs = [];
  if (txn.linkedTransactionId) {
    const linked = await txClient.transaction.findUnique({ where: { id: txn.linkedTransactionId } });
    if (linked) legs.push(linked);
  }
  const paired = await findFundVoucherPairedTxn(txn, book, txClient);
  if (paired && paired.id !== txn.id && !legs.some((l) => l.id === paired.id)) {
    legs.push(paired);
  }
  return legs;
};

const syncCounterpartLegsForChangeDelete = async (tx, txn, book, opts) => {
  const {
    pendingAction,
    pendingData,
    fieldUpdates = {},
    historyEntry = null,
    reverseBalanceOnRequest = false
  } = opts;
  const legs = await getCounterpartLegsForChangeDelete(txn, book, tx);
  for (const leg of legs) {
    const legBook = await tx.book.findUnique({ where: { id: leg.bookId } });
    if (!legBook) continue;

    if (reverseBalanceOnRequest) {
      let reversed = legBook.balance;
      if (leg.type === 'income') reversed -= leg.amount;
      else if (leg.type === 'expense') reversed += leg.amount;
      await tx.book.update({ where: { id: leg.bookId }, data: { balance: reversed } });
    }

    const data = { ...fieldUpdates };
    if (pendingAction) {
      data.reconStatus = 'pending';
      data.pendingAction = pendingAction;
      data.pendingData = pendingData;
    }
    if (historyEntry) {
      data.updateHistory = [...(leg.updateHistory || []), historyEntry];
    }

    await tx.transaction.update({ where: { id: leg.id }, data });
  }
};

const deleteCounterpartLegsForChangeDelete = async (tx, txn, book) => {
  const legs = await getCounterpartLegsForChangeDelete(txn, book, tx);
  for (const leg of legs) {
    const adj = reverseTxnBalanceForRemoval(leg);
    if (adj !== 0) {
      await tx.book.update({
        where: { id: leg.bookId },
        data: { balance: { increment: adj } }
      });
    }
    await tx.transaction.delete({ where: { id: leg.id } });
  }
};

const finalizeCounterpartLegsOnEditApprove = async (tx, txn, book, approveHistoryEntry) => {
  const legs = await getCounterpartLegsForChangeDelete(txn, book, tx);
  const source = await tx.transaction.findUnique({ where: { id: txn.id } });
  if (!source) return;

  for (const leg of legs) {
    const cur = await tx.transaction.findUnique({
      where: { id: leg.id },
      select: { version: true, updateHistory: true, amount: true, type: true, bookId: true }
    });
    if (!cur) continue;

    const oldDelta = applyTxnBalanceForAddition(cur);
    const syncFields = {
      amount: source.amount,
      note: source.note,
      category: source.category,
      reconStatus: 'approved',
      pendingAction: null,
      pendingData: null,
      version: { increment: 1 },
      updateHistory: [...(cur.updateHistory || []), approveHistoryEntry]
    };
    await tx.transaction.updateMany({
      where: { id: leg.id, version: cur.version },
      data: syncFields
    });

    const newDelta = source.type === 'expense' ? -source.amount : source.amount;
    const balanceFix = newDelta - oldDelta;
    if (balanceFix !== 0) {
      await tx.book.update({
        where: { id: leg.bookId },
        data: { balance: { increment: balanceFix } }
      });
    }
  }
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
      chainType: orgTxn.chainType || null,
      dateTime: orgTxn.dateTime || new Date()
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
  // Sender legs stay pending until the recipient accepts (no org-ledger approve step).
  return { personal: 'pending_recipient', fundOrg: 'pending_recipient', recipient: 'pending_recipient' };
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

/** Client ISO dateTime (device timezone) → Date for DB; falls back to now. */
function parseClientDateTime(value) {
  if (value === undefined || value === null || value === '') {
    return new Date();
  }
  const d = new Date(value);
  return Number.isNaN(d.getTime()) ? new Date() : d;
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
    const { name, organizationId } = req.body;
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

    const book = await prisma.book.create({
      data: {
        name,
        balance: 0.0,
        organizationId,
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

    // Regular book — delete everything
    await prisma.$transaction([
      prisma.transaction.deleteMany({ where: { bookId: book.id } }),
      prisma.book.delete({ where: { id: book.id } }),
    ]);

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
    const { bookId, amount, type, note, category, contact, recipientUserId, recipientOrgId, orgFundId, imageUrl, clientRef, audioNoteId } = req.body;

    if (!bookId || !amount || !type) {
      return res.status(400).json({ error: 'BookId, amount, and type are required' });
    }

    if (audioNoteId) {
      res.on('finish', async () => {
        if (res.statusCode === 201) {
          try {
            await prisma.audioNote.update({
              where: { id: audioNoteId },
              data: { status: 'completed' }
            });
          } catch (e) {
            console.error('Failed to mark audio note as completed:', e);
          }
        }
      });
    }

    const parsedAmount = parseFloat(amount);
    if (!parsedAmount || parsedAmount <= 0) {
      return res.status(400).json({ error: 'Amount must be a positive number' });
    }

    const txnClientRef = clientRef || 'cr_' + Date.now() + '_' + Math.random().toString(36).substring(2, 10);
    const txnDateTime = parseClientDateTime(req.body.dateTime);
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

      const initialStatus =
        bypassSourceOrgApproval && bypassRecipientOrgApproval ? 'approved' : 'pending_recipient';

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
            clientRef: txnClientRef,
            dateTime: txnDateTime
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
            clientRef: txnClientRef,
            dateTime: txnDateTime
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
              clientRef: txnClientRef,
              dateTime: txnDateTime
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
              linkedTransactionId: personalTxn.id,
              dateTime: txnDateTime
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
              clientRef: txnClientRef,
              dateTime: txnDateTime
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
      const initialStatus = (isSelfSend && bypassOrgApproval) ? 'approved' : 'pending_recipient';

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
          data: { bookId, amount: parsedAmount, type: 'expense', note: sourceNote, category: 'Send', contact, recipientUserId, createdById: req.user.id, reconStatus: initialStatus, imageUrl, chainId, chainType, orgFundId, clientRef: txnClientRef, dateTime: txnDateTime }
        });
        const recipientTxn = await prisma.transaction.create({
          data: { bookId: recipientBook.id, amount: parsedAmount, type: 'income', note: note || '', category: 'Send', contact, recipientUserId: req.user.id, linkedTransactionId: null, createdById: req.user.id, reconStatus: initialStatus, chainId, chainType, dateTime: txnDateTime }
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

      // Notify recipient when org approval was bypassed (skip for already-approved self-sends)
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

        // Force all vouchers to require manual approval by org admin, regardless of creator's role
        const voucherStatus = 'pending_org';

        const [txn, updatedBook] = await prisma.$transaction([
          prisma.transaction.create({ data: { bookId, amount: parsedAmount, type: 'expense', note, category, contact, orgFundId, createdById: req.user.id, reconStatus: voucherStatus, imageUrl, clientRef: txnClientRef, dateTime: txnDateTime } }),
          prisma.book.update({ where: { id: bookId }, data: { balance: { decrement: parsedAmount } } })
        ]);

        broadcast({ type: "data_changed" });
        const enriched = await enrichTxn(txn);
        return res.status(201).json({ transaction: enriched, book: updatedBook, isVoucher: true });
      }

      if (isVoucherBook) {
        // Force all vouchers to require manual approval by org admin, regardless of creator's role
        const voucherStatus = 'pending_org';

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
              clientRef: txnClientRef,
              dateTime: txnDateTime
            }
          }),
          prisma.book.update({ where: { id: bookId }, data: { balance: { decrement: parsedAmount } } })
        ]);

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



    const createResult = await prisma.$transaction(async (tx) => {
      const transaction = await tx.transaction.create({
        data: { bookId, amount: parsedAmount, type, note, category, contact, createdById: req.user.id, reconStatus: initialStatus, imageUrl, clientRef: txnClientRef, dateTime: txnDateTime }
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
    const hint = error?.code === 'P2022'
      ? 'Database schema out of date — run: npx prisma migrate deploy'
      : error?.code === 'P2003'
        ? 'Invalid book or linked record — try logout and sync books again'
        : null;
    res.status(500).json({
      error: hint || 'Server error creating transaction',
      ...(process.env.NODE_ENV !== 'production' && error?.message ? { detail: error.message } : {}),
    });
  }
});

// --- EDIT TRANSACTION ---
app.put('/api/transactions/:id', authenticateToken, async (req, res) => {
  try {
    const { amount, type, note, category, contact, recipientUserId, imageUrl, orgFundId, dateTime: clientDateTime } = req.body;
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
    const isExistingOrgFundMirror =
      !book.organization.isPersonal &&
      txn.type === 'expense' &&
      txn.category &&
      txn.category !== 'Send';
    if (
      !book.organization.isPersonal &&
      finalType === 'expense' &&
      finalCategory !== 'Send' &&
      !isExistingOrgFundMirror
    ) {
      return res.status(400).json({
        error: 'Organization books only support Send for expenses. Use your personal book with this organization as fund for other categories.'
      });
    }
    if (isExistingOrgFundMirror && category !== undefined && category === 'Send') {
      return res.status(400).json({
        error: 'Fund voucher entries cannot be changed to Send. Edit amount or note only.'
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
    if (clientDateTime !== undefined && clientDateTime !== null && clientDateTime !== '') {
      changes.dateTime = parseClientDateTime(clientDateTime);
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

    if (txn.pendingAction) {
      return res.status(400).json({ error: 'Transaction is already pending an approval for edit or delete.' });
    }

    const user = await prisma.user.findUnique({ where: { id: req.user.id }, select: { name: true } });
    let mustApprove = await mustUseChangeDeleteApprovalFlow(txn, book, req.user.id);
    const requiredApprovers = await getRequiredApproversForChangeDelete(txn, book, req.user.id);
    if (mustApprove && requiredApprovers.length === 0) {
      // Orphan: counterparty no longer exists — allow direct edit without approval
      mustApprove = false;
    }

    if (!mustApprove) {
      // Direct edit logic
      let balanceAdjustment = 0;
      if (
        txn.reconStatus !== 'rejected' &&
        changes.amount !== undefined &&
        changes.amount !== txn.amount
      ) {
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

        const linkedChanges = {};
        if (changes.amount !== undefined) linkedChanges.amount = parsedAmount;
        if (changes.note !== undefined) linkedChanges.note = changes.note;
        if (changes.category !== undefined) linkedChanges.category = changes.category;
        if (Object.keys(linkedChanges).length > 0) {
          await syncCounterpartLegsForChangeDelete(prisma, txn, book, {
            fieldUpdates: linkedChanges,
            historyEntry: {
              timestamp: new Date().toISOString(),
              userId: req.user.id,
              userName: user?.name || 'Unknown',
              action: 'edit (counterpart)',
              changes: { new: linkedChanges }
            }
          });
        }

        return updatedTxn;
      });

      broadcast({ type: 'data_changed' });
      const enriched = await enrichTxn(updated);
      return res.json({ transaction: enriched, message: 'Transaction updated' });
    } else {
      // Pending edit request flow
      let preTxnBalance = book.balance;
      if (txn.type === 'expense') {
        preTxnBalance += txn.amount;
      } else if (txn.type === 'income') {
        preTxnBalance -= txn.amount;
      }

      const pendingData = await buildChangeDeletePendingData(txn, book, req.user.id, {
        oldAmount: txn.amount,
        oldType: txn.type,
        oldCategory: txn.category,
        oldNote: txn.note,
        oldRecipientUserId: txn.recipientUserId,
        oldLinkedTransactionId: txn.linkedTransactionId,
        oldOrgFundId: txn.orgFundId,
        newAmount: changes.amount !== undefined ? parsedAmount : txn.amount,
        newNote: changes.note !== undefined ? changes.note : txn.note,
        newCategory: changes.category !== undefined ? changes.category : txn.category,
      });

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
                action: 'edit_request',
                changes: { old: { amount: txn.amount, type: txn.type, category: txn.category, note: txn.note }, new: changes },
              },
            ],
          },
        });

        await prisma.book.update({
          where: { id: book.id },
          data: { balance: preTxnBalance },
        });

        const linkedChanges = {};
        if (changes.amount !== undefined) linkedChanges.amount = parsedAmount;
        if (changes.note !== undefined) linkedChanges.note = changes.note;
        if (changes.category !== undefined) linkedChanges.category = changes.category;

        await syncCounterpartLegsForChangeDelete(prisma, txn, book, {
          pendingAction: 'edit',
          pendingData,
          fieldUpdates: linkedChanges,
          historyEntry: {
            timestamp: new Date().toISOString(),
            userId: req.user.id,
            userName: user?.name || 'Unknown',
            action: 'edit_request (counterpart)',
            changes: { new: linkedChanges }
          },
          reverseBalanceOnRequest: true
        });

        return updatedTxn;
      });

      broadcast({ type: 'data_changed' });
      await notifyChangeDeleteApprovers(updated, 'edit', pendingData);
      const enriched = await enrichTxn(updated);
      const summary = buildChangeDeleteNotification(pendingData, 'edit', updated);
      return res.json({
        transaction: enriched,
        pending: true,
        message: 'Edit submitted for approval',
        notification: summary,
      });
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
      let mustApprove = await mustUseChangeDeleteApprovalFlow(txn, book, req.user.id);
      const requiredApprovers = await getRequiredApproversForChangeDelete(txn, book, req.user.id);
      // Orphan: counterparty no longer exists — treat as instant-delete
      if (mustApprove && requiredApprovers.length === 0) {
        mustApprove = false;
      }
      result.requiredApproverCount = mustApprove ? Math.max(1, requiredApprovers.length) : 0;
      result.needsApproval = mustApprove;
      result.canInstantDelete = !mustApprove;
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
    if (txn.pendingAction === 'delete') {
      return res.status(400).json({ error: 'Deletion is already pending approval' });
    }
    let mustApprove = await mustUseChangeDeleteApprovalFlow(txn, book, req.user.id);
    const requiredApprovers = await getRequiredApproversForChangeDelete(txn, book, req.user.id);
    if (mustApprove && requiredApprovers.length === 0) {
      // Orphan: counterparty no longer exists — allow direct delete without approval
      mustApprove = false;
    }

    const executeHardDelete = async () => {
      await prisma.$transaction(async (prisma) => {
        let balanceAdjustment = reverseTxnBalanceForRemoval(txn);
        if (balanceAdjustment !== 0) {
          await prisma.book.update({ where: { id: book.id }, data: { balance: { increment: balanceAdjustment } } });
        }
        await deleteCounterpartLegsForChangeDelete(prisma, txn, book);
        await prisma.transaction.delete({ where: { id: txnId } });
      });
      broadcast({ type: 'data_changed' });
    };

    if (!mustApprove) {
      await executeHardDelete();
      return res.json({ message: 'Transaction deleted', pending: false });
    }

    // Linked transaction/requires approval: transition to pending delete
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

      await syncCounterpartLegsForChangeDelete(prisma, txn, book, {
        pendingAction: 'delete',
        pendingData,
        historyEntry: {
          timestamp: new Date().toISOString(),
          userId: req.user.id,
          userName: user?.name || 'Unknown',
          action: 'delete_request (counterpart)',
          changes: { old: { amount: txn.amount, type: txn.type, category: txn.category, note: txn.note } }
        },
        reverseBalanceOnRequest: true
      });
    });

    broadcast({ type: 'data_changed' });
    const refreshedTxn = await prisma.transaction.findUnique({ where: { id: txnId } });
    await notifyChangeDeleteApprovers(refreshedTxn || txn, 'delete', pendingData);
    const summary = buildChangeDeleteNotification(pendingData, 'delete', refreshedTxn || txn);
    const enriched = refreshedTxn ? await enrichTxn(refreshedTxn) : null;
    return res.json({
      message: 'Delete request submitted for approval',
      pending: true,
      notification: summary,
      transaction: enriched
    });
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

    // Prevent double approval of already approved transaction
    if (action === 'approve' && txn.reconStatus === 'approved' && !txn.pendingAction && txn.counterProposedAmount == null) {
      return res.json({ transaction: txn, message: 'Transaction is already approved' });
    }

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
        const dualLeg = pendingDataObj.dualLegSameUser === true;
        if (!dualLeg || txn.id === pendingDataObj.requestedFromTxnId) {
          return res.status(403).json({
            error: 'Approve or reject from the linked book entry (the other leg), not the row you requested from.'
          });
        }
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

    // Send on org/personal sender book: org admin must not approve — only the recipient accepts.
    if (action === 'approve' && txn.category === 'Send' && txn.reconStatus === 'pending_org' && txn.type === 'expense') {
      const srcBook = await prisma.book.findUnique({
        where: { id: txn.bookId },
        include: { organization: { select: { isPersonal: true } } }
      });
      if (srcBook) {
        let recipientUserId = txn.recipientUserId;
        let recipientOrgId = txn.recipientOrgId;
        if (!recipientUserId && !recipientOrgId && txn.linkedTransactionId) {
          const linked = await prisma.transaction.findUnique({
            where: { id: txn.linkedTransactionId },
            select: { recipientUserId: true, recipientOrgId: true }
          });
          recipientUserId = linked?.recipientUserId;
          recipientOrgId = linked?.recipientOrgId;
        }
        let isAuthorizedRecipient = false;
        if (recipientUserId) {
          isAuthorizedRecipient = req.user.id === recipientUserId;
        } else if (recipientOrgId) {
          isAuthorizedRecipient = await checkPermission(recipientOrgId, req.user.id, 'edit_all');
        }
        if (!isAuthorizedRecipient) {
          return res.status(403).json({
            error: 'This send is waiting for the recipient to accept. Approve from the recipient\'s book.',
          });
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
          const updatedPendingData = recordChangeDeleteApproval(txn.pendingData, req.user.id, txnId);
          if (!isChangeDeleteFullyApproved(updatedPendingData)) {
            await prisma.$transaction(async (tx) => {
              await tx.transaction.update({
                where: { id: txnId },
                data: {
                  pendingData: updatedPendingData,
                  updateHistory: [...(txn.updateHistory || []), approveHistoryEntry]
                }
              });
              const legs = await getCounterpartLegsForChangeDelete(txn, txnBook, tx);
              for (const leg of legs) {
                await tx.transaction.update({
                  where: { id: leg.id },
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

            const updated = await tx.transaction.findUnique({ where: { id: txnId } });
            if (updated) {
              const delta = applyTxnBalanceForAddition(updated);
              await tx.book.update({
                where: { id: txn.bookId },
                data: { balance: { increment: delta } }
              });
            }
            await finalizeCounterpartLegsOnEditApprove(tx, txn, txnBook, approveHistoryEntry);
          });
          const updated = await prisma.transaction.findUnique({ where: { id: txnId } });
          broadcast({ type: "data_changed" });
          return res.json({ transaction: updated, message: 'Edit approved' });
        } else if (txn.pendingAction === 'delete') {
          const updatedPendingData = recordChangeDeleteApproval(txn.pendingData, req.user.id, txnId);
          if (!isChangeDeleteFullyApproved(updatedPendingData)) {
            await prisma.$transaction(async (tx) => {
              await tx.transaction.update({
                where: { id: txnId },
                data: {
                  pendingData: updatedPendingData,
                  updateHistory: [...(txn.updateHistory || []), approveHistoryEntry]
                }
              });
              const legs = await getCounterpartLegsForChangeDelete(txn, txnBook, tx);
              for (const leg of legs) {
                await tx.transaction.update({
                  where: { id: leg.id },
                  data: { pendingData: updatedPendingData }
                });
              }
            });
            broadcast({ type: 'data_changed' });
            const remaining = (updatedPendingData.requiredApprovers || []).filter((id) => !(updatedPendingData.approvals || []).includes(id));
            return res.json({ message: `Delete approval recorded. Waiting for ${remaining.length} more approval(s).` });
          }

          await prisma.$transaction(async (tx) => {
            const adj = reverseTxnBalanceForRemoval(txn);
            if (adj !== 0) {
              await tx.book.update({
                where: { id: txn.bookId },
                data: { balance: { increment: adj } }
              });
            }
            await deleteCounterpartLegsForChangeDelete(tx, txn, txnBook);
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
          const nextStatus = 'pending_recipient';

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
          if (txn.recipientUserId) {
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
          return res.json({ message: 'Org approved, waiting for recipient acceptance' });
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
        const book = await prisma.book.findUnique({ where: { id: txn.bookId } });
        if (pd && book) {
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

            const legs = await getCounterpartLegsForChangeDelete(txn, book, tx);
            for (const leg of legs) {
              if (!leg.pendingAction) continue;
              const legPd = parsePendingData(leg.pendingData || pd);
              const legDelta = legPd.oldType === 'expense' ? -legPd.oldAmount : legPd.oldAmount;
              await tx.book.update({
                where: { id: leg.bookId },
                data: { balance: { increment: legDelta } }
              });
              const legVer = await tx.transaction.findUnique({ where: { id: leg.id }, select: { version: true } });
              if (!legVer) continue;
              const updL = await tx.transaction.updateMany({
                where: { id: leg.id, version: legVer.version },
                data: {
                  amount: legPd.oldAmount,
                  type: legPd.oldType,
                  category: legPd.oldCategory,
                  note: legPd.oldNote,
                  reconStatus: 'approved',
                  pendingAction: null,
                  pendingData: null,
                  version: { increment: 1 }
                }
              });
              if (updL.count === 0) throw new Error('Concurrency conflict on counterpart pendingAction reject');
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
      ? 'pending_recipient'
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

    const org = await prisma.organization.findUnique({
      where: { id: book.organizationId },
      select: { isPersonal: true }
    });

    const whereClause = { bookId };

    const transactions = await prisma.transaction.findMany({
      where: whereClause,
      orderBy: { dateTime: 'desc' }
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
// BanglaSpeechAPI proxy — Flutter sends audio_file + JWT; API key stays on server.
app.post('/api/asr/transcribe', authenticateToken, upload.single('audio_file'), async (req, res) => {
  try {
    if (!req.file) return res.status(400).json({ error: 'No audio file provided' });
    const { enabled } = getAsrConfig();
    if (!enabled) {
      try { fs.unlinkSync(req.file.path); } catch (_) {}
      return res.status(503).json({
        error: 'ASR not configured',
        hint: 'Set ASR_BASE_URL and ASR_API_KEY on the backend (BanglaSpeechAPI VALID_API_KEYS).',
      });
    }

    const text = await transcribeWithBanglaSpeechApi(
      req.file.path,
      req.file.originalname,
      req.file.mimetype
    );

    try { fs.unlinkSync(req.file.path); } catch (_) {}

    if (!text) {
      return res.status(502).json({ error: 'Transcription failed' });
    }

    res.json({ text });
  } catch (err) {
    if (req.file && req.file.path) {
      try { fs.unlinkSync(req.file.path); } catch (_) {}
    }
    console.error('ASR transcribe error:', err);
    res.status(500).json({ error: 'Server error during transcription' });
  }
});

// --- AUDIO NOTES ENDPOINTS ---
app.get('/api/audio-notes', authenticateToken, async (req, res) => {
  try {
    const notes = await prisma.audioNote.findMany({
      where: { userId: req.user.id },
      orderBy: { createdAt: 'desc' }
    });
    res.json(notes);
  } catch (err) {
    console.error('Error fetching audio notes:', err);
    res.status(500).json({ error: 'Server error fetching audio notes' });
  }
});

app.post('/api/audio-notes/upload', authenticateToken, upload.single('audio'), async (req, res) => {
  try {
    if (!req.file) return res.status(400).json({ error: 'No audio file provided' });

    const user = await prisma.user.findUnique({ where: { id: req.user.id } });
    if (!user) return res.status(400).json({ error: 'User not found' });

    let transcribedText = await transcribeWithBanglaSpeechApi(
      req.file.path,
      req.file.originalname,
      req.file.mimetype
    );

    // Fallback: Gemini (legacy) when BanglaSpeechAPI is not configured
    if (!transcribedText) {
      if (!user.aiConfig) {
        return res.status(400).json({
          error: 'ASR not configured on server and no AI config for fallback',
        });
      }
      const aiConfig = typeof user.aiConfig === 'string' ? JSON.parse(user.aiConfig) : user.aiConfig;
      const apiKey = aiConfig.apiKey;
      if (!apiKey) {
        return res.status(400).json({ error: 'Set ASR_API_KEY on server or Gemini API Key in settings' });
      }

      const audioData = fs.readFileSync(req.file.path).toString('base64');
      const mimeType = req.file.mimetype || 'audio/m4a';
      const geminiUrl = `https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent?key=${apiKey}`;
      const aiReqBody = {
        contents: [{
          parts: [
            { text: 'Listen to this audio and perfectly transcribe exactly what is spoken. If it is in Bengali, write in Bengali text. DO NOT add any extra commentary or formatting, just output the raw text.' },
            { inlineData: { mimeType: mimeType, data: audioData } }
          ]
        }],
        generationConfig: { temperature: 0.2 }
      };

      const aiRes = await fetch(geminiUrl, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(aiReqBody)
      });

      transcribedText = 'Unclear audio / Processing failed';
      if (aiRes.ok) {
        const aiData = await aiRes.json();
        if (aiData.candidates && aiData.candidates[0]?.content?.parts) {
          transcribedText = aiData.candidates[0].content.parts[0].text.trim();
        }
      } else {
        console.error('Gemini API Error:', await aiRes.text());
      }
    }

    let audioUrl = `/uploads/${req.file.filename}`;
    if (useS3) {
      // Audio notes always go to the 'audio' folder
      const storedPath = await uploadToS3(req.file.path, req.file.filename, req.file.mimetype, 'audio');
      if (storedPath) audioUrl = `/uploads/${storedPath}`;
    }

    const note = await prisma.audioNote.create({
      data: {
        userId: user.id,
        audioUrl: audioUrl,
        text: transcribedText,
        status: transcribedText.includes('Unclear audio') ? 'pending' : 'processed',
        recordedAt: new Date(req.body.recordedAt || Date.now()),
      }
    });

    res.status(201).json(note);
  } catch (err) {
    console.error('Error processing audio note:', err);
    res.status(500).json({ error: 'Server error processing audio' });
  }
});

app.post('/api/audio-notes', authenticateToken, async (req, res) => {
  try {
    const { audioUrl, text, recordedAt } = req.body;
    const note = await prisma.audioNote.create({
      data: {
        userId: req.user.id,
        audioUrl: audioUrl || null,
        text: text || "Unprocessed Audio Note",
        status: text ? 'processed' : 'pending',
        recordedAt: recordedAt ? new Date(recordedAt) : new Date(),
      }
    });
    res.status(201).json(note);
  } catch (err) {
    console.error('Error creating audio note:', err);
    res.status(500).json({ error: 'Server error creating audio note' });
  }
});

app.delete('/api/audio-notes/:id', authenticateToken, async (req, res) => {
  try {
    const noteId = req.params.id;
    const note = await prisma.audioNote.findUnique({ where: { id: noteId } });
    if (!note || note.userId !== req.user.id) {
      return res.status(404).json({ error: 'Audio note not found' });
    }
    await prisma.audioNote.delete({ where: { id: noteId } });
    res.json({ message: 'Deleted successfully' });
  } catch (err) {
    console.error('Error deleting audio note:', err);
    res.status(500).json({ error: 'Server error deleting audio note' });
  }
});

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

        // Org/personal Send expense waiting for recipient — not an admin Approval Center item
        if (!txn.pendingAction && txn.category === 'Send' && txn.type === 'expense') {
          if (['pending_recipient', 'pending_org', 'pending'].includes(txn.reconStatus)) {
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
          bookId: isFundVoucher ? txn.orgFundId : txn.bookId,
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
        bookId: txn.bookId,
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

const normalizeForBookMatch = (s) =>
  String(s || '').toLowerCase().replace(/[^\w\u0980-\u09ff]/gi, '').trim();

/** Fuzzy match user message to one of their books (e.g. "উইকনোট" → "Weekly Notebook"). */
const matchBookFromUserMessage = (text, booksWithOrg) => {
  const q = normalizeForBookMatch(text);
  if (!q || !booksWithOrg?.length) return null;

  let best = null;
  let bestScore = 0;

  for (const entry of booksWithOrg) {
    const name = normalizeForBookMatch(entry.book.name);
    if (!name || name.length < 2) continue;

    if (q.includes(name) || name.includes(q)) {
      return entry;
    }

    const nameWords = String(entry.book.name || '')
      .toLowerCase()
      .split(/[\s_\-]+/)
      .filter((w) => w.length >= 2);
    for (const word of nameWords) {
      const nw = normalizeForBookMatch(word);
      if (nw.length >= 3 && q.includes(nw)) {
        const score = nw.length + 10;
        if (score > bestScore) {
          bestScore = score;
          best = entry;
        }
      }
    }

    if (/উইক|week|weekly/i.test(q) && /week|উইক|weekly/i.test(name)) {
      const score = 12;
      if (score > bestScore) {
        bestScore = score;
        best = entry;
      }
    }
    if (/নোট|note|notebook/i.test(q) && /note|নোট|book/i.test(name)) {
      const score = 6;
      if (score > bestScore) {
        bestScore = score;
        best = entry;
      }
    }
  }
  return best;
};

const detectAiIntent = (messages) => {
  const lastUser = [...(messages || [])].reverse().find(m => m.role === 'user');
  const q = (lastUser?.content || '').toLowerCase();

  if (
    /(balance|ব্যালেন্স|balence|মোট ব্যালেন্স|total balance|কত টাকা|how much money|জমা|deposit|স্থিতি|বাকি|টাকা আছে|কত আছে|কি আছে|আছে কি|কত টাকা)/i.test(
      q
    )
  ) {
    return 'balance';
  }
  if (
    /(খাতায়|বইতে|book|notebook|নোটবুক|উইক|week)/i.test(q) &&
    /(কত|আছে|জমা|টাকা|balance|খরচ|আয়|income|expense)/i.test(q)
  ) {
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
  if (/(কুইক নোট|quick note|voice note|ভয়েস নোট).*(বিশ্লেষণ|পড়|analyze|read|summary|সারাংশ|এন্ট্রি|entry|লেনদেন)/i.test(q)) {
    return 'general';
  }
  return 'general';
};

const AI_LLM_HISTORY_LIMIT = 6;
const AI_LLM_CONTENT_LIMIT = 1800;
const GEMINI_DEFAULT_BASE = 'https://generativelanguage.googleapis.com';

const normalizeGeminiBaseUrl = (baseUrl) => {
  if (!baseUrl || typeof baseUrl !== 'string') return null;
  let base = baseUrl.trim().replace(/\/+$/, '');
  if (!base) return null;
  // Users sometimes paste .../v1beta or longer paths from API docs.
  base = base.replace(/\/v1beta(\/.*)?$/i, '');
  return base;
};

const buildGeminiRequestUrl = (baseUrl, model, mode, apiKey) => {
  const base = normalizeGeminiBaseUrl(baseUrl) || GEMINI_DEFAULT_BASE;
  const endpoint = mode === 'stream' ? 'streamGenerateContent' : 'generateContent';
  const query = mode === 'stream'
    ? `alt=sse&key=${encodeURIComponent(apiKey)}`
    : `key=${encodeURIComponent(apiKey)}`;
  return `${base}/v1beta/models/${encodeURIComponent(model)}:${endpoint}?${query}`;
};

const safeFetchJson = async (res) => {
  const text = await res.text();
  if (!text) return {};
  try {
    return JSON.parse(text);
  } catch {
    return { error: { message: text.slice(0, 300) } };
  }
};

const geminiTextFromResponse = (data) => {
  const parts = data?.candidates?.[0]?.content?.parts;
  if (!Array.isArray(parts)) return '';
  return parts.map((p) => (typeof p?.text === 'string' ? p.text : '')).join('');
};

const isGeminiThinkingModel = (model) => /gemini-2\.5|gemini-3/i.test(String(model || ''));

const resolveAiMaxTokens = (maxTokens, model = '', provider = '') => {
  const parsed = maxTokens != null ? parseInt(maxTokens, 10) : 512;
  const safe = Number.isFinite(parsed) ? parsed : 512;
  if (provider === 'gemini' && isGeminiThinkingModel(model)) {
    // 2.5+ uses internal "thoughts" tokens — low caps yield empty/broken replies.
    return Math.min(Math.max(safe, 2048), 8192);
  }
  return Math.min(Math.max(safe, 256), 2048);
};

const truncateAiMessagesForLlm = (messages, maxCount = AI_LLM_HISTORY_LIMIT) => {
  if (!Array.isArray(messages)) return [];
  return messages.slice(-maxCount).map(m => ({
    role: m.role,
    content: String(m.content || '').slice(0, AI_LLM_CONTENT_LIMIT),
  }));
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

  let matchedEntry = matchBookFromUserMessage(text, booksWithOrg);
  if (!matchedEntry) {
    for (const entry of booksWithOrg) {
      const name = entry.book.name.toLowerCase();
      if (name.length > 2 && q.includes(name)) {
        matchedEntry = entry;
        break;
      }
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
  return { handled: false };
};

const formatBalanceDataBlock = (books) => {
  const payload = books.map(b => ({ book: b.name, balance: b.balance, org: b.organization }));
  return `[DATA type:balance]\n${JSON.stringify(payload)}\n[/DATA]`;
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

  const userData = await prisma.user.findUnique({ where: { id: userId } });
  const intent = detectAiIntent(messages);
  const lastUserMessage = getLastUserMessage(messages);
  const booksForAiTxn = booksWithOrg.filter(({ role, isPersonal }) =>
    isPersonal || role === 'admin' || role === 'editor'
  );
  const transactionHints = parseTransactionHints(lastUserMessage, booksForAiTxn, contextBookId);
  const activeBookEntry = booksWithOrg.find(x => x.book.id === contextBookId);
  const recommendedTemperature =
    intent === 'transaction' ? 0.35 : intent === 'general' ? 0.72 : 0.58;

  const today = new Date().toISOString().split('T')[0];

  let dataContextSection = '';
  const serverToolData = {};

  if (intent === 'balance') {
    const balanceBlock = formatBalanceDataBlock(allBooks);
    serverToolData.balanceBlock = balanceBlock;
    dataContextSection += `\nREAL-TIME USER BALANCE DATA:\n${balanceBlock}\n`;
  } else if (intent === 'recent' && contextBookId) {
    const txns = await prisma.transaction.findMany({
      where: { bookId: contextBookId },
      orderBy: { dateTime: 'desc' },
      take: 8,
    });
    const recentBlock = formatTransactionsDataBlock(txns);
    serverToolData.recentBlock = recentBlock;
    dataContextSection += `\nREAL-TIME RECENT TRANSACTIONS:\n${recentBlock}\n`;
  } else if (intent === 'category' && contextBookId) {
    const txns = await prisma.transaction.findMany({
      where: { bookId: contextBookId },
      orderBy: { dateTime: 'desc' },
      take: 50,
    });
    const breakdown = {};
    txns.filter(t => t.type === 'expense').forEach(t => {
      const cat = t.category || 'General';
      breakdown[cat] = (breakdown[cat] || 0) + t.amount;
    });
    const payload = Object.entries(breakdown).map(([cat, amt]) => ({ category: cat, amount: amt }));
    const categoryBlock = `[DATA type:category]\n${JSON.stringify(payload)}\n[/DATA]`;
    serverToolData.categoryBlock = categoryBlock;
    dataContextSection += `\nREAL-TIME SPENDING BREAKDOWN BY CATEGORY:\n${categoryBlock}\n`;
  }

  const systemPrompt = `You are a casual human accountant & ledger assistant. Answer very concisely to save token bandwidth.

PERSONA:
- Converse naturally in short Bangla/English (casual & fun). Avoid typical AI phrases or long preambles.
- Talk directly to the user like a friend. Get straight to the point.
- USER: ${userData?.name || 'User'}
- TODAY: ${today}
- ACTIVE BOOK: ${activeBookEntry ? `"${activeBookEntry.book.name}" (${activeBookEntry.book.id})` : 'None'}
${dataContextSection}
INSTRUCTIONS:
- Do NOT use tools if the data needed is already present in the REAL-TIME context above. Just read it and reply immediately.
- To fetch extra missing data, write the tool command on its own line:
  1. [FETCH_RULE: <id>] -> Rules (id-01-transaction, id-02-design)
  2. [FETCH_NOTES: <count>] -> Quick audio notes
  3. [FETCH_BALANCE] -> Balances (only if missing in context)
  4. [FETCH_RECENT_TXN] -> Active book recent txns (only if missing in context)

TRANSACTIONS:
- ALL fields are strictly MANDATORY: amount, category, description, and note.
- DESCRIPTION MUST BE VERY DETAILED (INCLUDING WORK/PURPOSE CONTEXT):
  * Transport (e.g. Rickshaw, Uber, Bus): You must ask "কোথায় থেকে কোথায় গিয়েছিলেন? কেন গিয়েছিলেন? কোন কাজের কারণে বা অফিশিয়াল প্রয়োজনে? সাথে কি কেউ ছিল?" (From where to where? Why? For what official work/purpose? Anyone with you?). Do NOT accept simple travel endpoints.
  * Food/Restaurant: You must ask "কোথায় খেয়েছেন? কার সাথে? কোন অফিসের কাজ, প্রোগ্রাম বা মেহমানদারির কারণে এই খরচ করা হয়েছে?" (Where did you eat? With whom? Under what office work, event, or guest hospitality?).
  * Other categories: Always ask for the detailed purpose/work context.
- TWO-STEP CONFIRMATION FLOW (STRICT REQUIREMENT):
  1. First, ask conversational questions to gather all the mandatory description details (including the official work purpose).
  2. Once all details are gathered, summarize them and explicitly ask the user for confirmation (e.g., "আমি কি এটি আপনার ডেমো খাতায় যোগ করব?").
  3. ONLY output the JSON action block AFTER the user explicitly confirms (e.g., says "yes", "হ্যাঁ", "করো", "যোগ করো"). Do NOT output the action block before the user says yes.
- Once confirmed by the user, output the action block using this exact format:
\`\`\`action
{"action":"create_transaction","data":{"bookId":"<id>","type":"expense","amount":500,"category":"Transport","description":"Rickshaw fare from Dhanmondi to Gulshan to print program banner with Rahim","note":"Rickshaw"}}
\`\`\`
`;

  return {
    systemPrompt,
    contextBookId,
    intent,
    serverToolData,
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
        
        if (!amount || !category || !description) {
          proposedActions.push({
            action: 'create_transaction',
            data: { ...actionData.data },
            valid: false,
            reason: 'Missing required strict fields: amount, category, or description',
          });
          continue;
        }

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
              description: description || '',
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
  if (intent === 'recent' && serverToolData?.recentBlock && !cleanResponse.includes('[DATA type:transactions]')) {
    cleanResponse = cleanResponse
      ? `${cleanResponse}\n\n${serverToolData.recentBlock}`
      : serverToolData.recentBlock;
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
// AI PREPARE / FINALIZE — LLM calls run on the client; server builds context only
// ─────────────────────────────────────────────────────────────────────────────
app.post('/api/ai/agent/prepare', authenticateToken, async (req, res) => {
  try {
    const { bookId, messages } = req.body;
    if (!messages || !Array.isArray(messages)) {
      return res.status(400).json({ error: 'messages array is required' });
    }

    const agentCtx = await prepareAiAgentRequest(req.user.id, bookId, messages);
    const { systemPrompt, contextBookId, intent, serverToolData, recommendedTemperature } = agentCtx;

    const deterministic = await tryDeterministicAiResponse(messages, agentCtx, req.user.id);
    if (deterministic.handled) {
      await saveAiChatTurn({
        userId: req.user.id,
        userMessage: getLastUserMessage(messages),
        assistantMessage: deterministic.cleanResponse,
        bookId: contextBookId,
        model: null,
        provider: null,
        intent,
      });
      return res.json({
        mode: 'deterministic',
        response: deterministic.cleanResponse,
        proposedActions: deterministic.proposedActions || [],
        contextBookId,
        intent,
      });
    }

    return res.json({
      mode: 'llm',
      systemPrompt,
      recommendedTemperature,
      contextBookId,
      intent,
      serverToolData: serverToolData || {},
    });
  } catch (error) {
    console.error('[AI Agent Prepare] Error:', error);
    const msg = error?.message || String(error);
    return res.status(500).json({
      error: msg.includes('AudioNote') || msg.includes('does not exist')
        ? `Database migration required: ${msg}`
        : msg || 'Failed to prepare AI context',
    });
  }
});

app.post('/api/ai/agent/finalize', authenticateToken, async (req, res) => {
  try {
    const {
      rawText,
      bookId,
      messages,
      intent,
      contextBookId,
      serverToolData,
      model,
      provider,
    } = req.body;

    if (!rawText || !messages) {
      return res.status(400).json({ error: 'rawText and messages are required' });
    }

    const ctxBookId = contextBookId || bookId || null;
    const { cleanResponse, proposedActions } = await finalizeAiAgentResponse(rawText, {
      contextBookId: ctxBookId,
      userId: req.user.id,
      intent: intent || 'general',
      serverToolData: serverToolData || {},
      messages,
    });

    await saveAiChatTurn({
      userId: req.user.id,
      userMessage: getLastUserMessage(messages),
      assistantMessage: cleanResponse,
      bookId: ctxBookId,
      model: model || null,
      provider: provider || null,
      intent: intent || null,
    });

    return res.json({ response: cleanResponse, proposedActions });
  } catch (error) {
    console.error('[AI Agent Finalize] Error:', error);
    return res.status(500).json({ error: error.message || 'Failed to finalize AI response' });
  }
});

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

    if (!provider || !apiKey || !messages) {
      return res.status(400).json({ error: 'Missing required fields: provider, apiKey, messages' });
    }
    if (!model || !String(model).trim()) {
      return res.status(400).json({
        error: 'AI model is not selected. Run Find Working Models in AI settings, pick a model, and save.',
      });
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

    const tempVal = temperature != null ? parseFloat(temperature) : recommendedTemperature;
    const maxTokVal = resolveAiMaxTokens(maxTokens, model, provider);

    // ── Forward to AI Provider ──
    let aiResponseText = '';

    if (provider === 'gemini') {
      const url = buildGeminiRequestUrl(baseUrl, model, 'generate', apiKey);

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
      const geminiData = await safeFetchJson(geminiRes);
      if (!geminiRes.ok) {
        return res.status(geminiRes.status).json({ error: geminiData.error?.message || 'Gemini API Error' });
      }
      aiResponseText = geminiTextFromResponse(geminiData);

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
    const detail = error?.message || 'Internal server error';
    res.status(500).json({ error: detail });
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// AGENT TOOL CALLING ROUTE
// ─────────────────────────────────────────────────────────────────────────────
app.post('/api/ai/agent/tool', authenticateToken, async (req, res) => {
  try {
    const { toolName, args, bookId } = req.body;
    
    if (toolName === 'FETCH_RULE') {
      const { id } = args || {};
      if (id === 'id-01-transaction') {
        return res.json({ result: "Rule 01 - Transactions:\n- Must capture amount.\n- Must categorize properly.\n- Must provide detailed description (what/where/how/why)." });
      } else if (id === 'id-02-design') {
        return res.json({ result: "Rule 02 - Design:\n- Provide a beautiful, well-formatted response.\n- Use bold text for numbers." });
      } else {
        return res.json({ result: "Rule not found." });
      }
    } else if (toolName === 'FETCH_BALANCE') {
      const userOrgs = await prisma.organizationMember.findMany({
        where: { userId: req.user.id, status: 'active' },
        include: { organization: { include: { books: true } } },
      });
      const booksWithOrg = userOrgs.flatMap(m =>
        m.organization.books.map(b => ({
          book: b,
          orgName: m.organization.name,
          isPersonal: m.organization.isPersonal,
        }))
      );
      const balanceBooks = booksWithOrg.map(({ book, orgName, isPersonal }) => ({
        name: book.name,
        balance: book.balance,
        organization: isPersonal ? 'Personal' : orgName,
      }));
      return res.json({ result: formatBalanceDataBlock(balanceBooks) });
    } else if (toolName === 'FETCH_RECENT_TXN') {
      if (!bookId) return res.json({ result: "No bookId provided." });
      const recentTxns = await prisma.transaction.findMany({
        where: { bookId },
        orderBy: { dateTime: 'desc' },
        take: 10,
      });
      const preview = recentTxns.map((t) => ({
        note: t.note || t.category || '',
        amount: t.amount,
        type: t.type,
        category: t.category,
      }));
      return res.json({ result: formatTransactionsDataBlock(preview) });
    }
    
    return res.json({ result: "Unknown tool call." });
  } catch (error) {
    console.error('[AI Tool] Error:', error);
    res.status(500).json({ error: error.message });
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

    if (!provider || !apiKey || !messages) {
      return res.status(400).json({ error: 'Missing required fields: provider, apiKey, messages' });
    }
    if (!model || !String(model).trim()) {
      return res.status(400).json({
        error: 'AI model is not selected. Run Find Working Models in AI settings, pick a model, and save.',
      });
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

    const tempVal = temperature != null ? parseFloat(temperature) : recommendedTemperature;
    const maxTokVal = resolveAiMaxTokens(maxTokens, model, provider);

    if (provider === 'gemini') {
      const url = buildGeminiRequestUrl(baseUrl, model, 'stream', apiKey);

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
        const errData = await safeFetchJson(geminiRes);
        sendEvent('error', { message: errData.error?.message || 'Gemini API Error' });
        sendEvent('done', {});
        return res.end();
      }

      let fullText = '';

      if (!geminiRes.body) {
        const data = await safeFetchJson(geminiRes);
        fullText = geminiTextFromResponse(data);
        if (fullText) sendEvent('chunk', { content: fullText });
      } else {
        const reader = geminiRes.body.getReader();
        const decoder = new TextDecoder();
        let buffer = '';

        while (true) {
          const { done, value } = await reader.read();
          if (done) break;

          buffer += decoder.decode(value, { stream: true });
          const lines = buffer.split('\n');
          buffer = lines.pop() || '';

          for (const line of lines) {
            if (!line.startsWith('data: ')) continue;
            try {
              const data = JSON.parse(line.slice(6));
              const text = geminiTextFromResponse(data);
              if (text) {
                fullText += text;
                sendEvent('chunk', { content: text });
              }
            } catch (e) { /* skip parse errors */ }
          }
        }
      }

      if (!fullText.trim()) {
        const fallbackUrl = buildGeminiRequestUrl(baseUrl, model, 'generate', apiKey);
        const fallbackRes = await fetch(fallbackUrl, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            contents,
            systemInstruction: { parts: [{ text: systemPrompt }] },
            generationConfig: { temperature: tempVal, maxOutputTokens: maxTokVal },
          }),
        });
        const fallbackData = await safeFetchJson(fallbackRes);
        if (fallbackRes.ok) {
          fullText = geminiTextFromResponse(fallbackData);
          if (fullText) sendEvent('chunk', { content: fullText });
        }
      }

      if (!fullText.trim()) {
        const hint = isGeminiThinkingModel(model)
          ? 'Gemini 2.5+ needs higher Max Tokens (at least 2048). Open AI Settings, set Max Tokens to 2048 or higher, save, then retry.'
          : 'Gemini returned an empty response. Try another model from Find Working Models.';
        sendEvent('error', { message: hint });
        sendEvent('done', {});
        return res.end();
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
    const detail = error?.message || 'Internal server error';
    if (!res.headersSent) {
      res.status(500).json({ error: detail });
    } else {
      res.write(`data: ${JSON.stringify({ type: 'error', message: detail })}\n\n`);
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
      const { bookId, type, amount, category, note, description, dateTime, contact, recipientUserId, orgFundId, audioNoteId } = data;
      const resolvedNote = (note || description || '').trim();

      if (!bookId || !type || !amount) {
        return res.status(400).json({ error: 'Missing required transaction fields' });
      }

      if (audioNoteId) {
        res.on('finish', async () => {
          if (res.statusCode === 200) {
            try {
              await prisma.audioNote.update({
                where: { id: audioNoteId },
                data: { status: 'completed' }
              });
            } catch (e) {
              console.error('Failed to update audio note:', e);
            }
          }
        });
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
