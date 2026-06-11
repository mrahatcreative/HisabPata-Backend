const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const path = require('path');
const { S3Client, GetObjectCommand } = require('@aws-sdk/client-s3');

const { s3Endpoint, s3Bucket, s3AccessKey, s3SecretKey, s3Region, s3ForcePathStyle, useS3, getAsrConfig } = require('./config/env');
const { authenticateToken, authenticateAdmin } = require('./middleware/auth');
const { authLimiter } = require('./middleware/rateLimiter');
const {
  hasBookAccess, checkPermission, hasAdminOrEditorAccess, checkApprovalBypass,
  createNotification, getOrgAdminUserIds, maybeMirrorOrgTxnToCreatorPersonal,
  getChainRemainingBalance, mustUseChangeDeleteApprovalFlow,
  getRequiredApproversForChangeDelete, buildChangeDeletePendingData,
  syncCounterpartLegsForChangeDelete, notifyChangeDeleteApprovers,
  buildChangeDeleteNotification, deleteCounterpartLegsForChangeDelete,
  reverseTxnBalanceForRemoval, generateChainId, fundSendRetryStatuses,
  resolveApprovalOrgId, resolveFundSendChainParts, parsePendingData,
  recalculateBookBalance
} = require('./helpers');
const { parseClientDateTime, enrichTxn } = require('./helpers/enrichTxn');
const { DEFAULT_CATEGORIES } = require('./config/constants');
const { upload, uploadToS3, transcribeWithBanglaSpeechApi } = require('./config/upload');

const app = express();

const corsOrigins = process.env.CORS_ORIGINS;
const isCorsWildcard = corsOrigins === '*';
const allowedOrigins = isCorsWildcard
  ? true
  : corsOrigins
    ? corsOrigins.split(',').map(s => s.trim())
    : ['http://localhost:3000', 'http://127.0.0.1:3000', 'http://localhost:5000', 'http://127.0.0.1:5000', 'http://localhost:5173', 'http://127.0.0.1:5173', 'http://192.168.0.110:8099', 'http://localhost:8099', 'http://127.0.0.1:8099'];

app.use(helmet({ crossOriginResourcePolicy: { policy: 'cross-origin' } }));
app.use(cors({ origin: allowedOrigins, credentials: !isCorsWildcard }));
app.use(express.json());

if (useS3) {
  let s3Client = null;
  function getS3Client() {
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

  app.get('/uploads/:folder/:filename', async (req, res, next) => {
    try {
      const client = getS3Client();
      if (!client) return next();
      const key = `${req.params.folder}/${req.params.filename}`;
      const result = await client.send(new GetObjectCommand({ Bucket: s3Bucket, Key: key }));
      if (!result.Body) return next();
      if (result.ContentType) res.setHeader('Content-Type', result.ContentType);
      if (result.ContentLength) res.setHeader('Content-Length', String(result.ContentLength));
      res.setHeader('Cache-Control', 'public, max-age=3600');
      result.Body.pipe(res);
    } catch (e) { next(); }
  });
}
app.use('/uploads', express.static(path.join(__dirname, '..', 'uploads')));
app.use('/admin', express.static(path.join(__dirname, '..', 'admin_console')));

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

app.use((req, res, next) => {
  console.log(`[${new Date().toISOString()}] ${req.method} ${req.path}`);
  next();
});

require('./routes/auth')(app);
require('./routes/org')(app);
require('./routes/user')(app);
require('./routes/ai')(app);
require('./routes/aiTools')(app);
require('./routes/books')(app, { authenticateToken, recalculateBookBalance });
require('./routes/categories')(app, { authenticateToken });
require('./routes/notifications')(app, { authenticateToken });
require('./routes/personalBook')(app, { authenticateToken, hasBookAccess, enrichTxn });
require('./routes/upload')(app, { authenticateToken, upload, uploadToS3, useS3 });
require('./routes/audioNotes')(app, { authenticateToken, upload, transcribeWithBanglaSpeechApi, uploadToS3, useS3, getAsrConfig });
require('./routes/admin')(app, { authenticateToken, authenticateAdmin, upload });
require('./routes/retry')(app, { authenticateToken, resolveApprovalOrgId, checkApprovalBypass, resolveFundSendChainParts, fundSendRetryStatuses, hasAdminOrEditorAccess });
require('./routes/approvals')(app, { authenticateToken, hasAdminOrEditorAccess, checkPermission, createNotification, getOrgAdminUserIds, resolveApprovalOrgId, parsePendingData });
require('./routes/transactions')(app, { authenticateToken, hasBookAccess, checkPermission, hasAdminOrEditorAccess, checkApprovalBypass, createNotification, getOrgAdminUserIds, maybeMirrorOrgTxnToCreatorPersonal, getChainRemainingBalance, mustUseChangeDeleteApprovalFlow, getRequiredApproversForChangeDelete, buildChangeDeletePendingData, syncCounterpartLegsForChangeDelete, notifyChangeDeleteApprovers, buildChangeDeleteNotification, deleteCounterpartLegsForChangeDelete, reverseTxnBalanceForRemoval, generateChainId, fundSendRetryStatuses, resolveApprovalOrgId, resolveFundSendChainParts, parsePendingData, parseClientDateTime, enrichTxn, DEFAULT_CATEGORIES });

module.exports = app;
