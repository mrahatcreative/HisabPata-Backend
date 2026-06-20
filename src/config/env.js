require('dotenv').config();

const rawEndpoint = process.env.AWS_ENDPOINT_URL || '';
const s3Endpoint  = rawEndpoint ? rawEndpoint.replace(/\/$/, '') : '';
const s3Bucket    = process.env.AWS_BUCKET || 'hisabpata';
const s3AccessKey = (process.env.AWS_ACCESS_KEY_ID || '').trim();
const s3SecretKey = (process.env.AWS_SECRET_ACCESS_KEY || '').trim();
const s3Region    = process.env.AWS_REGION || 'us-east-1';
const s3ForcePathStyle = process.env.AWS_FORCE_PATH_STYLE !== 'false';
const useS3       = !!s3Endpoint;

const PORT = process.env.PORT || 8000;

const JWT_SECRET = process.env.JWT_SECRET;
if (!JWT_SECRET) {
  if (process.env.NODE_ENV === 'production') {
    console.error('FATAL: JWT_SECRET must be set in production!');
    process.exit(1);
  }
  console.warn('WARNING: JWT_SECRET not set. Using fallback (dev only).');
}

function getAsrConfig() {
  const base = (process.env.ASR_BASE_URL || 'https://stotext.shilpigosthi.com').replace(/\/$/, '');
  const key = (process.env.ASR_API_KEY || '').trim();
  return { base, key, enabled: !!key };
}

const AI_SERVER_URL = (process.env.AI_SERVER_URL || 'http://localhost:5328').replace(/\/$/, '');

module.exports = { s3Endpoint, s3Bucket, s3AccessKey, s3SecretKey, s3Region, s3ForcePathStyle, useS3, PORT, JWT_SECRET, AI_SERVER_URL, getAsrConfig };
