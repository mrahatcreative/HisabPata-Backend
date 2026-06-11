const { S3Client, PutObjectCommand } = require('@aws-sdk/client-s3');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const sharp = require('sharp');

const {
  s3Endpoint, s3Bucket, s3AccessKey, s3SecretKey, s3Region, s3ForcePathStyle, useS3
} = require('./env');

const uploadDir = path.join(__dirname, '..', '..', 'uploads');
if (!fs.existsSync(uploadDir)) {
  fs.mkdirSync(uploadDir, { recursive: true });
}

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
  limits: { fileSize: 100 * 1024 * 1024 },
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

const { getAsrConfig } = require('./env');

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

module.exports = { upload, uploadToS3, useS3, transcribeWithBanglaSpeechApi };
