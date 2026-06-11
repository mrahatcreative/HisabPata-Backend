const multer = require('multer');

module.exports = function(app, { authenticateToken, upload, uploadToS3, useS3 }) {

app.post('/api/upload', authenticateToken, (req, res) => {
  upload.single('file')(req, res, async (err) => {
    if (err instanceof multer.MulterError) {
      if (err.code === 'LIMIT_FILE_SIZE') {
        return res.status(400).json({ error: 'File size limit exceeded. Max limit is 100MB.' });
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

};
