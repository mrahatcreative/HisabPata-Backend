const { prisma } = require('../config/database');

module.exports = function(app, { authenticateToken }) {

app.post('/api/devices/register-token', authenticateToken, async (req, res) => {
  try {
    const { token, deviceInfo } = req.body;
    if (!token) {
      return res.status(400).json({ error: 'FCM token is required' });
    }

    await prisma.fcmToken.upsert({
      where: { token },
      update: { userId: req.user.id, deviceInfo: deviceInfo || null },
      create: { userId: req.user.id, token, deviceInfo: deviceInfo || null },
    });

    res.json({ message: 'FCM token registered' });
  } catch (error) {
    console.error('Register FCM token error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

app.delete('/api/devices/register-token', authenticateToken, async (req, res) => {
  try {
    const { token } = req.body;
    if (!token) {
      return res.status(400).json({ error: 'FCM token is required' });
    }

    await prisma.fcmToken.deleteMany({
      where: { token, userId: req.user.id },
    });

    res.json({ message: 'FCM token unregistered' });
  } catch (error) {
    console.error('Unregister FCM token error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

};
