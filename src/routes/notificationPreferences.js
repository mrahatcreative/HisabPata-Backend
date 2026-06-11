const { prisma } = require('../config/database');

module.exports = function(app, { authenticateToken }) {

app.get('/api/notification-preferences', authenticateToken, async (req, res) => {
  try {
    const prefs = await prisma.notificationPreference.findMany({
      where: { userId: req.user.id }
    });
    res.json({ preferences: prefs });
  } catch (error) {
    console.error('Get notification preferences error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

app.put('/api/notification-preferences', authenticateToken, async (req, res) => {
  try {
    const { preferences } = req.body;
    if (!Array.isArray(preferences)) {
      return res.status(400).json({ error: 'preferences array is required' });
    }

    for (const pref of preferences) {
      const { type, pushEnabled, emailEnabled, inAppEnabled } = pref;
      if (!type) continue;

      await prisma.notificationPreference.upsert({
        where: { userId_type: { userId: req.user.id, type } },
        update: {
          pushEnabled: pushEnabled !== undefined ? pushEnabled : true,
          emailEnabled: emailEnabled !== undefined ? emailEnabled : true,
          inAppEnabled: inAppEnabled !== undefined ? inAppEnabled : true,
        },
        create: {
          userId: req.user.id,
          type,
          pushEnabled: pushEnabled !== undefined ? pushEnabled : true,
          emailEnabled: emailEnabled !== undefined ? emailEnabled : true,
          inAppEnabled: inAppEnabled !== undefined ? inAppEnabled : true,
        },
      });
    }

    const updated = await prisma.notificationPreference.findMany({
      where: { userId: req.user.id }
    });
    res.json({ preferences: updated, message: 'Preferences updated' });
  } catch (error) {
    console.error('Update notification preferences error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

};
