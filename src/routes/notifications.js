const { prisma } = require('../config/database');

module.exports = function(app, { authenticateToken }) {

app.get('/api/notifications', authenticateToken, async (req, res) => {
  try {
    const { type, isRead, search, cursor, limit: queryLimit } = req.query;
    const limit = Math.min(parseInt(queryLimit) || 50, 200);

    const where = {
      userId: req.user.id,
      isDeleted: false,
    };

    if (type) {
      const types = Array.isArray(type) ? type : [type];
      where.type = { in: types };
    }

    if (isRead === 'true') where.isRead = true;
    else if (isRead === 'false') where.isRead = false;

    if (search) {
      where.OR = [
        { title: { contains: search, mode: 'insensitive' } },
        { message: { contains: search, mode: 'insensitive' } },
      ];
    }

    let notifications;
    if (cursor) {
      const cursorNotif = await prisma.notification.findUnique({ where: { id: cursor } });
      if (!cursorNotif) return res.status(400).json({ error: 'Invalid cursor' });
      where.createdAt = { lt: cursorNotif.createdAt };
      notifications = await prisma.notification.findMany({
        where,
        orderBy: { createdAt: 'desc' },
        take: limit,
      });
    } else {
      notifications = await prisma.notification.findMany({
        where,
        orderBy: { createdAt: 'desc' },
        take: limit,
        skip: parseInt(req.query.offset) || 0,
      });
    }

    const unreadCount = await prisma.notification.count({
      where: { userId: req.user.id, isRead: false, isDeleted: false }
    });

    const nextCursor = notifications.length === limit ? notifications[notifications.length - 1].id : null;

    res.json({ notifications, unreadCount, nextCursor });
  } catch (error) {
    console.error('Fetch notifications error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

app.put('/api/notifications/:id/read', authenticateToken, async (req, res) => {
  try {
    const notif = await prisma.notification.findUnique({ where: { id: req.params.id } });
    if (!notif) return res.status(404).json({ error: 'Notification not found' });
    if (notif.userId !== req.user.id) return res.status(403).json({ error: 'Not your notification' });

    await prisma.notification.update({
      where: { id: req.params.id },
      data: { isRead: true }
    });
    res.json({ message: 'Marked as read' });
  } catch (error) {
    console.error('Mark notification read error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

app.put('/api/notifications/read-all', authenticateToken, async (req, res) => {
  try {
    await prisma.notification.updateMany({
      where: { userId: req.user.id, isRead: false, isDeleted: false },
      data: { isRead: true }
    });
    res.json({ message: 'All notifications marked as read' });
  } catch (error) {
    console.error('Mark all read error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

app.delete('/api/notifications/:id', authenticateToken, async (req, res) => {
  try {
    const notif = await prisma.notification.findUnique({ where: { id: req.params.id } });
    if (!notif) return res.status(404).json({ error: 'Notification not found' });
    if (notif.userId !== req.user.id) return res.status(403).json({ error: 'Not your notification' });

    await prisma.notification.update({
      where: { id: req.params.id },
      data: { isDeleted: true }
    });
    res.json({ message: 'Notification deleted' });
  } catch (error) {
    console.error('Delete notification error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

app.delete('/api/notifications', authenticateToken, async (req, res) => {
  try {
    const { ids } = req.body;
    if (!Array.isArray(ids) || ids.length === 0) {
      return res.status(400).json({ error: 'ids array is required' });
    }
    const result = await prisma.notification.updateMany({
      where: { id: { in: ids }, userId: req.user.id },
      data: { isDeleted: true }
    });
    res.json({ message: `${result.count} notification(s) deleted` });
  } catch (error) {
    console.error('Batch delete notifications error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

};
