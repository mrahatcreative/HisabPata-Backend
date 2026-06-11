const { prisma } = require('../config/database');

module.exports = function(app, { authenticateToken }) {

app.get('/api/categories', authenticateToken, async (req, res) => {
  try {
    const [globalCategories, userCategories] = await Promise.all([
      prisma.category.findMany({ where: { userId: null } }),
      prisma.category.findMany({ where: { userId: req.user.id } })
    ]);
    res.json([...globalCategories, ...userCategories]);
  } catch (error) {
    console.error('Fetch categories error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/categories', authenticateToken, async (req, res) => {
  try {
    const { name, type } = req.body;
    if (!name || !type) {
      return res.status(400).json({ error: 'Name and type are required' });
    }
    if (!['INCOME', 'EXPENSE'].includes(type)) {
      return res.status(400).json({ error: 'Type must be INCOME or EXPENSE' });
    }

    const category = await prisma.category.create({
      data: {
        userId: req.user.id,
        name,
        type,
        isPermanent: false,
      }
    });
    res.status(201).json(category);
  } catch (error) {
    console.error('Create category error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

app.delete('/api/categories/:id', authenticateToken, async (req, res) => {
  try {
    const category = await prisma.category.findUnique({ where: { id: req.params.id } });
    if (!category) return res.status(404).json({ error: 'Category not found' });
    if (category.isPermanent) {
      return res.status(400).json({ error: 'Permanent categories cannot be deleted' });
    }
    if (category.userId !== req.user.id) {
      return res.status(403).json({ error: 'You can only delete your own categories' });
    }
    await prisma.category.delete({ where: { id: req.params.id } });
    res.json({ message: 'Category deleted' });
  } catch (error) {
    console.error('Delete category error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

};
