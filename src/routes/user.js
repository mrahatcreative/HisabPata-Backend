const { prisma } = require('../config/database');
const { authenticateToken } = require('../middleware/auth');

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

module.exports = function(app) {
  app.get('/api/user/ai-config', authenticateToken, async (req, res) => {
    try {
      const cfg = await loadUserAiConfig(req.user.id);
      if (!cfg || !cfg.apiKey) {
        return res.json({ configured: false, config: null });
      }
      const safeConfig = { ...cfg, apiKey: cfg.apiKey.substring(0, 4) + '...' + cfg.apiKey.slice(-4) };
      return res.json({ configured: true, config: safeConfig });
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

      const safeConfig = { ...normalized.config, apiKey: normalized.config.apiKey.substring(0, 4) + '...' + normalized.config.apiKey.slice(-4) };
      res.json({ message: 'AI configuration saved', config: safeConfig });
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
          members: { where: { status: 'active' }, include: { user: { select: { id: true, name: true, avatarUrl: true } } } },
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
          members: o.members.map(m => ({ id: m.user.id, name: m.user.name, role: m.role, userId: m.userId, avatarUrl: m.user.avatarUrl })),
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
        select: { id: true, name: true, avatarUrl: true },
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
          user: { select: { id: true, name: true, phoneNumber: true, email: true, avatarUrl: true } },
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
          avatarUrl: m.user.avatarUrl,
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
      const { name, avatarUrl, email, phoneNumber } = req.body;
      if (!name) {
        return res.status(400).json({ error: 'Name is required' });
      }

      const updateData = { name };
      if (avatarUrl !== undefined) {
        updateData.avatarUrl = avatarUrl;
      }
      if (email !== undefined) {
        updateData.email = email || null;
      }
      if (phoneNumber !== undefined) {
        updateData.phoneNumber = phoneNumber || null;
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
};
