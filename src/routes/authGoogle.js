const { OAuth2Client } = require('google-auth-library');
const jwt = require('jsonwebtoken');
const { prisma } = require('../config/database');

const DEFAULT_CATEGORIES = ['Food', 'Transport', 'Shopping', 'Bills', 'Health', 'Education', 'Entertainment', 'Salary', 'Others'];
const client = new OAuth2Client(process.env.GOOGLE_CLIENT_ID);

module.exports = function(app) {
  app.post('/api/auth/google', async (req, res) => {
    try {
      const { idToken } = req.body;
      if (!idToken) {
        return res.status(400).json({ error: 'ID token is required' });
      }

      // Verify the Google ID token
      const ticket = await client.verifyIdToken({
        idToken,
        audience: process.env.GOOGLE_CLIENT_ID,
      });

      const payload = ticket.getPayload();
      const email = payload.email;
      const name = payload.name;
      const avatarUrl = payload.picture;

      if (!email) {
        return res.status(400).json({ error: 'Email is required from Google Auth' });
      }

      // Find or create user
      let user = await prisma.user.findUnique({ where: { email } });

      if (!user) {
        // Create new user + personal org + member + book in one transaction
        user = await prisma.$transaction(async (tx) => {
          const u = await tx.user.create({
            data: {
              name: name || 'Google User',
              email,
              avatarUrl,
              password: 'google_auth_' + Date.now() + Math.random().toString(36).substring(7),
            },
          });

          const personalOrg = await tx.organization.create({
            data: {
              name: `${name || 'My'}'s Personal`,
              isPersonal: true,
              inviteCode: null,
              categories: DEFAULT_CATEGORIES,
            }
          });

          await tx.organizationMember.create({
            data: { userId: u.id, organizationId: personalOrg.id, role: 'admin', status: 'active' }
          });

          await tx.book.create({
            data: { name: 'Personal Book', isDefault: true, balance: 0.0, organizationId: personalOrg.id }
          });

          return u;
        });
      } else {
        // Update user's avatar if it changed
        if (avatarUrl && user.avatarUrl !== avatarUrl) {
          user = await prisma.user.update({
            where: { id: user.id },
            data: { avatarUrl },
          });
        }

        // Safety net: create personal org+book if missing
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
      }

      // Generate JWT
      const token = jwt.sign(
        { id: user.id, tokenVersion: user.tokenVersion },
        process.env.JWT_SECRET,
        { expiresIn: '30d' }
      );

      res.json({
        token,
        user: {
          id: user.id,
          name: user.name,
          email: user.email,
          phoneNumber: user.phoneNumber ?? '',
          avatarUrl: user.avatarUrl,
          tokenVersion: user.tokenVersion,
        },
      });
    } catch (error) {
      console.error('Google Auth Error:', error);
      res.status(401).json({ error: 'Invalid Google Token', detail: error.message });
    }
  });
};
