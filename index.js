require('dotenv').config();
const http = require('http');
const { WebSocketServer } = require('ws');

const app = require('./src/app');
const { setupWebSocket } = require('./src/websocket');
const { prisma, prismaBase } = require('./src/config/database');
const { PORT } = require('./src/config/env');

// ─── Seed Functions ─────────────────────────────────────────────────────────

const seedUser = async () => {
  const bcrypt = require('bcryptjs');
  const jwt = require('jsonwebtoken');
  const DEFAULT_CATEGORIES = require('./src/config/constants').DEFAULT_CATEGORIES;
  const JWT_SECRET = require('./src/config/env').JWT_SECRET;
  const JWT_SECRET_FINAL = JWT_SECRET || 'dev_secret_key_do_not_use_in_production';

  const existing = await prisma.user.findFirst();
  if (existing) return;

  const password = process.env.SEED_USER_PASSWORD || '123456';
  const hashedPassword = await bcrypt.hash(password, 10);

  const user = await prisma.$transaction(async (tx) => {
    const u = await tx.user.create({
      data: {
        name: process.env.SEED_USER_NAME || 'testuser',
        email: (process.env.SEED_USER_EMAIL || 'test@example.com').toLowerCase(),
        password: hashedPassword,
      }
    });

    const personalOrg = await tx.organization.create({
      data: { name: `${u.name}'s Personal`, isPersonal: true, inviteCode: null, categories: DEFAULT_CATEGORIES }
    });

    await tx.organizationMember.create({
      data: { userId: u.id, organizationId: personalOrg.id, role: 'admin', status: 'active' }
    });

    await tx.book.create({
      data: { name: 'Personal Book', isDefault: true, balance: 0.0, organizationId: personalOrg.id }
    });

    return u;
  });
};

const seedPermanentCategories = async () => {
  const { prisma } = require('./src/config/database');
  const existing = await prisma.organization.findFirst({ where: { name: 'PermanentCategories' } });
  if (existing) return;
  await prisma.organization.create({
    data: {
      name: 'PermanentCategories',
      isPersonal: false,
      inviteCode: 'PERMANENT',
      categories: ['expense:Permanent']
    }
  });
};

// ─── Server Setup ───────────────────────────────────────────────────────────

const server = http.createServer(app);
setupWebSocket(server);

process.on('SIGTERM', async () => {
  console.log('\nSIGTERM received. Shutting down gracefully...');
  server.close(async () => {
    await prisma.$disconnect();
    console.log('Prisma disconnected. Goodbye!');
    process.exit(0);
  });
});
process.on('SIGINT', async () => {
  console.log('\nSIGINT received. Shutting down...');
  server.close(async () => {
    await prisma.$disconnect();
    process.exit(0);
  });
});

server.listen(PORT, async () => {
  console.log(`\n======================================================`);
  console.log(`Hisab Pata Node.js Backend listening on port ${PORT} 🚀`);
  console.log(`WebSocket ready for realtime sync`);
  console.log(`======================================================\n`);
  if (process.env.NODE_ENV !== 'production' || process.env.SEED_DEFAULT_USER === 'true') {
    await seedUser();
  }
  await seedPermanentCategories();
});
