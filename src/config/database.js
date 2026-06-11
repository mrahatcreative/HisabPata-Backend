const { Pool } = require('pg');
const { PrismaPg } = require('@prisma/adapter-pg');
const { PrismaClient } = require('@prisma/client');
const { AsyncLocalStorage } = require('async_hooks');

const pool = new Pool({ connectionString: process.env.DATABASE_URL });
const adapter = new PrismaPg(pool);
const prismaBase = new PrismaClient({ adapter });

const requestContext = new AsyncLocalStorage();
const txExecutions = new Map();
setInterval(() => {
  txExecutions.clear();
}, 10 * 60 * 1000);

const prisma = prismaBase.$extends({
  query: {
    transaction: {
      async create({ args, query }) {
        const ctx = requestContext.getStore() || { flowId: 'UNKNOWN', step: { current: 0 }, reason: 'untracked' };
        ctx.step.current += 1;
        const result = await query(args);
        
        let dupCount = (txExecutions.get(result.id) || 0) + 1;
        txExecutions.set(result.id, dupCount);

        console.log(`[STRICT_DEBUG_TXN] | FLOW_ID: ${ctx.flowId} | STEP: ${ctx.step.current} | REASON: ${ctx.reason} | EVENT: CREATE | TXN_ID: ${result.id} | CREATED: ${result.createdAt} | STATUS_AFTER: ${result.reconStatus} | PEND_AFTER: ${result.pendingAction} | LINKED: ${result.linkedTransactionId} | ORG_FUND: ${result.orgFundId} | APPLIED: ${result.applied} | DUP_EXEC_COUNT: ${dupCount} | REQ_ID: ${ctx.flowId}`);
        return result;
      },
      async update({ args, query }) {
        const ctx = requestContext.getStore() || { flowId: 'UNKNOWN', step: { current: 0 }, reason: 'untracked' };
        ctx.step.current += 1;
        
        let beforeSnapshot = null;
        if (args.where && args.where.id) {
          beforeSnapshot = await prismaBase.transaction.findUnique({ where: args.where });
        }
        
        const result = await query(args);
        
        let dupCount = (txExecutions.get(result.id) || 0) + 1;
        txExecutions.set(result.id, dupCount);

        console.log(`[STRICT_DEBUG_TXN] | FLOW_ID: ${ctx.flowId} | STEP: ${ctx.step.current} | REASON: ${ctx.reason} | EVENT: UPDATE | TXN_ID: ${result.id} | CREATED: ${result.createdAt} | STATUS_BEFORE: ${beforeSnapshot?.reconStatus} | STATUS_AFTER: ${result.reconStatus} | PEND_BEFORE: ${beforeSnapshot?.pendingAction} | PEND_AFTER: ${result.pendingAction} | LINKED: ${result.linkedTransactionId} | ORG_FUND: ${result.orgFundId} | APPLIED: ${result.applied} | DUP_EXEC_COUNT: ${dupCount} | REQ_ID: ${ctx.flowId}`);
        return result;
      },
      async updateMany({ args, query }) {
        const ctx = requestContext.getStore() || { flowId: 'UNKNOWN', step: { current: 0 }, reason: 'untracked' };
        ctx.step.current += 1;
        
        const beforeSnapshots = await prismaBase.transaction.findMany({ where: args.where });
        
        const result = await query(args);
        
        for (const beforeSnapshot of beforeSnapshots) {
           let dupCount = (txExecutions.get(beforeSnapshot.id) || 0) + 1;
           txExecutions.set(beforeSnapshot.id, dupCount);
           console.log(`[STRICT_DEBUG_TXN] | FLOW_ID: ${ctx.flowId} | STEP: ${ctx.step.current} | REASON: ${ctx.reason} | EVENT: UPDATEMANY_ITEM | TXN_ID: ${beforeSnapshot.id} | CREATED: ${beforeSnapshot.createdAt} | STATUS_BEFORE: ${beforeSnapshot.reconStatus} | PEND_BEFORE: ${beforeSnapshot.pendingAction} | LINKED: ${beforeSnapshot.linkedTransactionId} | ORG_FUND: ${beforeSnapshot.orgFundId} | APPLIED: ${beforeSnapshot.applied} | DUP_EXEC_COUNT: ${dupCount} | REQ_ID: ${ctx.flowId} | NEW_DATA: ${JSON.stringify(args.data)}`);
        }
        return result;
      }
    },
    book: {
      async update({ args, query }) {
        const ctx = requestContext.getStore() || { flowId: 'UNKNOWN', step: { current: 0 }, reason: 'untracked' };
        ctx.step.current += 1;

        let beforeSnapshot = null;
        if (args.where && args.where.id) {
          beforeSnapshot = await prismaBase.book.findUnique({ where: args.where });
        }

        const result = await query(args);

        console.log(`[BALANCE_MUTATION_EVENT] | FLOW_ID: ${ctx.flowId} | STEP: ${ctx.step.current} | REASON: ${ctx.reason} | FUNC: update | BOOK_ID: ${result.id} | OLD_BAL: ${beforeSnapshot?.balance} | NEW_BAL: ${result.balance} | REQ_ID: ${ctx.flowId}`);
        return result;
      },
      async updateMany({ args, query }) {
        const ctx = requestContext.getStore() || { flowId: 'UNKNOWN', step: { current: 0 }, reason: 'untracked' };
        ctx.step.current += 1;

        const beforeSnapshots = await prismaBase.book.findMany({ where: args.where });
        const result = await query(args);
        const afterSnapshots = await prismaBase.book.findMany({ where: args.where });
        
        for (const beforeSnapshot of beforeSnapshots) {
          const afterSnapshot = afterSnapshots.find(b => b.id === beforeSnapshot.id);
          console.log(`[BALANCE_MUTATION_EVENT] | FLOW_ID: ${ctx.flowId} | STEP: ${ctx.step.current} | REASON: ${ctx.reason} | FUNC: updateMany | BOOK_ID: ${beforeSnapshot.id} | OLD_BAL: ${beforeSnapshot.balance} | NEW_BAL: ${afterSnapshot?.balance} | REQ_ID: ${ctx.flowId}`);
        }
        return result;
      }
    }
  }
});

module.exports = { prisma, prismaBase, requestContext, txExecutions, pool };
