const { prisma } = require('../../config/database');
const { authenticateToken } = require('../../middleware/auth');
const {
  prepareAiAgentRequest,
  tryDeterministicAiResponse,
  saveAiChatTurn,
  getLastUserMessage,
  finalizeAiAgentResponse,
  formatBalanceDataBlock,
  formatTransactionsDataBlock,
} = require('./utils');

module.exports = function(app) {

app.post('/api/ai/agent/prepare', authenticateToken, async (req, res) => {
  try {
    const { bookId, messages } = req.body;
    if (!messages || !Array.isArray(messages)) {
      return res.status(400).json({ error: 'messages array is required' });
    }

    const agentCtx = await prepareAiAgentRequest(req.user.id, bookId, messages);
    const { systemPrompt, contextBookId, intent, serverToolData, recommendedTemperature } = agentCtx;

    const deterministic = await tryDeterministicAiResponse(messages, agentCtx, req.user.id);
    if (deterministic.handled) {
      await saveAiChatTurn({
        userId: req.user.id,
        userMessage: getLastUserMessage(messages),
        assistantMessage: deterministic.cleanResponse,
        bookId: contextBookId,
        model: null,
        provider: null,
        intent,
      });
      return res.json({
        mode: 'deterministic',
        response: deterministic.cleanResponse,
        proposedActions: deterministic.proposedActions || [],
        contextBookId,
        intent,
      });
    }

    return res.json({
      mode: 'llm',
      systemPrompt,
      recommendedTemperature,
      contextBookId,
      intent,
      serverToolData: serverToolData || {},
    });
  } catch (error) {
    console.error('[AI Agent Prepare] Error:', error);
    const msg = error?.message || String(error);
    return res.status(500).json({
      error: msg.includes('AudioNote') || msg.includes('does not exist')
        ? `Database migration required: ${msg}`
        : msg || 'Failed to prepare AI context',
    });
  }
});

app.post('/api/ai/agent/finalize', authenticateToken, async (req, res) => {
  try {
    const {
      rawText,
      bookId,
      messages,
      intent,
      contextBookId,
      serverToolData,
      model,
      provider,
    } = req.body;

    if (!rawText || !messages) {
      return res.status(400).json({ error: 'rawText and messages are required' });
    }

    const ctxBookId = contextBookId || bookId || null;
    const { cleanResponse, proposedActions } = await finalizeAiAgentResponse(rawText, {
      contextBookId: ctxBookId,
      userId: req.user.id,
      intent: intent || 'general',
      serverToolData: serverToolData || {},
      messages,
    });

    await saveAiChatTurn({
      userId: req.user.id,
      userMessage: getLastUserMessage(messages),
      assistantMessage: cleanResponse,
      bookId: ctxBookId,
      model: model || null,
      provider: provider || null,
      intent: intent || null,
    });

    return res.json({ response: cleanResponse, proposedActions });
  } catch (error) {
    console.error('[AI Agent Finalize] Error:', error);
    return res.status(500).json({ error: error.message || 'Failed to finalize AI response' });
  }
});

app.post('/api/ai/agent/tool', authenticateToken, async (req, res) => {
  try {
    const { toolName, args, bookId } = req.body;
    
    if (toolName === 'FETCH_RULE') {
      const { id } = args || {};
      if (id === 'id-01-transaction') {
        return res.json({ result: "Rule 01 - Transactions:\n- Must capture amount.\n- Must categorize properly.\n- Must provide detailed description (what/where/how/why)." });
      } else if (id === 'id-02-design') {
        return res.json({ result: "Rule 02 - Design:\n- Provide a beautiful, well-formatted response.\n- Use bold text for numbers." });
      } else {
        return res.json({ result: "Rule not found." });
      }
    } else if (toolName === 'FETCH_BALANCE') {
      const userOrgs = await prisma.organizationMember.findMany({
        where: { userId: req.user.id, status: 'active' },
        include: { organization: { include: { books: true } } },
      });
      const booksWithOrg = userOrgs.flatMap(m =>
        m.organization.books.map(b => ({
          book: b,
          orgName: m.organization.name,
          isPersonal: m.organization.isPersonal,
        }))
      );
      const balanceBooks = booksWithOrg.map(({ book, orgName, isPersonal }) => ({
        name: book.name,
        balance: book.balance,
        organization: isPersonal ? 'Personal' : orgName,
      }));
      return res.json({ result: formatBalanceDataBlock(balanceBooks) });
    } else if (toolName === 'FETCH_RECENT_TXN') {
      if (!bookId) return res.json({ result: "No bookId provided." });
      const recentTxns = await prisma.transaction.findMany({
        where: { bookId },
        orderBy: { dateTime: 'desc' },
        take: 10,
      });
      const preview = recentTxns.map((t) => ({
        note: t.note || t.category || '',
        amount: t.amount,
        type: t.type,
        category: t.category,
      }));
      return res.json({ result: formatTransactionsDataBlock(preview) });
    }
    
    return res.json({ result: "Unknown tool call." });
  } catch (error) {
    console.error('[AI Tool] Error:', error);
    res.status(500).json({ error: error.message });
  }
});

};
