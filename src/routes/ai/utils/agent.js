const { prisma } = require('../../../config/database');
const {
  getLastUserMessage,
  detectAiIntent,
  parseTransactionHints,
  resolveBookFromMessage,
  extractTransactionPreviewNotes,
  stripAiActionBlocks,
  AI_ACTION_BLOCK_REGEX,
  resolveAiTransactionNote,
} = require('./parse');
const {
  formatBalanceDataBlock,
  formatTransactionsDataBlock,
} = require('./format');
const { saveAiChatTurn } = require('./chat');

const buildTransactionAction = (hints, lastUserMessage, bookRecord) => ({
  action: 'create_transaction',
  data: {
    bookId: bookRecord.id,
    bookName: bookRecord.name,
    orgName: bookRecord.organization?.name || 'Unknown',
    type: hints.type,
    amount: hints.amount,
    category: hints.category,
    note: resolveAiTransactionNote({
      note: '',
      description: '',
      amount: hints.amount,
      previewNotes: [{ note: lastUserMessage, amount: hints.amount }],
      lastUserMessage,
      category: hints.category,
    }),
    dateTime: new Date().toISOString(),
    contact: '',
    recipientUserId: null,
    orgFundId: null,
  },
  valid: true,
});

const tryDeterministicAiResponse = async (messages, agentCtx, userId) => {
  return { handled: false };
};

const prepareAiAgentRequest = async (userId, bookId, messages) => {
  const userOrgs = await prisma.organizationMember.findMany({
    where: { userId, status: 'active' },
    include: { organization: { include: { books: true } } },
  });

  const booksWithOrg = userOrgs.flatMap(m =>
    m.organization.books.map(b => ({
      book: b,
      orgName: m.organization.name,
      isPersonal: m.organization.isPersonal,
      role: m.role,
    }))
  );

  const allBooks = booksWithOrg.map(x => x.book);
  let contextBookId = resolveBookFromMessage(getLastUserMessage(messages), booksWithOrg, bookId);
  if (!contextBookId && allBooks.length > 0) {
    contextBookId = (allBooks.find(b => b.isDefault) || allBooks[0]).id;
  }

  const userData = await prisma.user.findUnique({ where: { id: userId } });
  const intent = detectAiIntent(messages);
  const lastUserMessage = getLastUserMessage(messages);
  const booksForAiTxn = booksWithOrg.filter(({ role, isPersonal }) =>
    isPersonal || role === 'admin' || role === 'editor'
  );
  const transactionHints = parseTransactionHints(lastUserMessage, booksForAiTxn, contextBookId);
  const activeBookEntry = booksWithOrg.find(x => x.book.id === contextBookId);
  const recommendedTemperature =
    intent === 'transaction' ? 0.35 : intent === 'general' ? 0.72 : 0.58;

  const today = new Date().toISOString().split('T')[0];

  let dataContextSection = '';
  const serverToolData = {};

  if (intent === 'balance') {
    const balanceBlock = formatBalanceDataBlock(allBooks);
    serverToolData.balanceBlock = balanceBlock;
    dataContextSection += `\nREAL-TIME USER BALANCE DATA:\n${balanceBlock}\n`;
  } else if (intent === 'recent' && contextBookId) {
    const txns = await prisma.transaction.findMany({
      where: { bookId: contextBookId },
      orderBy: { dateTime: 'desc' },
      take: 8,
    });
    const recentBlock = formatTransactionsDataBlock(txns);
    serverToolData.recentBlock = recentBlock;
    dataContextSection += `\nREAL-TIME RECENT TRANSACTIONS:\n${recentBlock}\n`;
  } else if (intent === 'category' && contextBookId) {
    const txns = await prisma.transaction.findMany({
      where: { bookId: contextBookId },
      orderBy: { dateTime: 'desc' },
      take: 50,
    });
    const breakdown = {};
    txns.filter(t => t.type === 'expense').forEach(t => {
      const cat = t.category || 'General';
      breakdown[cat] = (breakdown[cat] || 0) + t.amount;
    });
    const payload = Object.entries(breakdown).map(([cat, amt]) => ({ category: cat, amount: amt }));
    const categoryBlock = `[DATA type:category]\n${JSON.stringify(payload)}\n[/DATA]`;
    serverToolData.categoryBlock = categoryBlock;
    dataContextSection += `\nREAL-TIME SPENDING BREAKDOWN BY CATEGORY:\n${categoryBlock}\n`;
  }

  const systemPrompt = `You are a casual human accountant & ledger assistant. Answer very concisely to save token bandwidth.

PERSONA:
- Converse naturally in short Bangla/English (casual & fun). Avoid typical AI phrases or long preambles.
- Talk directly to the user like a friend. Get straight to the point.
- USER: ${userData?.name || 'User'}
- TODAY: ${today}
- ACTIVE BOOK: ${activeBookEntry ? `"${activeBookEntry.book.name}" (${activeBookEntry.book.id})` : 'None'}
${dataContextSection}
INSTRUCTIONS:
- Do NOT use tools if the data needed is already present in the REAL-TIME context above. Just read it and reply immediately.
- To fetch extra missing data, write the tool command on its own line:
  1. [FETCH_RULE: <id>] -> Rules (id-01-transaction, id-02-design)
  2. [FETCH_NOTES: <count>] -> Quick audio notes
  3. [FETCH_BALANCE] -> Balances (only if missing in context)
  4. [FETCH_RECENT_TXN] -> Active book recent txns (only if missing in context)

TRANSACTIONS:
- ALL fields are strictly MANDATORY: amount, category, description, and note.
- DESCRIPTION MUST BE VERY DETAILED (INCLUDING WORK/PURPOSE CONTEXT):
  * Transport (e.g. Rickshaw, Uber, Bus): You must ask "কোথায় থেকে কোথায় গিয়েছিলেন? কেন গিয়েছিলেন? কোন কাজের কারণে বা অফিশিয়াল প্রয়োজনে? সাথে কি কেউ ছিল?" (From where to where? Why? For what official work/purpose? Anyone with you?). Do NOT accept simple travel endpoints.
  * Food/Restaurant: You must ask "কোথায় খেয়েছেন? কার সাথে? কোন অফিসের কাজ, প্রোগ্রাম বা মেহমানদারির কারণে এই খরচ করা হয়েছে?" (Where did you eat? With whom? Under what office work, event, or guest hospitality?).
  * Other categories: Always ask for the detailed purpose/work context.
- TWO-STEP CONFIRMATION FLOW (STRICT REQUIREMENT):
  1. First, ask conversational questions to gather all the mandatory description details (including the official work purpose).
  2. Once all details are gathered, summarize them and explicitly ask the user for confirmation (e.g., "আমি কি এটি আপনার ডেমো খাতায় যোগ করব?").
  3. ONLY output the JSON action block AFTER the user explicitly confirms (e.g., says "yes", "হ্যাঁ", "করো", "যোগ করো"). Do NOT output the action block before the user says yes.
- Once confirmed by the user, output the action block using this exact format:
\`\`\`action
{"action":"create_transaction","data":{"bookId":"<id>","type":"expense","amount":500,"category":"Transport","description":"Rickshaw fare from Dhanmondi to Gulshan to print program banner with Rahim","note":"Rickshaw"}}
\`\`\`
`;

  return {
    systemPrompt,
    contextBookId,
    intent,
    serverToolData,
    transactionHints,
    recommendedTemperature,
  };
};

const parseAiAgentActions = async (aiResponseText, contextBookId, userId, { onComplaint, lastUserMessage, previewNotes } = {}) => {
  const matches = [...aiResponseText.matchAll(AI_ACTION_BLOCK_REGEX)];
  let cleanResponse = stripAiActionBlocks(aiResponseText);
  const proposedActions = [];
  const txnPreviews = previewNotes || extractTransactionPreviewNotes(aiResponseText);
  const userMsg = lastUserMessage || '';

  for (const match of matches) {
    try {
      const actionData = JSON.parse(match[1].trim());
      if (actionData.action === 'create_transaction' && actionData.data) {
        const { bookId: txnBookId, type, amount, category, note, dateTime, contact, recipientUserId, orgFundId, description } = actionData.data;
        
        if (!amount || !category || !description) {
          proposedActions.push({
            action: 'create_transaction',
            data: { ...actionData.data },
            valid: false,
            reason: 'Missing required strict fields: amount, category, or description',
          });
          continue;
        }

        const resolvedNote = resolveAiTransactionNote({
          note,
          description,
          amount,
          previewNotes: txnPreviews,
          lastUserMessage: userMsg,
          category,
        });
        const book = await prisma.book.findFirst({
          where: { id: txnBookId || contextBookId },
          include: { organization: { include: { members: { where: { userId } } } } },
        });
        if (!book || book.organization.members.length === 0) {
          proposedActions.push({
            action: 'create_transaction',
            data: { ...actionData.data, note: resolvedNote },
            valid: false,
            reason: 'Book not found or access denied',
          });
        } else {
          proposedActions.push({
            action: 'create_transaction',
            data: {
              bookId: book.id,
              bookName: book.name,
              orgName: book.organization?.name || 'Unknown',
              type,
              amount: parseFloat(amount),
              category: category || 'General',
              note: resolvedNote,
              dateTime: dateTime ? new Date(dateTime) : new Date().toISOString(),
              contact: contact || '',
              recipientUserId: recipientUserId || null,
              orgFundId: orgFundId || null,
              description: description || '',
            },
            valid: true,
          });
        }
      }
      if (actionData.action === 'create_complaint' && actionData.data) {
        const { subject, message, category } = actionData.data;
        if (subject && message) {
          try {
            const complaint = await prisma.complaint.create({
              data: { userId, subject, message, category: category || 'Other' },
            });
            if (onComplaint) {
              onComplaint({ subject, id: complaint.id });
            } else {
              cleanResponse += `\n\nআপনার রিপোর্ট "${subject}" জমা হয়েছে।`;
            }
          } catch (err) {
            console.error('[AI Agent] Auto-execute complaint failed:', err);
          }
        }
      }
    } catch (parseErr) {
      console.error('[AI Agent] Action parse error:', parseErr);
    }
  }

  return { cleanResponse, proposedActions };
};

const finalizeAiAgentResponse = async (aiResponseText, { contextBookId, userId, intent, serverToolData, onComplaint, messages }) => {
  const lastUserMessage = getLastUserMessage(messages);
  const previewNotes = extractTransactionPreviewNotes(aiResponseText);
  const { cleanResponse: baseClean, proposedActions } = await parseAiAgentActions(
    aiResponseText,
    contextBookId,
    userId,
    { onComplaint, lastUserMessage, previewNotes }
  );
  let cleanResponse = baseClean;

  if (intent === 'balance' && serverToolData?.balanceBlock && !cleanResponse.includes('[DATA type:balance]')) {
    cleanResponse = cleanResponse
      ? `${cleanResponse}\n\n${serverToolData.balanceBlock}`
      : serverToolData.balanceBlock;
  }
  if (intent === 'category' && serverToolData?.categoryBlock && !cleanResponse.includes('[DATA type:category]')) {
    cleanResponse = cleanResponse
      ? `${cleanResponse}\n\n${serverToolData.categoryBlock}`
      : serverToolData.categoryBlock;
  }
  if (intent === 'recent' && serverToolData?.recentBlock && !cleanResponse.includes('[DATA type:transactions]')) {
    cleanResponse = cleanResponse
      ? `${cleanResponse}\n\n${serverToolData.recentBlock}`
      : serverToolData.recentBlock;
  }

  return { cleanResponse: cleanResponse.trim(), proposedActions };
};

const emitAiStreamFinal = async (sendEvent, fullText, agentCtx, userId, messages, meta = {}) => {
  const { cleanResponse, proposedActions } = await finalizeAiAgentResponse(fullText, {
    ...agentCtx,
    userId,
    messages,
    onComplaint: ({ subject, id }) => sendEvent('auto_action', { action: 'create_complaint', subject, id }),
  });
  if (proposedActions.length > 0) sendEvent('actions', { actions: proposedActions });
  sendEvent('clean', { response: cleanResponse });
  await saveAiChatTurn({
    userId,
    userMessage: getLastUserMessage(messages),
    assistantMessage: cleanResponse,
    bookId: agentCtx.contextBookId,
    model: meta.model || null,
    provider: meta.provider || null,
    intent: agentCtx.intent || null,
  });
};

module.exports = {
  buildTransactionAction,
  tryDeterministicAiResponse,
  prepareAiAgentRequest,
  parseAiAgentActions,
  finalizeAiAgentResponse,
  emitAiStreamFinal,
};
