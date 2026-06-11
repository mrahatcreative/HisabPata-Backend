const { prisma } = require('../../config/database');

const AI_ACTION_BLOCK_REGEX = /```action\s*([\s\S]*?)```/g;

const stripAiActionBlocks = (text) => (text || '').replace(AI_ACTION_BLOCK_REGEX, '').trim();

const getLastUserMessage = (messages) => {
  const last = [...(messages || [])].reverse().find(m => m.role === 'user');
  return (last?.content || '').trim();
};

const extractTransactionPreviewNotes = (aiResponseText) => {
  const regex = /\[DATA type:transactions\]([\s\S]*?)\[\/DATA\]/g;
  const previews = [];
  for (const match of aiResponseText.matchAll(regex)) {
    try {
      const items = JSON.parse(match[1].trim());
      if (Array.isArray(items)) {
        for (const item of items) {
          if (item && typeof item === 'object') previews.push(item);
        }
      }
    } catch (_) { /* skip malformed preview blocks */ }
  }
  return previews;
};

const resolveAiTransactionNote = ({ note, description, amount, previewNotes, lastUserMessage, category }) => {
  const direct = (note || description || '').trim();
  if (direct) return direct;

  const parsedAmount = parseFloat(amount);
  if (Number.isFinite(parsedAmount) && previewNotes?.length) {
    const match = previewNotes.find(
      p => p?.note && Math.abs(parseFloat(p.amount) - parsedAmount) < 0.01
    );
    if (match?.note) return String(match.note).trim();
    if (previewNotes.length === 1 && previewNotes[0]?.note) {
      return String(previewNotes[0].note).trim();
    }
  }

  if (lastUserMessage) return lastUserMessage;
  return (category || 'General').trim();
};

const normalizeForBookMatch = (s) =>
  String(s || '').toLowerCase().replace(/[^\w\u0980-\u09ff]/gi, '').trim();

const matchBookFromUserMessage = (text, booksWithOrg) => {
  const q = normalizeForBookMatch(text);
  if (!q || !booksWithOrg?.length) return null;

  let best = null;
  let bestScore = 0;

  for (const entry of booksWithOrg) {
    const name = normalizeForBookMatch(entry.book.name);
    if (!name || name.length < 2) continue;

    if (q.includes(name) || name.includes(q)) {
      return entry;
    }

    const nameWords = String(entry.book.name || '')
      .toLowerCase()
      .split(/[\s_\-]+/)
      .filter((w) => w.length >= 2);
    for (const word of nameWords) {
      const nw = normalizeForBookMatch(word);
      if (nw.length >= 3 && q.includes(nw)) {
        const score = nw.length + 10;
        if (score > bestScore) {
          bestScore = score;
          best = entry;
        }
      }
    }

    if (/উইক|week|weekly/i.test(q) && /week|উইক|weekly/i.test(name)) {
      const score = 12;
      if (score > bestScore) {
        bestScore = score;
        best = entry;
      }
    }
    if (/নোট|note|notebook/i.test(q) && /note|নোট|book/i.test(name)) {
      const score = 6;
      if (score > bestScore) {
        bestScore = score;
        best = entry;
      }
    }
  }
  return best;
};

const detectAiIntent = (messages) => {
  const lastUser = [...(messages || [])].reverse().find(m => m.role === 'user');
  const q = (lastUser?.content || '').toLowerCase();

  if (
    /(balance|ব্যালেন্স|balence|মোট ব্যালেন্স|total balance|কত টাকা|how much money|জমা|deposit|স্থিতি|বাকি|টাকা আছে|কত আছে|কি আছে|আছে কি|কত টাকা)/i.test(
      q
    )
  ) {
    return 'balance';
  }
  if (
    /(খাতায়|বইতে|book|notebook|নোটবুক|উইক|week)/i.test(q) &&
    /(কত|আছে|জমা|টাকা|balance|খরচ|আয়|income|expense)/i.test(q)
  ) {
    return 'balance';
  }
  if (/(category|ক্যাটাগরি|খরচের হার|spending breakdown|বিভাগে খরচ|কোন খাতে)/i.test(q)) {
    return 'category';
  }
  if (/(recent|সাম্প্রতিক|latest|গত|last \d+|লেনদেন দেখ|transaction list|লেনদেন তালিকা)/i.test(q)) {
    return 'recent';
  }
  if (/(help|সাহায্য|কী কর|ki korte|how to|কিভাবে)/i.test(q) && !/\d/.test(q)) {
    return 'help';
  }
  if (/\d/.test(q) && /(খরচ|expense|income|আয়|লেনদেন|record|যোগ|add|rickshaw|রিকশা|bazar|বাজার|send|পাঠ)/i.test(q)) {
    return 'transaction';
  }
  if (/(কুইক নোট|quick note|voice note|ভয়েস নোট).*(বিশ্লেষণ|পড়|analyze|read|summary|সারাংশ|এন্ট্রি|entry|লেনদেন)/i.test(q)) {
    return 'general';
  }
  return 'general';
};

const AI_LLM_HISTORY_LIMIT = 6;
const AI_LLM_CONTENT_LIMIT = 1800;
const GEMINI_DEFAULT_BASE = 'https://generativelanguage.googleapis.com';

const normalizeGeminiBaseUrl = (baseUrl) => {
  if (!baseUrl || typeof baseUrl !== 'string') return null;
  let base = baseUrl.trim().replace(/\/+$/, '');
  if (!base) return null;
  base = base.replace(/\/v1beta(\/.*)?$/i, '');
  return base;
};

const buildGeminiRequestUrl = (baseUrl, model, mode, apiKey) => {
  const base = normalizeGeminiBaseUrl(baseUrl) || GEMINI_DEFAULT_BASE;
  const endpoint = mode === 'stream' ? 'streamGenerateContent' : 'generateContent';
  const query = mode === 'stream'
    ? `alt=sse&key=${encodeURIComponent(apiKey)}`
    : `key=${encodeURIComponent(apiKey)}`;
  return `${base}/v1beta/models/${encodeURIComponent(model)}:${endpoint}?${query}`;
};

const safeFetchJson = async (res) => {
  const text = await res.text();
  if (!text) return {};
  try {
    return JSON.parse(text);
  } catch {
    return { error: { message: text.slice(0, 300) } };
  }
};

const geminiTextFromResponse = (data) => {
  const parts = data?.candidates?.[0]?.content?.parts;
  if (!Array.isArray(parts)) return '';
  return parts.map((p) => (typeof p?.text === 'string' ? p.text : '')).join('');
};

const isGeminiThinkingModel = (model) => /gemini-2\.5|gemini-3/i.test(String(model || ''));

const resolveAiMaxTokens = (maxTokens, model = '', provider = '') => {
  const parsed = maxTokens != null ? parseInt(maxTokens, 10) : 512;
  const safe = Number.isFinite(parsed) ? parsed : 512;
  if (provider === 'gemini' && isGeminiThinkingModel(model)) {
    return Math.min(Math.max(safe, 2048), 8192);
  }
  return Math.min(Math.max(safe, 256), 2048);
};

const truncateAiMessagesForLlm = (messages, maxCount = AI_LLM_HISTORY_LIMIT) => {
  if (!Array.isArray(messages)) return [];
  return messages.slice(-maxCount).map(m => ({
    role: m.role,
    content: String(m.content || '').slice(0, AI_LLM_CONTENT_LIMIT),
  }));
};

const saveAiChatTurn = async ({ userId, userMessage, assistantMessage, bookId, model, provider, intent }) => {
  const userText = String(userMessage || '').trim();
  const assistantText = String(assistantMessage || '').trim();
  if (!userId || !userText || !assistantText) return;
  try {
    await prisma.aiChatMessage.createMany({
      data: [
        { userId, role: 'user', content: userText, bookId: bookId || null, model: model || null, provider: provider || null, intent: intent || null },
        { userId, role: 'assistant', content: assistantText, bookId: bookId || null, model: model || null, provider: provider || null, intent: intent || null },
      ],
    });
  } catch (error) {
    console.error('[AI Chat] Failed to save turn:', error);
  }
};

const isBanglaMessage = (text) => /[\u0980-\u09FF]/.test(text || '');

const CATEGORY_KEYWORDS = [
  { keys: ['rickshaw', 'রিকশা', 'bus', 'বাস', 'transport', 'যাতায়াত', 'pathao', 'uber', 'cng'], cat: 'Transport' },
  { keys: ['food', 'খাবার', 'breakfast', 'lunch', 'dinner', 'snack', 'নাস্তা'], cat: 'Food' },
  { keys: ['bazar', 'বাজার', 'market', 'grocery', 'সবজি'], cat: 'Shopping' },
  { keys: ['bill', 'বিল', 'electric', 'gas', 'internet', 'mobile'], cat: 'Bills' },
  { keys: ['salary', 'বেতন', 'income', 'আয়', 'donation', 'দান'], cat: 'Income' },
  { keys: ['medicine', 'doctor', 'চিকিৎসা', 'hospital'], cat: 'Medical' },
  { keys: ['education', 'school', 'college', 'শিক্ষা', 'book'], cat: 'Education' },
];

const parseTransactionHints = (text, booksWithOrg, defaultBookId) => {
  const q = (text || '').toLowerCase();
  const amountMatch = (text || '').match(/(\d+(?:[.,]\d+)?)\s*(?:টাকা|taka|tk|bdt|৳)?/i);
  const amount = amountMatch ? parseFloat(String(amountMatch[1]).replace(',', '')) : null;

  let type = 'expense';
  if (/(income|আয়|salary|বেতন|received|পেলাম|জমা|donation|দান)/i.test(text || '')) {
    type = 'income';
  }

  let category = type === 'income' ? 'Income' : 'General';
  for (const { keys, cat } of CATEGORY_KEYWORDS) {
    if (keys.some(k => q.includes(k.toLowerCase()))) {
      category = cat;
      break;
    }
  }

  let matchedEntry = matchBookFromUserMessage(text, booksWithOrg);
  if (!matchedEntry) {
    for (const entry of booksWithOrg) {
      const name = entry.book.name.toLowerCase();
      if (name.length > 2 && q.includes(name)) {
        matchedEntry = entry;
        break;
      }
    }
  }
  if (!matchedEntry && /(personal|পার্সোনাল|personal book|নিজের)/i.test(text || '')) {
    matchedEntry = booksWithOrg.find(x => x.isPersonal) || null;
  }
  if (!matchedEntry && defaultBookId) {
    matchedEntry = booksWithOrg.find(x => x.book.id === defaultBookId) || null;
  }

  return {
    amount,
    type,
    category,
    bookId: matchedEntry?.book.id || null,
    bookName: matchedEntry?.book.name || null,
    orgName: matchedEntry?.orgName || null,
    isPersonal: matchedEntry?.isPersonal ?? null,
  };
};

const resolveBookFromMessage = (text, booksWithOrg, defaultBookId) => {
  const hints = parseTransactionHints(text, booksWithOrg, defaultBookId);
  return hints.bookId || defaultBookId || null;
};

const formatTransactionsDataBlock = (transactions) => {
  const payload = transactions.map(t => ({
    note: t.note || t.category || '',
    amount: t.amount,
    type: t.type || 'expense',
    category: t.category || 'General',
  }));
  return `[DATA type:transactions]\n${JSON.stringify(payload)}\n[/DATA]`;
};

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

const formatBalanceDataBlock = (books) => {
  const payload = books.map(b => ({ book: b.name, balance: b.balance, org: b.organization }));
  return `[DATA type:balance]\n${JSON.stringify(payload)}\n[/DATA]`;
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

module.exports = {
  prisma,
  getLastUserMessage,
  saveAiChatTurn,
  prepareAiAgentRequest,
  tryDeterministicAiResponse,
  finalizeAiAgentResponse,
  emitAiStreamFinal,
  loadUserAiConfig,
  resolveAiRequestConfig,
  truncateAiMessagesForLlm,
  resolveAiMaxTokens,
  buildGeminiRequestUrl,
  safeFetchJson,
  geminiTextFromResponse,
  isGeminiThinkingModel,
  formatBalanceDataBlock,
  formatTransactionsDataBlock,
};
