const { prisma } = require('../../../config/database');

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

const CATEGORY_KEYWORDS = [
  { keys: ['rickshaw', 'রিকশা', 'bus', 'বাস', 'transport', 'যাতায়াত', 'pathao', 'uber', 'cng'], cat: 'Transport' },
  { keys: ['food', 'খাবার', 'breakfast', 'lunch', 'dinner', 'snack', 'নাস্তা'], cat: 'Food' },
  { keys: ['bazar', 'বাজার', 'market', 'grocery', 'সবজি'], cat: 'Shopping' },
  { keys: ['bill', 'বিল', 'electric', 'gas', 'internet', 'mobile'], cat: 'Bills' },
  { keys: ['salary', 'বেতন', 'income', 'আয়', 'donation', 'দান'], cat: 'Income' },
  { keys: ['medicine', 'doctor', 'চিকিৎসা', 'hospital'], cat: 'Medical' },
  { keys: ['education', 'school', 'college', 'শিক্ষা', 'book'], cat: 'Education' },
];

const AI_ACTION_BLOCK_REGEX = /```action\s*([\s\S]*?)```/g;

const stripAiActionBlocks = (text) => (text || '').replace(AI_ACTION_BLOCK_REGEX, '').trim();

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
    } catch (_) { }
  }
  return previews;
};

const isBanglaMessage = (text) => /[\u0980-\u09FF]/.test(text || '');

const getLastUserMessage = (messages) => {
  const last = [...(messages || [])].reverse().find(m => m.role === 'user');
  return (last?.content || '').trim();
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

module.exports = {
  normalizeForBookMatch,
  matchBookFromUserMessage,
  CATEGORY_KEYWORDS,
  AI_ACTION_BLOCK_REGEX,
  stripAiActionBlocks,
  extractTransactionPreviewNotes,
  isBanglaMessage,
  getLastUserMessage,
  resolveAiTransactionNote,
  detectAiIntent,
  parseTransactionHints,
  resolveBookFromMessage,
};
