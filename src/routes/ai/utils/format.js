const formatBalanceDataBlock = (books) => {
  const payload = books.map(b => ({ book: b.name, balance: b.balance, org: b.organization }));
  return `[DATA type:balance]\n${JSON.stringify(payload)}\n[/DATA]`;
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

module.exports = {
  formatBalanceDataBlock,
  formatTransactionsDataBlock,
};
