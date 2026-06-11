const { AsyncLocalStorage } = require('async_hooks');
const requestContext = new AsyncLocalStorage();

const { prisma } = require('../../config/database');
const { broadcast, broadcastToUser, broadcastToUsers } = require('../../websocket');

module.exports = function(app, deps) {

// --- STRICT DEBUG LOGGER CONTEXT INJECTION ---
app.use('/api/transactions', (req, res, next) => {
  const flowId = Math.random().toString(36).substring(2, 10);
  let reason = req.method + ' ' + req.path;
  if (req.path === '/' && req.method === 'POST') reason = 'CREATE/SEND';
  else if (req.method === 'PUT') reason = 'EDIT';
  else if (req.method === 'DELETE') reason = 'DELETE';
  else if (req.path.includes('/approve')) reason = 'APPROVE';
  else if (req.path.includes('/reject')) reason = 'REJECT';
  else if (req.path.includes('/retry')) reason = 'RETRY';
  else if (req.path.includes('/modify')) reason = 'MODIFY_AMOUNT';

  requestContext.run({ flowId, step: { current: 0 }, reason }, () => {
    next();
  });
});

  require('./create')(app, deps);
  require('./edit')(app, deps);
  require('./delete')(app, deps);
  require('./query')(app, deps);
};
