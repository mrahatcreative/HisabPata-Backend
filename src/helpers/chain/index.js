const resolve = require('./resolve');
const approvers = require('./approvers');
const pending = require('./pending');
const legs = require('./legs');
const notify = require('./notify');

module.exports = {
  ...resolve,
  ...approvers,
  ...pending,
  ...legs,
  ...notify,
};
