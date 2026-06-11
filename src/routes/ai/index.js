const chat = require('./chat');
const agent = require('./agent');

module.exports = function(app) {
  chat(app);
  agent(app);
};
