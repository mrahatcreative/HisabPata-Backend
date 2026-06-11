const orgRoutes = require('./org');
const membersRoutes = require('./members');

module.exports = function(app) {
  orgRoutes(app);
  membersRoutes(app);
};
