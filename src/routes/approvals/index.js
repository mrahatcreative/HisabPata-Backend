module.exports = function(app, deps) {
  require('./action')(app, deps);
  require('./pending')(app, deps);
};
