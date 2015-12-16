var AkeraStrategy = require('passport-akera').Strategy;

module.exports = init;

function init(config, router, passport, webAuth) {

  // broker configuration required for api authentication
  if (!config || !config.host || !config.port) {
    // if service mounted on broker get configuration from it
    if (router.__broker) {
      config = config || {};
      config.host = config.host || router.__broker.host;
      config.port = config.port || router.__broker.port;
      config.useSSL = config.useSSL || router.__broker.useSSL;
    } else
      throw new Error('Invalid Akera authentication configuration.');
  }

  var OPTS = {
    server : {
      host : config.host,
      port : config.port,
      useSSL : config.useSSL || false
    },
    usernameField : config.usernameField || 'username',
    passwordField : config.passwordField || 'password'
  };

  passport.use(new AkeraStrategy(OPTS));

  router.post(config.route || '/akera/', function(req, res, next) {
    passport.authenticate('akeraAuth', function(err, user, info) {
      if (err)
        return next(err);
      if (!user)
        return next(info || new Error('Invalid credentials.'));

      if (req.session)
        req.session.user = user;

      webAuth.successRedirect(req, res, next);
    })(req, res, next);
  });
}
