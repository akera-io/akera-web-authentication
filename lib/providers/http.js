const async = require('async');
const BasicStrategy = require('passport-http').BasicStrategy;

module.exports = init;

function init(config, router, passport, webAuth) {

  const verify = function(req, username, password, verified) {
    // we have user and password, try to authenticate with that using all
    // strategies
    const strategies = webAuth.getLocalStrategies();

    if (strategies && strategies.length > 0) {
      async.each(strategies, function(strategy, callback) {

        // already authenticated successfully
        if (webAuth.isAuthenticated(req)) {
          callback();
        } else {
          // set the user name and password in request data
          if (req.body !== undefined) {
            req.body[strategy.options.usernameField] = username;
            req.body[strategy.options.passwordField] = password;
          } else {
            req.query[strategy.options.usernameField] = username;
            req.query[strategy.options.passwordField] = password;
          }

          passport.authenticate(strategy.name, function(err, user) {
            if (!err && user)
              webAuth.setUser(req, user);
            callback();
          })(req);
        }

      }, function() {
        // clean up
        strategies.forEach(function(strategy) {
          if (req.body !== undefined) {
            delete req.body[strategy.options.usernameField];
            delete req.body[strategy.options.passwordField];
          } else {
            delete req.query[strategy.options.usernameField];
            delete req.query[strategy.options.passwordField];
          }
        });
        verified();
      });
    } else {
      verified();
    }
  };

  // basic authentication
  const strategy = new BasicStrategy({
    passReqToCallback : true,
    realm : config.realm
  }, verify);

  passport.use(strategy);

  // check for basic authentication header, authentication delegated to other
  // providers
  router.use(function(req, res, next) {
    passport.authenticate(strategy.name, function() {
      // noop
      return next && next();
    })(req, res, next);
  });

}
