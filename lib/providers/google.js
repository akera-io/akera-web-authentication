var GoogleStrategy = require('passport-google-oauth').OAuth2Strategy;

module.exports = init;

function init(config, router, passport, webAuth) {

  if (!config || !config.clientID || !config.clientSecret)
    throw new Error('Invalid Google authentication configuration.');

  var akeraApp = router.__app;

  config.route = akeraApp.getRoute(config.route || '/google/', router);
  config.scope = config.scope
      || 'https://www.googleapis.com/auth/userinfo.profile';

  if (config.profileAuth) {
    config.authCallback = akeraApp.require(config.profileAuth);
    if (typeof config.authCallback !== 'function')
      throw new Error('Invalid profile authorization function.');
  }

  var OPTS = null;
  var authMiddleware = null;
  var strategyName = config.name || 'google';

  router.all(config.route, function(req, res, next) {
    if (OPTS === null) {

      OPTS = {
        clientID : config.clientID,
        clientSecret : config.clientSecret,
        callbackURL : webAuth.getUrl(req) + 'callback'
      };

      var strategy = new GoogleStrategy(OPTS, function(token, tokenSecret,
          profile, done) {
        if (config.authCallback) {
          config.authCallback(profile, function(err, user) {
            done(err, user);
          });
        } else {
          process.nextTick(function() {
            return done(null, profile);
          });
        }
      });

      passport.use(strategyName, strategy);

      authMiddleware = passport.authenticate(strategyName, {
        scope : config.scope
      });
    }

    if (authMiddleware !== null)
      authMiddleware(req, res, next);
  });

  router.all(config.route + 'callback', passport.authenticate(strategyName, {
    failureRedirect : config.failureRedirect
  }), function(req, res, next) {
    // successfull login
    webAuth.setUser(req, req.user);
    webAuth.successRedirect(req, res, next);
  });

}
