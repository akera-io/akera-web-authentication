var GoogleStrategy = require('passport-google-oauth').OAuth2Strategy;

module.exports = init;

function init(config, router, passport, webAuth) {

  if (!config || !config.clientID || !config.clientSecret)
    throw new Error('Invalid Google authentication configuration.');

  var akeraApp = router.__app;

  config.route = akeraApp.getRoute(config.route || '/google/');
  config.scope = config.scope
      || 'https://www.googleapis.com/auth/userinfo.profile';

  if (config.profileAuth) {
    config.authCallback = akeraApp.require(config.profileAuth);
    if (typeof config.authCallback !== 'function')
      throw new Error('Invalid profile authorization function.');
  }

  var OPTS = null;
  var strategyName = config.name || 'google';

  router.get(config.route, function(req) {
    if (OPTS === null) {

      OPTS = {
        clientID : config.clientID,
        clientSecret : config.clientSecret,
        callbackURL : req.originalURL
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
    }
  }, passport.authenticate(strategyName, {
    scope : config.scope
  }));

  router.get(config.route + 'callback', passport.authenticate(strategyName, {
    failureRedirect : config.failureRedirect
  }), function(req, res, next) {
    // successfull login
    req.session.user = req.user;
    webAuth.successRedirect(req, res, next);
  });

}
