var FacebookStrategy = require('passport-facebook').Strategy;

module.exports = init;

function init(config, router, passport, webAuth) {

  if (!config || !config.clientID || !config.clientSecret)
    throw new Error('Invalid Facebook authentication configuration.');

  var akeraApp = router.__app;

  config.route = akeraApp.getRoute(config.route || '/facebook/');
  config.scope = config.scope || 'email';

  if (!(config.scope instanceof Array))
    config.scope = [ config.scope ];

  config.profileFields = config.profileFields || [ 'id', 'emails', 'name' ];
  config.enableProof = config.enableProof || false;

  if (config.profileAuth) {
    config.authCallback = akeraApp.require(config.profileAuth);
    if (typeof config.authCallback !== 'function')
      throw new Error('Invalid profile authorization function.');
  }

  var OPTS = null;
  var authMiddleware = null;
  var strategyName = config.name || 'facebook';

  router.all(config.route, function(req, res, next) {

    if (OPTS === null) {
      // only mount the strategy on first request to be able to set the full
      // callback URL
      OPTS = {
        clientID : config.clientID,
        clientSecret : config.clientSecret,
        profileFields : config.profileFields,
        enableProof : config.enableProof,
        callbackURL : webAuth.getUrl(req) + 'callback'
      };

      var strategy = new FacebookStrategy(OPTS, function(accessToken,
          refreshToken, profile, done) {
        if (typeof config.authCallback === 'function') {
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
    try {
      req.user.displayName = req.user.name.givenName + ' ' + req.user.name.familyName;
      req.user.email = req.user.emails[0].value;
    } catch (e) {
    }
    
    webAuth.setUser(req, req.user);
    webAuth.successRedirect(req, res, next);
  });

}
