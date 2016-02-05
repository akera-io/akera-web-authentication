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

  router.get(config.route, function(req) {
    if (OPTS === null) {

      OPTS = {
        clientID : config.clientID,
        clientSecret : config.clientSecret,
        profileFields : config.profileFields,
        enableProof : config.enableProof,
        callbackURL : req.originalURL
      };

      passport.use(new FacebookStrategy(OPTS, function(accessToken,
          refreshToken, profile, done) {
        if (config.authCallback) {
          config.authCallback(profile, function(err, user) {
            done(err, user);
          });
        } else {
          process.nextTick(function() {
            return done(null, profile);
          });
        }
      }));
    }
  }, passport.authenticate('facebook', {
    scope : config.scope
  }));

  router.get(config.route + 'callback', passport.authenticate('facebook', {
    failureRedirect : config.failureRedirect
  }), function(req, res, next) {
    // successfull login
    req.session.user = req.user;
    webAuth.successRedirect(req, res, next);
  });

}
