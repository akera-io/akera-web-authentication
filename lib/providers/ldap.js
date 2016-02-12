var LdapStrategy = require('passport-ldapauth');

module.exports = init;

function init(config, router, passport, webAuth) {

  if (!config || !config.url || !config.bindDn || !config.bindCredentials)
    throw new Error('LDAP configuration invalid.');

  var searchBase = config.searchBase;

  if (!searchBase) {
    if (config.searchDomain) {
      searchBase = config.searchDomain.split('.').reduce(
          function(prev, current) {
            if (prev !== '')
              prev += ',';
            return prev + 'DC=' + current;
          }, '');
    } else {
      throw new Error('LDAP search base or domain need to be set.');
    }
  }

  var searchFilter = config.searchFilter
      || '(&(objectcategory=person)(objectclass=user)(|(samaccountname={{username}})(mail={{username}})))';
  var usernameField = config.usernameField || 'username';
  var passwordField = config.passwordField || 'password';

  var OPTS = {
    server : {
      url : config.url,
      bindDn : config.bindDn,
      bindCredentials : config.bindCredentials,
      searchBase : searchBase,
      searchFilter : searchFilter, 
      reconnect : true,
      timeout : parseInt((config.timeout || 1000), 10)
    },
    usernameField : usernameField,
    passwordField : passwordField

  };
  
  var strategy = new LdapStrategy(OPTS);
  var strategyName = config.name || strategy.name;
  
  passport.use(strategyName, strategy);

  var akeraApp = router.__app;
  config.route = akeraApp.getRoute(config.route || '/ldap/');

  router.post(config.route, function(req, res, next) {
    passport.authenticate(strategyName, function(err, user, info) {
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
