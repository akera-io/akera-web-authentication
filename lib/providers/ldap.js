var LdapStrategy = require('passport-ldapauth');
var fs = require('fs');

module.exports = init;

function init(config, router, passport, webAuth) {

  if (!config || !config.url || !config.bindDn || !config.bindCredentials)
    throw new Error('LDAP configuration invalid.');

  var akeraApp = router.__app;
  var searchBase = config.searchBase;

  if (!searchBase) {
    if (config.searchDomain) {
      searchBase = config.searchDomain.split('.').reduce(
        function (prev, current) {
          if (prev !== '')
            prev += ',';
          return prev + 'DC=' + current;
        }, '');
    } else {
      throw new Error('LDAP search base or domain need to be set.');
    }
  }

  var searchFilter = config.searchFilter ||
    '(&(objectcategory=person)(objectclass=user)(|(samaccountname={{username}})(mail={{username}})))';
  var usernameField = config.usernameField || 'username';
  var passwordField = config.passwordField || 'password';

  var OPTS = {
    server: {
      url: config.url,
      bindDn: config.bindDn,
      bindCredentials: config.bindCredentials,
      searchBase: searchBase,
      searchFilter: searchFilter,
      reconnect: true,
      timeout: parseInt((config.timeout || 1000), 10)
    },
    usernameField: usernameField,
    passwordField: passwordField
  };

  if (config.tlsOptions) {
    try {
      if (config.tlsOptions.ca) {
        if (typeof config.tlsOptions.ca === 'string')
          config.tlsOptions.ca = [fs.readFileSync(config.tlsOptions.ca)];
        else if (typeof config.tlsOptions.ca === 'object') {
          for (var key in config.tlsOptions.ca) {
            config.tlsOptions.ca[key] = fs.readFileSync(config.tlsOptions.ca[key]);
          }
        }
      }
    } catch (err) {
      akeraApp.log('warn', `Ldap CA certificate load error: ${err.message}`);
    }

    OPTS.server.tlsOptions = config.tlsOptions;
  }

  var strategy = new LdapStrategy(OPTS);
  var strategyName = config.name || strategy.name;

  passport.use(strategyName, strategy);
  webAuth.addLocalStrategy(strategyName, OPTS);

  config.route = akeraApp.getRoute(config.route || '/ldap/');

  router.all(config.route, function (req, res, next) {
    try {
      passport.authenticate(strategyName, function (err, user, info) {
        if (!user)
          err = err || new Error('Invalid user credentials.');

        if (err) {
          akeraApp.log('warn', 'Ldap authentication error: $1 ($2)', err.message, info);
          return next(err);
        }

        webAuth.setUser(req, user);
        webAuth.successRedirect(req, res, next);
      })(req, res, next);
    } catch (err) {
      akeraApp.log('error', `Passport authentication error: ${err.message}`);
      return next(err);
    }
  });
}