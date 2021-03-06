const LdapStrategy = require('passport-ldapauth');
const fs = require('fs');

module.exports = init;

function loadCertificates(tlsOptions, akeraApp) {
  try {
    if (tlsOptions.ca) {
      if (typeof tlsOptions.ca === 'string')
        tlsOptions.ca = [fs.readFileSync(tlsOptions.ca)];
      else if (typeof tlsOptions.ca === 'object') {
        for (var key in tlsOptions.ca) {
          tlsOptions.ca[key] = fs.readFileSync(tlsOptions.ca[key]);
        }
      }
    }
  } catch (err) {
    akeraApp.log('warn', 'Ldap CA certificate load error: $1', err.message);
  }

  return tlsOptions;
}

function init(config, router, passport, webAuth) {

  if (!config || !config.url || !config.bindDn || !config.bindCredentials)
    throw new Error('LDAP configuration invalid.');

  const akeraApp = router.__app;
  const strategyName = config.name || strategy.name;

  let searchBase = config.searchBase;

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

  config.route = akeraApp.getRoute(config.route || '/ldap/');
  config.fullRoute = akeraApp.getRoute(config.route, router);

  const OPTS = {
    server: {
      url: config.url,
      bindDn: config.bindDn,
      bindCredentials: config.bindCredentials,
      searchBase: searchBase,
      searchFilter: config.searchFilter ||
        '(&(objectcategory=person)(objectclass=user)(|(samaccountname={{username}})(mail={{username}})))',
      reconnect: true,
      timeout: parseInt((config.timeout || 5))
    },
    usernameField: config.usernameField || 'username',
    passwordField: config.passwordField || 'password'
  };

  if (config.tlsOptions)
    OPTS.server.tlsOptions = loadCertificates(config.tlsOptions, akeraApp);

  const strategy = new LdapStrategy(OPTS);

  passport.use(strategyName, strategy);
  webAuth.addLocalStrategy(strategyName, OPTS);

  router.all(config.route, function (req, res, next) {
    try {
      passport.authenticate(strategyName, function (err, user) {
        if (!user)
          err = err || new Error('Invalid user credentials.');

        if (err) {
          akeraApp.log('warn', 'Ldap authentication error: ' + err.message);
          return next(err);
        }

        webAuth.successRedirect(req, res, next);
      })(req, res, next);
    } catch (err) {
      akeraApp.log('error', 'Passport authentication error: ' + err.message);
      return next(err);
    }
  });
}