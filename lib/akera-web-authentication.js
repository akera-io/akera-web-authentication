module.exports = AkeraWebAuthentication;

var path = require('path');

function AkeraWebAuthentication(akeraWebApp, authConfig) {
  var self = this;

  this.init = function(config, router) {
    if (!router || !router.__app || typeof router.__app.require !== 'function')
      throw new Error('Invalid Akera web service router.');

    var passport = require('passport');
    var akeraApp = router.__app;

    if (!config || !(config.providers instanceof Array)
      || config.providers.length === 0)
      throw new Error('Invalid authentication service configuration.');

    var express = akeraApp.require('express');
    var authRouter = express.Router({
      mergeParams : true
    });

    var authRoute = akeraApp.getRoute(config.route || '/auth/');
    authRouter.__route = akeraApp.getRoute(authRoute, router);
    authRouter.__broker = router.__broker;
    authRouter.__app = akeraApp;

    config.successRedirect = config.successRedirect || router.__route;
    config.failureRedirect = config.failureRedirect || config.loginRedirect;
    config.loginRedirect = config.loginRedirect || config.failureRedirect;

    this.config = config;

    passport.serializeUser(function(user, cb) {
      cb(null, user);
    });

    passport.deserializeUser(function(user, cb) {
      cb(null, user);
    });

    akeraApp.log('debug', 'Authentication route: ' + authRouter.__route);

    config.providers.forEach(function(provider) {
      provider.successRedirect = config.successRedirect;
      provider.failureRedirect = config.failureRedirect;

      var strategyName = provider.name || 'default';

      akeraApp.log('debug', 'Authentication provider: ' + provider.strategy
        + '[' + strategyName + ']');
      try {
        self.useProvider(provider, authRouter, passport);
      } catch (err) {
        akeraApp.log('error', err.message);
      }
    });

    // basic http auth
    if (config.basic !== undefined) {
      if (typeof config.basic !== 'object')
        config.basic = {};

      config.basic.strategy = 'http';

      self.useProvider(config.basic, router, passport);
    }

    // initialize passport and session on akera's express app
    akeraApp.app.use(passport.initialize());
    akeraApp.app.use(passport.session());

    authRouter.all('/logout', self.logout);

    router.use(authRoute, authRouter);
    router.use(self.requireAuthentication);
  };

  this.isAuthenticated = function(req) {
    return req && req.session && req.session.get('user');
  };

  this.requireAuthentication = function(req, res, next) {
    if (self.isAuthenticated(req))
      next();
    else {
      if (self.config.loginRedirect) {
        if (self.config.loginRedirect !== req.url) {
          res.redirect(self.config.loginRedirect);
        } else {
          next();
        }
        return;
      }

      throw new Error('Not authenticated.');
    }
  };

  this.logout = function(req, res) {
    try {
      req.logout();
      req.session.set('user');
    } catch (e) {}

    var redirectUrl = self.config.logoutRedirect || self.config.loginRedirect
      || '/';

    res.redirect(redirectUrl);

  };

  this.useProvider = function(provider, router, passport) {
    if (!provider.strategy)
      throw new Error('Authentication provider strategy not set.');

    var strategy = null;

    try {
      strategy = require(path.join(__dirname, 'providers', provider.strategy
        .toLowerCase()));
    } catch (e) {
      throw new Error('Authentication provider not found for: '
        + provider.strategy);
    }

    try {
      strategy(provider, router, passport, this);
    } catch (e) {
      throw new Error('Authentication provider initialization error for: '
        + provider.strategy);
    }
  };

  this.successRedirect = function(req, res, next) {

    if (res) {
      var successRedirect = (req && req.session && req.session.authOriginalUrl) ? req.session.authOriginalUrl
        : self.config.successRedirect;

      return res.redirect(successRedirect);
    }

    if (typeof next === 'function')
      next();
  };

  this.failureRedirect = function(req, res, next) {
    if (req && res && self.config && self.config.failureRedirect) {
      res.redirect(self.config.failureRedirect);
    }

    if (typeof next === 'function')
      next();
  };

  this.getUrl = function(req) {
    return req.protocol + '://' + req.get('host') + req.url;
  }

  this.setUser = function(req, user) {
    if (req && user && req.session) {
      if (typeof req.session.set === 'function')
        req.session.set('user', user);
      else
        req.session.user = user;
    }
  }

  this.addLocalStrategy = function(name, options) {
    self.strategies = self.strategies || [];

    var found = self.strategies.filter(function(strategy) {
      return strategy.name === name;
    });

    if (!found || found.length === 0) {
      self.strategies.push({
        name : name,
        options : options
      });
    }
  }

  this.getLocalStrategies = function() {
    return self.strategies;
  }

  if (akeraWebApp !== undefined) {
    // mounted as application level service
    var AkeraWeb = null;

    try {
      AkeraWeb = akeraWebApp.require('akera-web');
    } catch (err) {}

    if (!AkeraWeb || !(akeraWebApp instanceof AkeraWeb))
      throw new Error('Invalid Akera web service instance.');

    if (!authConfig || typeof authConfig !== 'object')
      throw new Error('Invalid authentication configuration.');

    this.init(authConfig, akeraWebApp.router);

  }

}

AkeraWebAuthentication.init = function(config, router) {
  var akeraWebAuth = new AkeraWebAuthentication();
  akeraWebAuth.init(config, router);
}

AkeraWebAuthentication.dependencies = function() {
  return [ 'akera-web-session' ];
};
