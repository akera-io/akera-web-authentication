module.exports = AkeraWebAuthentication;

var path = require('path');

function AkeraWebAuthentication(akeraWebApp, authConfig) {

  this.init = function(config, router) {
    var self = this;
    var passport = require('passport');

    if (!config || !(config.providers instanceof Array)
        || config.providers.length === 0)
      throw new Error('Invalid authentication service configuration.');

    if (!router || !router.__app || typeof router.__app.require !== 'function')
      throw new Error('Invalid akera application router.');

    var express = router.__app.require('express');
    var authRouter = express.Router({
      mergeParams : true
    });

    var akeraApp = router.__app;
    
    var authRoute = config.route || '/auth/';
    authRouter.__route = akeraApp.getRoute(authRoute, router);
    authRouter.__broker = router.__broker;
    authRouter.__app = akeraApp;

    config.successRedirect = config.successRedirect || router.__route;
    config.failureRedirect = config.failureRedirect || config.loginRedirect;
    config.loginRedirect = config.loginRedirect || config.failureRedirect;

    this.config = config;

    passport.serializeUser(function(user, cb) {
      cb(null, user.dn);
    });

    passport.deserializeUser(function(dn, cb) {
      cb(null, {
        dn : dn
      });
    });

    config.providers.forEach(function(provider) {
      provider.successRedirect = config.successRedirect;
      provider.failureRedirect = config.failureRedirect;

      self.useProvider(provider, authRouter, passport);
    });

    // initialize passport and session on akera's express app
    akeraApp.app.use(passport.initialize());
    akeraApp.app.use(passport.session());

    authRouter.use('/logout', this.logout);
    router.use(authRoute, authRouter);

    router.use('/', this.requireAuthentication);
  };

  this.requireAuthentication = function(req, res, next) {
    if (!req.session.user) {
      if (this.config.loginRedirect) {
        if (this.config.loginRedirect !== req.url) {
          res.redirect(this.config.loginRedirect);
          return;
        } else {
          return next();
        }
      }

      throw new Error('Not authenticated.');
    }

    next();

  };

  this.logout = function(req, res) {
    try {
      req.logout();
      delete req.session.user;
    } catch (e) {
    }

    var redirectUrl = this.config.logoutRedirect || this.config.loginRedirect
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
          : this.config.successRedirect;

      return res.redirect(successRedirect);
    }

    if (typeof next === 'function')
      next();
  };

  this.failureRedirect = function(req, res, next) {
    if (req && res && this.config && this.config.failureRedirect) {
      res.redirect(this.config.failureRedirect);
    }

    if (typeof next === 'function')
      next();
  };

  if (akeraWebApp !== undefined) {
    // mounted as application level service
    var AkeraWeb = null;

    try {
      AkeraWeb = akeraWebApp.require('akera-web');
    } catch (err) {
    }

    if (!AkeraWeb || !(akeraWebApp instanceof AkeraWeb))
      throw new Error('Invalid Akera web service instance');

    if (!authConfig || typeof authConfig !== 'object')
      authConfig = {};

    var express = akeraWebApp.require('express');

    var router = express.Router({
      mergeParams : true
    });

    var route = akeraWebApp.getRoute(authConfig.route);

    router.__route = akeraWebApp.getRoute(route, akeraWebApp.router);
    router.__app = akeraWebApp;

    this.init(authConfig, router);
    akeraWebApp.router.use(route, router);
  }

}

AkeraWebAuthentication.dependencies = function() {
  return [ 'akera-web-session' ];
};
