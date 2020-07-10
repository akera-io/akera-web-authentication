import path from "path";

export default class AkeraWebAuthentication {
  private strategies: Array<any>;
  private config: any;
  private akeraApp: any;

  static dependencies() {
    return ["@akeraio/web-session"]
  }

  static init(config, router): AkeraWebAuthentication {
    const instance = new AkeraWebAuthentication();
    instance.initService(config, router);

    return instance;
  }

  public constructor(akeraWebApp?, authConfig?) {
    if (akeraWebApp !== undefined) {
      // mounted as application level service
      let AkeraWeb = null;

      try {
        AkeraWeb = akeraWebApp.require('@akeraio/web');
      } catch {
        // NOP
      }

      if (!AkeraWeb || !(akeraWebApp instanceof AkeraWeb)) {
        throw new Error("Invalid Akera web service instance.");
      }

      if (!authConfig || typeof authConfig !== 'object') {
        throw new Error("Invalid authentication configuration.");
      }

      this.initService(authConfig, akeraWebApp.router);
    }
  }

  public initService(config, router) {
    if (!router || !router.__app || typeof router.__app.require !== "function") {
      throw new Error("Invalid Akera web service router.");
    }

    const akeraApp = router.__app;

    if (!config || !(config.providers instanceof Array) || config.providers.length === 0) {
      throw new Error('Invalid authentication service configuration.');
    }

    const passport = akeraApp.require("passport");
    const express = akeraApp.require("express");
    const authRouter = express.Router({
      mergeParams: true
    });

    const authRoute = akeraApp.getRoute(config.route || '/auth/');
    authRouter.__route = akeraApp.getRoute(authRoute, router);
    authRouter.__broker = router.__broker;
    authRouter.__app = akeraApp;

    config.successRedirect = config.successRedirect || router.__route;
    config.failureRedirect = config.failureRedirect || config.loginRedirect;
    config.loginRedirect = config.loginRedirect || config.failureRedirect;

    this.config = config;
    this.akeraApp = akeraApp;

    passport.serializeUser((user, cb) => {
      cb(null, user);
    });

    passport.deserializeUser((user, cb) => {
      cb(null, user);
    });

    akeraApp.log('debug', 'Authentication route: ' + authRouter.__route);

    config.providers.forEach((provider) => {
      provider.successRedirect = config.successRedirect;
      provider.failureRedirect = config.failureRedirect;

      const strategyName = provider.name || provider.strategy;

      akeraApp.log('info', `Authentication provider: ${provider.strategy} [${strategyName}]`);
      try {
        this.useProvider(provider, authRouter, passport);
      } catch (err) {
        akeraApp.log('error', err.message);
      }
    });

    // basic http auth
    if (config.basic !== undefined) {
      if (typeof config.basic !== 'object') {
        config.basic = {};
      }

      config.basic.strategy = 'http';

      this.useProvider(config.basic, router, passport);
    }

    // initialize passport and session on akera's express app
    akeraApp.app.use(passport.initialize());
    akeraApp.app.use(passport.session());

    authRouter.all('/logout', this.logout);

    router.use(authRoute, authRouter);
    router.use(this.requireAuthentication);
  }

  isAuthenticated(req) {
    return req && req.session && !!(req.session.user || req.session.get('user'));
  }

  requireAuthentication(req, res, next) {
    if (this.isAuthenticated(req))
      next();
    else {
      let loginRedirect = this.config.loginRedirect;

      if (!loginRedirect && this.config.providers.length === 1) {
        loginRedirect = this.config.providers[0].fullRoute;
      }

      if (loginRedirect) {
        if (loginRedirect !== req.originalUrl) {
          if (req.session)
            req.session.authOriginalUrl = req.originalUrl;
          res.redirect(loginRedirect);
        } else {
          next();
        }
        return;
      }

      throw new Error('Not authenticated.');
    }
  }

  logout(req, res) {
    try {
      req.logout();
      req.session.set('user');
    } catch {
      // NOP
    }

    const logoutRedirect = this.config.logoutRedirect || this.config.loginRedirect || '/';
    res.redirect(logoutRedirect);
  }

  useProvider(provider, router, passport) {
    if (!provider.strategy)
      throw new Error('Authentication provider strategy not set.');

    let strategy = null;

    try {
      strategy = require(path.join(__dirname, 'providers', provider.strategy.toLowerCase()));
    } catch (e) {
      throw new Error(`Authentication provider not found for: ${provider.strategy}`);
    }

    try {
      strategy(provider, router, passport, this);
    } catch (e) {
      throw new Error(`Authentication provider initialization error for: ${provider.strategy}`);
    }
  }

  successRedirect(req, res, next) {
    this.setUser(req, req.user);

    if (res) {
      const successRedirect = (req && req.session && req.session.authOriginalUrl) ? req.session.authOriginalUrl
        : this.config.successRedirect;

      return res.redirect(successRedirect);
    }

    if (typeof next === 'function') {
      next();
    }
  }

  failureRedirect(req, res, next) {
    if (req && res && this.config && this.config.failureRedirect) {
      res.redirect(this.config.failureRedirect);
    }

    if (typeof next === 'function') {
      next();
    }
  }

  getUrl(req) {
    return `${req.protocol}://${req.get('host')}${req.originalUrl}`;
  }

  setUser(req, user) {
    if (req && user && req.session) {
      if (typeof req.session.set === 'function') {
        req.session.set('user', user);
      } else {
        req.session.user = user;
      }
    }
  }

  addLocalStrategy(name, options) {
    this.strategies = this.strategies || [];

    const found = this.strategies.filter(function (strategy) {
      return strategy.name === name;
    });

    if (!found || found.length === 0) {
      this.strategies.push({
        name: name,
        options: options
      });
    }
  }

  getLocalStrategies() {
    return this.strategies;
  }
}