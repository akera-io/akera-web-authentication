import {Express, NextFunction, Request, Response, Router} from "express";
import passport, {PassportStatic} from "passport";
import {WebMiddleware} from "@akeraio/web-middleware";
import {AkeraLogger, ConnectionPool, ConnectionPoolOptions, LogLevel} from "@akeraio/api";

import Strategies from "./providers";
import {IProvider} from "./ProviderInterfaces";

export interface IAkeraWebConfig {
  route?: string,
  fullRoute?: string,
  logoutRedirect?: string,
  loginRedirect?: string,
  successRedirect?: string,
  failureRedirect?: string,
  providers?: Array<IProvider>,
  basic?: IProvider
}

export interface IStrategy {
  name: string,
  options: any
}

export default class AkeraWebAuthentication extends WebMiddleware {
  private strategies: Array<IStrategy>;

  private _router: Router;
  private _passport: PassportStatic;
  private _config: IAkeraWebConfig;
  private _connectionPool: ConnectionPool;
  private _logger: AkeraLogger;

  get dependencies(): Array<string> {
    return ["@akeraio/web-session"]
  }

  get logger(): AkeraLogger {
    return this._logger;
  }

  public constructor(config?: IAkeraWebConfig) {
    super();
    this._config = config;
    this._logger = new AkeraLogger(() => ({}));

    if (!this._config || !(this._config.providers instanceof Array) || this._config.providers.length === 0) {
      throw new Error("Invalid authentication service configuration.");
    }
  }

  public mount(brokerConfig: ConnectionPoolOptions | ConnectionPool, logger?: AkeraLogger): Router {
    if (this._router) {
      return this._router;
    }

    this._router = Router({
      mergeParams: true
    });

    if (!this._passport) {
      this._passport = passport;
    }

    if (logger) {
      this._logger = logger;
    }

    this.initConnectionPool(brokerConfig);

    this._passport.serializeUser((user, cb) => {
      cb(null, user);
    });

    this._passport.deserializeUser((user, cb) => {
      cb(null, user);
    });

    this._config.successRedirect = this._config.successRedirect || "";
    this._config.failureRedirect = this._config.failureRedirect || this._config.loginRedirect;
    this._config.loginRedirect = this._config.loginRedirect || this._config.failureRedirect;

    for (const provider of this._config.providers) {
      provider.successRedirect = this._config.successRedirect;
      provider.failureRedirect = this._config.failureRedirect;

      const strategyName = provider.name || provider.strategy;

      this._logger.log(LogLevel.info, `Authentication provider: ${provider.strategy} [${strategyName}]`);
      try {
        this.useProvider(provider, this._router, this._passport);
        provider.fullRoute = provider.route;
      } catch (err) {
        this._logger.log(LogLevel.error, err.message);
      }
    }

    // basic http auth
    if (this._config.basic !== undefined) {
      if (typeof this._config.basic !== "object") {
        this._config.basic = {
          name: "basic"
        };
      }

      this._config.basic.strategy = "http";
      this.useProvider(this._config.basic, this._router, this._passport);
    }

    this._router.all("/logout", this.logout);
    this._router.use(this.requireAuthentication);
    return this._router;
  }

  public initPassport(app: Express): void {
    app.use(this._passport.initialize());
    app.use(this._passport.session());
  }

  public get passport(): PassportStatic {
    return this._passport;
  }

  public isAuthenticated(req: Request): boolean {
    return req && req.session && !!(req.session.user || req.session.get('user'));
  }

  public requireAuthentication(req: Request, res: Response, next: NextFunction): void {
    if (this.isAuthenticated(req)) {
      next();
      return;
    }

    let loginRedirect = this._config.loginRedirect;
    if (!loginRedirect && this._config.providers.length === 1) {
      loginRedirect = this._config.providers[0].fullRoute;
    }

    if (!loginRedirect) {
      throw new Error("Not authenticated.");
    }

    if (loginRedirect === req.originalUrl) {
      next();
      return;
    }

    if (req.session) {
      req.session.authOriginalUrl = req.originalUrl;
    }
    res.redirect(loginRedirect);
  }

  public logout(req: Request, res: Response): void {
    try {
      req.logout();
      req.session.set("user");
    } catch {
      // NOP
    }

    res.redirect(this._config.logoutRedirect || this._config.loginRedirect || '/');
  }

  public useProvider(provider: IProvider, router: Router, passport: PassportStatic): void {
    if (!provider.strategy) {
      throw new Error("Authentication provider strategy not set.");
    }

    if (Object.keys(Strategies).indexOf(provider.strategy.toLowerCase()) < 0) {
      throw new Error(`Authentication provider not found for: ${provider.strategy}`);
    }

    try {
      const strategy = Strategies[provider.strategy.toLowerCase()];
      strategy(provider, router, passport, this);
    } catch (e) {
      throw new Error(`Authentication provider initialization error for: ${provider.strategy}`);
    }
  }

  public successRedirect(req: Request, res: Response, next: NextFunction): void {
    this.setUser(req, req.user);

    if (res) {
      const successRedirect = (req && req.session && req.session.authOriginalUrl)
        ? req.session.authOriginalUrl
        : this._config.successRedirect;

      return res.redirect(successRedirect);
    }

    if (typeof next === 'function') {
      next();
    }
  }

  public failureRedirect(req: Request, res: Response, next?: NextFunction): void {
    if (req && res && this._config && this._config.failureRedirect) {
      res.redirect(this._config.failureRedirect);
      return;
    }

    if (typeof next === 'function') {
      next();
    }
  }

  public getUrl(req: Request): string {
    return `${req.protocol}://${req.get('host')}${req.originalUrl}`;
  }

  public setUser(req: Request, user: any): void {
    if (req && user && req.session) {
      if (typeof req.session.set === 'function') {
        req.session.set('user', user);
      } else {
        req.session.user = user;
      }
    }
  }

  public addLocalStrategy(name: string, options: any): void {
    this.strategies = this.strategies || [];

    const found = this.strategies.filter(function (strategy) {
      return strategy.name === name;
    });

    if (!found || found.length === 0) {
      this.strategies.push({
        name,
        options
      });
    }
  }

  public getLocalStrategies(): Array<IStrategy> {
    return this.strategies;
  }

  private initConnectionPool(brokerConfig: ConnectionPoolOptions | ConnectionPool): void {
    if (brokerConfig instanceof ConnectionPool) {
      this._connectionPool = brokerConfig;
      return;
    }

    this._connectionPool = new ConnectionPool(brokerConfig);
  }
}