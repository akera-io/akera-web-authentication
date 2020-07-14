import {Express, NextFunction, Request, Response, Router} from "express";
import passport, {PassportStatic} from "passport";
import {WebMiddleware, IWebMiddleware} from "@akeraio/web-middleware";
import {ConnectionPool, ConnectionPoolOptions, LogLevel} from "@akeraio/api";

import Strategies from "./providers";
import {IProvider} from "./ProviderInterfaces";

/**
 * Configuration parameters used by the @akeraio/web-authentication middleware.
 */
export interface IAkeraWebConfig {
  /**
   * The route where the middleware will be mounted.
   */
  route?: string,
  /**
   * The full path of the route where the middleware will be mounted.
   */
  fullRoute?: string,
  /**
   * Path used to redirect the user after logout.
   */
  logoutRedirect?: string,
  /**
   * Path used to redirect the user after login.
   */
  loginRedirect?: string,
  /**
   * Path used to redirect the user after a successful authentication.
   */
  successRedirect?: string,
  /**
   * Path used to redirect the user after a failed authentication.
   */
  failureRedirect?: string,
  /**
   * A list with providers that will be registered into the application.
   */
  providers?: Array<IProvider>,
  /**
   * Basic authentication provider configuration.
   */
  basic?: IProvider
}

/**
 * Strategy definition interface. Use this interface when you
 * want to register a new strategy into the authentication middleware.
 */
export interface IStrategy {
  /**
   * The name of the strategy.
   */
  name: string,
  /**
   * Options passed to the strategy.
   */
  options: any
}

/**
 * Logger function that can be called from the AkeraWebAuthentication middleware.
 *
 * @param level The level of the message.
 * @param message The message to be logged.
 */
type LoggerFunction = (level: LogLevel, message: string) => void;

/**
 * Middleware class that provides an authentication system for the akera web package.
 */
export default class AkeraWebAuthentication extends WebMiddleware implements IWebMiddleware {
  /**
   * A list with strategies loaded into the system.
   */
  private _strategies: Array<IStrategy>;

  /**
   * The router exposed by this middleware.
   */
  private _router: Router;

  /**
   * The passport instance used by the Web Authentication middleware.
   */
  private _passport: PassportStatic;

  /**
   * The configuration used by this middleware.
   */
  private _config: IAkeraWebConfig;

  /**
   * An akera server connection pool that can be used to connect to the backend.
   */
  private _connectionPool: ConnectionPool;

  /**
   * The logger wrapper. Based on what configuration parameters are used
   * this function can be taken either from ConnectionPool or from the
   * ConnectionPoolOptions.
   */
  private _logger: LoggerFunction;

  /**
   * The list of dependencies on other akera.io web middleware
   * modules that needs to be loaded/mounted before.
   *
   * The middleware has no responsability to load the dependencies
   * by itself.
   */
  getDependencies(): Array<string> {
    return ["@akeraio/web-session"]
  }

  /**
   * Returns the logger function to be used where logging is required.
   */
  get log(): LoggerFunction {
    return this._logger;
  }

  /**
   * @akeraio/web-authentication middleware constructor.
   *
   * @throws Error
   *
   * @param [config] The configuration used by this middleware.
   */
  public constructor(config?: IAkeraWebConfig) {
    super();
    this._config = config;

    if (!this._config || !(this._config.providers instanceof Array) || this._config.providers.length === 0) {
      throw new Error("Invalid authentication service configuration.");
    }
  }

  /**
   * Mount the middleware using the connection information provided
   * and return an [Express](https://expressjs.com) Router.
   *
   * @param config The connection information, can be either a single
   *               or multiple brokers if middleware is to be mounted
   *               at application level.
   */
  public mount(config: ConnectionPoolOptions | ConnectionPool): Router {
    if (this._router) {
      return this._router;
    }

    this._router = Router({
      mergeParams: true
    });

    if (!this._passport) {
      this._passport = passport;
    }

    if (config instanceof ConnectionPool) {
      this._logger = (level: LogLevel, message: string) => config.log(message, level);
    } else if ("logger" in config) {
      this._logger = config.logger.log;
    } else {
      this._logger = () => ({});
    }

    this.initConnectionPool(config);

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

      this.log(LogLevel.info, `Authentication provider: ${provider.strategy} [${strategyName}]`);
      try {
        this.useProvider(provider, this._router, this._passport);
        provider.fullRoute = provider.route;
      } catch (err) {
        this.log(LogLevel.error, err.message);
      }
    }

    // basic http auth
    if (this._config.basic !== undefined) {
      if (typeof this._config.basic !== "object") {
        this._config.basic = {
          name: "basic",
          strategy: "http"
        };
      }

      this._config.basic.strategy = "http";
      this.useProvider(this._config.basic, this._router, this._passport);
    }

    this._router.all("/logout", this.logout);
    this._router.use(this.requireAuthentication);
    return this._router;
  }

  /**
   * Initializes the passport middleware application wide.
   *
   * @param app A reference to the express application.
   */
  public initPassport(app: Express): void {
    app.use(this._passport.initialize());
    app.use(this._passport.session());
  }

  /**
   * Returns the passport instance.
   */
  public get passport(): PassportStatic {
    return this._passport;
  }

  /**
   * Checks if the request is authenticated or not.
   *
   * @param req The request object.
   */
  public isAuthenticated(req: Request): boolean {
    return req && req.session && !!(req.session.user || req.session.get('user'));
  }

  /**
   * Forces the request to be authenticated.
   *
   * @param req The request object.
   * @param res The response object.
   * @param next A reference to the next function that will be called.
   */
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

  /**
   * Logs the user out of the application and redirects him to the
   * configured page (logoutRedirect, loginRedirect or "/").
   *
   * @param req The request object.
   * @param res The response object.
   */
  public logout(req: Request, res: Response): void {
    try {
      req.logout();
      req.session.set("user");
    } catch {
      // NOP
    }

    res.redirect(this._config.logoutRedirect || this._config.loginRedirect || '/');
  }

  /**
   * Registers a strategy provider that can be used in the application to authenticate
   * users.
   *
   * @param provider The provider configuration.
   * @param router The router on which we mount the provider.
   * @param passport The passport instance.
   */
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

  /**
   * Successful Authentication redirect route middleware.
   *
   * @param req The request object.
   * @param res The response object.
   * @param next A reference to the next function that will be called.
   */
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

  /**
   * Failed Authentication redirect route middleware.
   *
   * @param req The request object.
   * @param res The response object.
   * @param next A reference to the next function that will be called.
   */
  public failureRedirect(req: Request, res: Response, next?: NextFunction): void {
    if (req && res && this._config && this._config.failureRedirect) {
      res.redirect(this._config.failureRedirect);
      return;
    }

    if (typeof next === 'function') {
      next();
    }
  }

  /**
   * Returns the full URL of the request.
   *
   * @param req The request object.
   */
  public getUrl(req: Request): string {
    return `${req.protocol}://${req.get('host')}${req.originalUrl}`;
  }

  /**
   * Sets the user onto the session.
   *
   * @param req The request object.
   * @param user The user that will be set onto the session.
   */
  public setUser(req: Request, user: any): void {
    if (req && user && req.session) {
      if (typeof req.session.set === 'function') {
        req.session.set('user', user);
      } else {
        req.session.user = user;
      }
    }
  }

  /**
   * Adds a strategy to the list of loaded authentication strategies.
   *
   * @param name The name of the strategy.
   * @param options The options used to register the strategy.
   */
  public addLocalStrategy(name: string, options: any): void {
    this._strategies = this._strategies || [];

    const found = this._strategies.filter(function (strategy) {
      return strategy.name === name;
    });

    if (!found || found.length === 0) {
      this._strategies.push({
        name,
        options
      });
    }
  }

  /**
   * Returns the loaded strategies.
   */
  public getLocalStrategies(): Array<IStrategy> {
    return this._strategies;
  }

  /**
   * Initializes the backend broker connection pool available in the middleware.
   *
   * @param brokerConfig The ConnectionPoolOptions object or the actual ConnectionPool.
   */
  private initConnectionPool(brokerConfig: ConnectionPoolOptions | ConnectionPool): void {
    if (brokerConfig instanceof ConnectionPool) {
      this._connectionPool = brokerConfig;
      return;
    }

    this._connectionPool = new ConnectionPool(brokerConfig);
  }
}