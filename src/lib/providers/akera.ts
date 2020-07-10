import {Strategy as AkeraStrategy} from "@akeraio/passport";
import {PassportStatic} from "passport";

import AkeraWebAuthentication from "../AkeraWebAuthentication";

export interface IAkeraConfig {
  name?: string,
  route?: any,
  fullRoute?: any,
  host?: string,
  port?: number | string,
  useSSL?: boolean,
  usernameField?: string,
  passwordField?: string,
}

export default function init(config: IAkeraConfig, router, passport: PassportStatic, webAuth: AkeraWebAuthentication): void {
  // broker configuration required for api authentication
  if (!config || !config.host || !config.port) {
    // if service mounted on broker get configuration from it
    if (router.__broker) {
      config = config || {};
      config.host = config.host || router.__broker.host;
      config.port = config.port || router.__broker.port;
      config.useSSL = config.useSSL || router.__broker.useSSL;
    } else
      throw new Error("Invalid Akera authentication configuration.");
  }

  const akeraApp = router.__app;

  config.route = akeraApp.getRoute(config.route || "/akera/");
  config.fullRoute = akeraApp.getRoute(config.route, router);

  const OPTS = {
    server: {
      host: config.host,
      port: config.port,
      useSSL: config.useSSL || false
    },
    usernameField: config.usernameField || "username",
    passwordField: config.passwordField || "password"
  };

  const strategy = new AkeraStrategy(OPTS);
  const strategyName = config.name || strategy.name;
  passport.use(strategyName, strategy);
  webAuth.addLocalStrategy(strategyName, OPTS);

  router.all(config.route, function (req, res, next) {
    passport.authenticate(strategyName, function (err, user, info) {
      if (err)
        return next(err);
      if (!user)
        return next(info || new Error("Invalid credentials."));

      webAuth.successRedirect(req, res, next);
    })(req, res, next);
  });
}