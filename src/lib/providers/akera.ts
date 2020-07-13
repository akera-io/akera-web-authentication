import {Strategy as AkeraStrategy} from "@akeraio/passport";
import {PassportStatic} from "passport";
import {Router} from "express";

import AkeraWebAuthentication from "../AkeraWebAuthentication";
import {IBroker} from "@akeraio/api";

export interface IAkeraConfig {
  name?: string,
  route?: any,
  host?: string,
  port?: number,
  useSSL?: boolean,
  usernameField?: string,
  passwordField?: string,
  broker?: IBroker
}

export default async function init(config: IAkeraConfig, router: Router, passport: PassportStatic, webAuth: AkeraWebAuthentication): Promise<void> {
  // broker configuration required for api authentication
  let broker;
  let server;

  if (!config || !config.host || !config.port) {
    broker = await webAuth.getConnection();
  } else {
    server = {
      host: config.host,
      port: config.port,
      useSSL: config.useSSL || false
    };
  }

  const OPTS = {
    broker,
    server,
    usernameField: config.usernameField || "username",
    passwordField: config.passwordField || "password"
  };

  const strategy = new AkeraStrategy(OPTS, () => ({}));

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