import {Strategy as AkeraStrategy} from "@akeraio/passport";
import {PassportStatic} from "passport";
import {Router} from "express";

import AkeraWebAuthentication from "../AkeraWebAuthentication";
import {IAkeraProvider} from "../ProviderInterfaces";

export default async function init(config: IAkeraProvider, router: Router, passport: PassportStatic, webAuth: AkeraWebAuthentication): Promise<void> {
  if (!config || !config.host || !config.port) {
    throw new Error("Invalid Akera authentication configuration.");
  }
  const options = {
    server: {
      host: config.host,
      port: config.port,
      useSSL: config.useSSL || false
    },
    usernameField: config.usernameField || "username",
    passwordField: config.passwordField || "password"
  }

  const strategy = new AkeraStrategy(options, () => ({}));

  const strategyName = config.name || strategy.name;
  passport.use(strategyName, strategy);
  webAuth.addLocalStrategy(strategyName, options);

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