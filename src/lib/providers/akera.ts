import {Strategy as AkeraStrategy} from "@akeraio/passport";
import {PassportStatic} from "passport";
import {Router} from "express";

import AkeraWebAuthentication from "../AkeraWebAuthentication";
import {IAkeraProvider} from "../ProviderInterfaces";

/**
 * @akeraio/passport authentication strategy initialization function.
 *
 * @param config The configuration parameters used for the strategy.
 * @param router The router on which we attach the strategy.
 * @param passport The passport instance used for authentication.
 * @param webAuth The reference to the @akeraio/web-auth middleware.
 */
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