import {PassportStatic} from "passport";
import AkeraWebAuthentication from "../AkeraWebAuthentication";
import {Router} from "express";
import {IOAuthProvider} from "../ProviderInterfaces";

/**
 * OAuth authentication strategy initialization function.
 *
 * @param config The configuration parameters used for the strategy.
 * @param router The router on which we attach the strategy.
 * @param passport The passport instance used for authentication.
 * @param webAuth The reference to the @akeraio/web-auth middleware.
 */
export default async function init(config: IOAuthProvider, router: Router, passport: PassportStatic, webAuth: AkeraWebAuthentication): Promise<void> {
  if (!config || !config.oauthStrategy) {
    throw new Error("Invalid OAuth authentication configuration.");
  }

  const strategyName = config.name || "oauth";

  config.route = config.route || `${strategyName}/`;

  if (!(config.scope instanceof Array)) {
    config.scope = config.scope.split(" ");
  }

  if (config.profileAuth) {
    config.authCallback = config.profileAuth;
    if (typeof config.authCallback !== "function") {
      throw new Error("Invalid profile authorization function.");
    }
  }

  config.callbackURL = `${config.route}callback`;

  const StrategyModule = await import(config.oauthStrategy);
  const Strategy = StrategyModule.Strategy;

  const strategy = new Strategy(config, (accessToken, refreshToken, profile, done) => {
    if (config.authCallback) {
      config.authCallback(profile, (err, user) => done(err, user));
    } else {
      process.nextTick(() => done(null, profile));
    }
  });

  passport.use(strategyName, strategy);

  router.all(
    config.route,
    (req, res, next) => {
      passport.authenticate(strategyName, {
          scope: config.scope
        }
      )(req, res, next);
    });

  router.all(
    `${config.route}callback`,
    passport.authenticate(strategyName, {
      failureRedirect: config.failureRedirect
    }),
    (req, res, next) => {
      // successfull login
      webAuth.successRedirect(req, res, next);
    }
  );
}