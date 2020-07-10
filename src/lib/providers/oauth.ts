import {PassportStatic} from "passport";
import AkeraWebAuthentication from "../AkeraWebAuthentication";

type AuthCallback = (profile, cb: (err, user) => void) => void;

export interface IOAuthConfig {
  oauthStrategy: string,
  name?: string,
  scope?: string | Array<string>,
  route?: any,
  fullRoute?: any,
  authCallback?: AuthCallback,
  profileAuth: string,
  callbackURL: string,
  failureRedirect: string,
}

export default function init(config: IOAuthConfig, router, passport: PassportStatic, webAuth: AkeraWebAuthentication): void {
  if (!config || !config.oauthStrategy) {
    throw new Error("Invalid OAuth authentication configuration.");
  }

  const akeraApp = router.__app;
  const strategyName = config.name || "oauth";
  const Strategy = akeraApp.require(config.oauthStrategy).Strategy;

  config.route = akeraApp.getRoute(config.route || `/${strategyName}/`);
  config.fullRoute = akeraApp.getRoute(config.route, router);

  if (!(config.scope instanceof Array)) {
    config.scope = config.scope.split(" ");
  }

  if (config.profileAuth) {
    config.authCallback = akeraApp.require(config.profileAuth);
    if (typeof config.authCallback !== "function") {
      throw new Error("Invalid profile authorization function.");
    }
  }

  config.callbackURL = `${config.fullRoute}callback`;

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