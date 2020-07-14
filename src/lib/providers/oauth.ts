import {PassportStatic} from "passport";
import AkeraWebAuthentication from "../AkeraWebAuthentication";
import {Router} from "express";
import {Strategy as GoogleStrategy} from "passport-google";
import {Strategy as FacebookStrategy} from "passport-facebook";
import {IOAuthProvider} from "../ProviderInterfaces";

const Strategies = {
  google: GoogleStrategy,
  facebook: FacebookStrategy,
}

export default function init(config: IOAuthProvider, router: Router, passport: PassportStatic, webAuth: AkeraWebAuthentication): void {
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

  const strategy = new Strategies[config.oauthStrategy](config, (accessToken, refreshToken, profile, done) => {
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