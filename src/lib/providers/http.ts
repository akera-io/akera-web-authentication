import {BasicStrategy} from "passport-http";
import {PassportStatic} from "passport";
import AkeraWebAuthentication from "../AkeraWebAuthentication";
import {Router} from "express";

export interface IHTTPConfig {
  name?: string,
  route?: any,
  fullRoute?: any,
  realm: string,
}

export default function init(config: IHTTPConfig, router: Router, passport: PassportStatic, webAuth: AkeraWebAuthentication): void {
  // basic authentication
  const strategy = new BasicStrategy(
    {
      passReqToCallback: true,
      realm: config.realm
    },
    async (req, username, password, verified) => {
      // we have user and password, try to authenticate with that using all
      // strategies
      const strategies = webAuth.getLocalStrategies();

      if (!strategies || strategies.length == 0) {
        verified();
        return;
      }

      if (webAuth.isAuthenticated(req)) {
        verified();
        return;
      }

      for (const strategy of strategies) {
        if (req.body !== undefined) {
          req.body[strategy.options.usernameField] = username;
          req.body[strategy.options.passwordField] = password;
        } else {
          req.query[strategy.options.usernameField] = username;
          req.query[strategy.options.passwordField] = password;
        }

        const response = await (new Promise((resolve) => {
          passport.authenticate(strategy.name, (err, user) => {
            if (!err && user) {
              webAuth.setUser(req, user);
            }

            resolve(!err);
          })(req);
        }));

        if (req.body !== undefined) {
          delete req.body[strategy.options.usernameField];
          delete req.body[strategy.options.passwordField];
        } else {
          delete req.query[strategy.options.usernameField];
          delete req.query[strategy.options.passwordField];
        }

        if (response) {
          verified();
          return;
        }
      }
    }
  );

  passport.use(strategy);

  router.use(function (req, res, next) {
    passport.authenticate(strategy.name, function () {
      // noop
      return next && next();
    })(req, res, next);
  });
}