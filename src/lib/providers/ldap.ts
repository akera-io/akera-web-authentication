import * as fs from "fs";
import {PassportStatic} from "passport";
import LDAPStrategy from "passport-ldapauth";
import {Router} from "express";
import {LogLevel} from "@akeraio/net";

import AkeraWebAuthentication from "../AkeraWebAuthentication";
import {ILDAPProvider} from "../ProviderInterfaces";

/**
 * Function to load the certificates defined in TLSOptions.
 *
 * @param tlsOptions The options used for TLS/SSL configuration.
 * @param webAuth A reference to the @akeraio/web-auth middleware.
 */
function loadCertificates(tlsOptions, webAuth: AkeraWebAuthentication) {
  try {
    if (tlsOptions.ca) {
      if (typeof tlsOptions.ca === "string")
        tlsOptions.ca = [fs.readFileSync(tlsOptions.ca)];
      else if (typeof tlsOptions.ca === "object") {
        for (const key of Object.keys(tlsOptions.ca)) {
          tlsOptions.ca[key] = fs.readFileSync(tlsOptions.ca[key]);
        }
      }
    }
  } catch (err) {
    webAuth.log(LogLevel.warn, `LDAP CA certificate load error: ${err.message}`);
  }

  return tlsOptions;
}

/**
 * passport-ldap authentication strategy initialization function.
 *
 * @param config The configuration parameters used for the strategy.
 * @param router The router on which we attach the strategy.
 * @param passport The passport instance used for authentication.
 * @param webAuth The reference to the @akeraio/web-auth middleware.
 */
export default function init(config: ILDAPProvider, router: Router, passport: PassportStatic, webAuth: AkeraWebAuthentication): void {
  if (!config || !config.url || !config.bindDn || !config.bindCredentials) {
    throw new Error("LDAP configuration invalid.");
  }

  let searchBase = config.searchBase;

  if (!searchBase) {
    if (config.searchDomain) {
      searchBase = config.searchDomain
        .split(".")
        .reduce((prev, current) => `${prev}${prev !== "" ? "," : ""}DC=${current}`, "");
    } else {
      throw new Error('LDAP search base or domain need to be set.');
    }
  }

  const OPTS = {
    server: {
      url: config.url,
      bindDn: config.bindDn,
      bindCredentials: config.bindCredentials,
      searchBase: searchBase,
      searchFilter: config.searchFilter ||
        "(&(objectcategory=person)(objectclass=user)(|(samaccountname={{username}})(mail={{username}})))",
      reconnect: true,
      timeout: parseInt(config.timeout || "5"),
      tlsOptions: {},
    },
    usernameField: config.usernameField || "username",
    passwordField: config.passwordField || "password"
  };

  if (config.tlsOptions) {
    OPTS.server.tlsOptions = loadCertificates(config.tlsOptions, webAuth);
  }

  const strategy = new LDAPStrategy(OPTS);
  const strategyName = config.name || strategy.name;

  passport.use(strategyName, strategy);
  webAuth.addLocalStrategy(strategyName, OPTS);

  router.all(config.route, function (req, res, next) {
    try {
      passport.authenticate(strategyName, function (err, user) {
        if (!user) {
          err = err || new Error("Invalid user credentials.");
        }

        if (err) {
          webAuth.log(LogLevel.warn, `LDAP authentication error: ${err.message}`);
          return next(err);
        }

        webAuth.successRedirect(req, res, next);
      })(req, res, next);
    } catch (err) {
      webAuth.log(LogLevel.error, `Passport authentication error: ${err.message}`);
      return next(err);
    }
  });
}