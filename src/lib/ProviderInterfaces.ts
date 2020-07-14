/**
 * The base configuration properties available for each
 * authentication provider used by the @akeraio/web-auth middleware.
 */
export interface IProvider {
  /**
   * The name of the provider.
   */
  name: string,
  /**
   * The name of the strategy.
   */
  strategy: string,
  /**
   * The route where the provider will be mounted.
   */
  route?: string,
  /**
   * The full route path where the provider will be mounted.
   */
  fullRoute?: string,
  /**
   * Where to redirect the user after a successful authentication.
   */
  successRedirect?: string,
  /**
   * Where to redirect the user after a failure authentication.
   */
  failureRedirect?: string
}

/**
 * Specific configuration for @akeraio/passport provider.
 */
export interface IAkeraProvider extends IProvider {
  /**
   * The address of the akera.io server.
   */
  host?: string,
  /**
   * The port of the akera.io server.
   */
  port?: number,
  /**
   * Should the connection use SSL.
   */
  useSSL?: boolean,
  /**
   * The field from the request body or query where the username is stored.
   */
  usernameField?: string,
  /**
   * The field from the request body or query where the password is stored.
   */
  passwordField?: string,
}

/**
 * Specific configuration for passport-http provider.
 */
export interface IHTTPProvider extends IProvider {
  /**
   * The authentication realm provided by the HTTP provider.
   */
  realm: string,
}

/**
 * Specific configuration for passport-ldap provider.
 */
export interface ILDAPProvider extends IProvider {
  /**
   * The URL used to connect to the LDAP server.
   */
  url: string,
  /**
   * The bindDN string used to connect to the LDAP server.
   */
  bindDn: string,
  /**
   * The credentials used to login into the LDAP server.
   */
  bindCredentials: string,
  /**
   * The search base used to lookup after user in the LDAP server.
   */
  searchBase?: string,
  /**
   * The domain used to lookup after user in the LDAP server.
   */
  searchDomain?: string,
  /**
   * The search filter used to lookup after user in the LDAP server.
   */
  searchFilter?: string,
  /**
   * After how many seconds should the connection timeout.
   */
  timeout?: string,
  /**
   * The field from the request body or query where the username is stored.
   */
  usernameField?: string,
  /**
   * The field from the request body or query where the password is stored.
   */
  passwordField?: string,
  /**
   * TLS/SSL Connection options
   */
  tlsOptions?: {
    /**
     * The certificate that will be used for SSL/TLS Connection
     */
    ca?: string | Map<string, string | Buffer>
  }
}

/**
 * Callback function used for user authentication when using OAuth providers.
 *
 * @param profile Profile information.
 * @param cb Callback to send the information back.
 */
export type AuthCallback = (profile, cb: (err, user) => void) => void;

/**
 * Specific configuration for passport OAuth providers.
 */
export interface IOAuthProvider extends IProvider {
  /**
   * The name of the OAuth Strategy.
   */
  oauthStrategy: string,
  /**
   * The OAuth authorization scope list.
   */
  scope?: string | Array<string>,
  /**
   * The callback function used for authorization.
   */
  authCallback?: AuthCallback,
  /**
   * The callback function used to fetch profile information.
   */
  profileAuth?: AuthCallback,
  /**
   * The URL send as CallbackURL to the OAuth provider.
   */
  callbackURL: string,
  /**
   * The ClientID used to authenticate the OAuth request.
   */
  clientID?: string,
  /**
   * The Client Secret used to authenticate the OAuth request.
   */
  clientSecret?: string,
}