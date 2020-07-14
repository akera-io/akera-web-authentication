export interface IProvider {
  name: string,
  strategy?: string,
  route?: string,
  fullRoute?: string,
  successRedirect?: string,
  failureRedirect?: string
}

export interface IAkeraProvider extends IProvider {
  host?: string,
  port?: number,
  useSSL?: boolean,
  usernameField?: string,
  passwordField?: string,
}

export interface IHTTPProvider extends IProvider {
  realm: string,
}

export interface ILDAPProvider extends IProvider {
  url: string,
  bindDn: string,
  bindCredentials: string,
  searchBase?: string,
  searchDomain: string,
  searchFilter?: string,
  timeout?: string,
  usernameField?: string,
  passwordField?: string,
  tlsOptions?: {
    ca?: string | Map<string, string | Buffer>
  }
}

export type AuthCallback = (profile, cb: (err, user) => void) => void;

export interface IOAuthProvider extends IProvider {
  oauthStrategy: string,
  scope?: string | Array<string>,
  authCallback?: AuthCallback,
  profileAuth?: AuthCallback,
  callbackURL: string,
  clientID?: string,
  clientSecret?: string,
}