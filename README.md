[![Akera Logo](http://akera.io/logo.png)](http://akera.io/)

  Authentication module for Akera.io web service.

## Installation

```bash
$ npm install @akeraio/web-authentication
```

## Docs

  * [Website and Documentation](http://akera.io/)


## Quick Start

  This module is designed to be loaded as application level service which 
  is usually done by adding a reference to it in `services` section of 
  application's configuration.
   
  ```json
{
  "services": [
		{ 
			"middleware": "@akeraio/web-authentication",
			"config": {
				"route": "/authenticate/",
				"loginRedirect": "/login.html",
				"successRedirect": "/",
				"failureRedirect": "/autherr.html",
				"providers": [
					{ 
						"strategy": "ldap",
					  	"url": "ldap://localhost:389",
						"bindDn": "ldapUser",
						"bindCredentials": "passwd",
						"searchBase": "CN=Users,DC=yourdomain,DC=com"
					},
					{ 
						"strategy": "akera",
						"route": "/server/",
					  	"host": "localhost",
						"port": 8383
					},
					{ 
						"strategy": "facebook",
					  	"clientID": "ID",
						"clientSecret": "secret"
					},
					{ 
						"strategy": "google",
					  	"clientID": "ID",
						"clientSecret": "secret"
					}
				]
			}
		}
	]
}
  ```
  
  Service options available:
  - `route`: the route where the service is going to be mounted (default: '/auth/')
  - `loginRedirect`: the login page where user will get redirected if session not authenticated
  - `successRedirect`: the page where user will get redirected when authenticated
  - `failureRedirect`: the page where user will get redirected when authentication failed
  - `providers`: an array of authentication providers, supported providers:
  	- `ldap`: LDAP, Active Directory provider using [passport-ldapauth](https://github.com/vesse/passport-ldapauth)
	- `facebook`: Facebook provider using [passport-facebook](https://github.com/jaredhanson/passport-facebook)
  	- `google`: Google provider using [passport-google-oauth](https://github.com/jaredhanson/passport-google-oauth)
  	- `akera`: Akera.io server-side authentication provider using [@akeraio/passport](https://github.com/akera-io/passport-akera)
  	
  	Provider specific configuration can be found on each provider web page.  	
  
## License
	
MIT 

  	