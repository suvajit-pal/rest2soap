# rest2soap

A lightweight wrapper using Adobe IO Runtime enabling JSON format calls to be made to an Adobe Campaign Classic (ACC) instance.
This is technically not a pure REST wrapper as it supports only POST actions and REST verbs like GET, PUT, DELETE, etc are not available but provides an easy interface to get a REST request format from an existing SOAP payload and making subsequent calls via the JSON format.

- Additionally this package supports calls from systems that need to pass sensitive information over a secure PGP encrypted format. Supports both encrypted PGP request and response.

- If you are looking for ACC SDK implementation, please check https://github.com/adobe/acc-js-sdk

## Setup

- Get a Adobe IO Runtime environemnt provisioned.
- Populate the `.env` file in the project root and fill it as shown [below](#env)
- Create a parameter binding file as shown [below](#config)

## Usage
- Deploy the package to your or client runtime namespace.

- Create a package parameter bind.

	```aio rt pkg bind [packagename] [bindpackagename] --param-file config/config.json ```

- Update the package binding of an existing package run

	```aio rt pkg update --param-file config/config.json ```

- Multiple package binds can be created for different parameter values.

- Call action ```testConnection``` to validate connection.
- Supported parameters checkDecryption and checkEncryption to validate PGP keys.

- Call action ```getRestRequestFromSoap``` to get the REST request format.

- Call action ```invokeSoapAction``` to make the SOAP call in Adobe Campaign Classic (ACC). 

## Local Dev

- `aio app run --local` to start your local Dev server
- App will run on `localhost:9080` by default

By default the UI will be served locally but actions will be deployed and served from Adobe I/O Runtime. To start a
local serverless stack and also run your actions locally use the `aio app run --local` option.

## Deploy & Cleanup

- `aio app deploy` to build and deploy all actions on Runtime and static files to CDN
- `aio app undeploy` to undeploy the app

## Config

### `.env`

```bash
# This file should not be committed to source control

## please provide your Adobe I/O Runtime credentials
# AIO_RUNTIME_AUTH= ## IO Runtime Auth Credential ##
# AIO_RUNTIME_NAMESPACE=## IO Runtime Namespace ##
```

### `.config`

```
{
	"encryptRequest" : "/** Possible values Y and N. Set to Y, if the incoming request will be PGP encrypted */", 
	"encryptResponse" : "/** Possible values Y and N. Set to Y if the response has to be PGP encrypted */",
	"generateToken"	: "/** Possible values Y and N. Set to Y if the API should generate loginTokens for Campaign SOAP Calls.*/",
	"instanceLoginAPI" : "/** The login username that will be used to generate tokens. Required if generateToken is set to Y. */",
	"instanceLoginAPIKey" : "/** The login password that will be used to generate tokens. Required if generateToken is set to Y.",
	"instance" : "/** The instance identifier without campaign.adobe.com prefix. */",
	"pass" : "/** The PGP private key password. Required if either encryptRequest or encryptResponse is set to Y.*/",
	"private_key" : "/** The PGP private key in ASCII armoured format. Required if either encryptRequest or encryptResponse is set to Y.*/",
	"public_key" : "/** The PGP public key in ASCII armoured format. Required if either encryptRequest or encryptResponse is set to Y.*/",
	"verifySignature" : "/** Possible values Y and N. Set to Y if the PGP request should be validated using the 'public_key' and the PGP response will be signed with 'key'. */"
}
```
