# Globus-Proxy

API Spec -> https://tapis-project.github.io/live-docs/?service=GlobusProxy&amp;branch=dev

## Setup steps

Navigate to the root directory of the app and run the docker-compose file with

`docker-compose up`

## Run tests

Automated testing is handled with pytest, and is automatically configured to run when booting up the container locally. The test files are located in the `service/tests` directory.

## Quickstart

Use any HTTP client to interact with the running API. The following examples use `curl`. 

#### Generate Tokens

In order to use the API, you must first generate an auth token / refresh token pair from Globus. These keys are unique to each Globus endpoint. 


```
$ curl http://localhost:5000/v3/globus-proxy/auth/url/<client id>
{
	"message": "Please go to this URL and login: https://auth.globus.org/v2/oauth2/authorize?client_id=64e62ddd-9a10-42c4-823e-411f77bfa265&redirect_uri=https%3A%2F%2Fauth.globus.org%2Fv2%2Fweb%2Fauth-code&scope=openid+profile+email+urn%3Aglobus%3Aauth%3Ascope%3Atransfer.api.globus.org%3Aall&state=_default&response_type=code&code_challenge=iD5xQTnT5_bem5pHgZRo-sepAT69gwarq9skUAaaR4U&code_challenge_method=S256&access_type=offline",
	"metadata": {},
	"result": {
		"session_id": "Q5xCRfqVLWlm9I2sABhJJlb3es-qt0zF_6KHSAuzKDU",
		"url": "https://auth.globus.org/v2/oauth2/authorize?client_id=64e62ddd-9a10-42c4-823e-411f77bfa265&redirect_uri=https%3A%2F%2Fauth.globus.org%2Fv2%2Fweb%2Fauth-code&scope=openid+profile+email+urn%3Aglobus%3Aauth%3Ascope%3Atransfer.api.globus.org%3Aall&state=_default&response_type=code&code_challenge=iD5xQTnT5_bem5pHgZRo-sepAT69gwarq9skUAaaR4U&code_challenge_method=S256&access_type=offline"
	},
	"status": "success",
	"version": "dev"
}
```

You will have to navigate to the URL returned in the response message manually to login to the account tied to the endpoint, then authorize the app to use the authenticated client and provide a label. Refresh tokens live for 6 months past the last time they were used, so this manually process should not be required every time you use the API.

#### Swapping auth code for token pair
Logging into the URL from the last request will return a Globus auth code. This code must be entered in the next request to return a token pair. 

Follow the URL given in the response from the last request and login. 
```

```
