
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

In order to use the API, you must first generate an auth token / refresh token pair from Globus. These keys are unique to each Globus endpoint. The code below will begin the auth process, returning an auth URL that must be manually logged in to and a session id, unique to this auth flow, which must be entered in the following request.


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
$ curl http://localhost:5000/v3/globus-proxy/auth/tokens/<client id>/<session id>/<auth code>

{"message":"successfully authorized globus client","metadata":{},"result":{"access_token":"...","refresh_token":"..."},"status":"success","version":"dev"}
```

Both of these tokens (access token and refresh token) must be sent in every request made to the Globus-Proxy api.

#### Consent Management
Some endpoints will require an additional 'consent' auth flow. If you are using one of these endpoints, you will have to navigate to the URL provided in the response -- similar to the initial call for requesting a token -- and authorize the globus client to manage this endpoint.

#### Initiate a Transfer
In order to transfer a file between two endpoints, you will need to know the id of both endpoints and have a valid token pair for a Globus transfer client. 

```
$ curl -X POST "http://localhost:5000/v3/globus-proxy/transfers/64e62ddd-9a10-42c4-823e-411f77bfa265?access_token=<access token>&refresh_token=<refresh token>" \
-H "Content-Type: application/json" \
-d '{"source_endpoint": "57218f41-3200-11e8-b907-0ac6873fc732", "destination_endpoint": "<destination>", "transfer_items": [{ "source_path": "data1/1M.dat", "destination_path": "test/1M.dat", "recursive": "False" }]}'

{
	"message": "Success",
	"metadata": {},
	"result": {
		"DATA_TYPE": "transfer_result",
		"code": "Accepted",
		"message": "The transfer has been accepted and a task has been created and queued for execution",
		"request_id": "GFMQzaP0u",
		"resource": "/transfer",
		"submission_id": "<submission id>",
		"task_id": "<task id>",
		"task_link": {
			"DATA_TYPE": "link",
			"href": "task/<task id>?format=json",
			"rel": "related",
			"resource": "task",
			"title": "related task"
		}
	},
	"status": "success",
	"version": "dev"
}
```

This will kick off a transfer of a 1Mb file from one of the Globus test endpoints to whatever destination endpoint you provide. You can check the status of the transfer by passing the task id to the GET endpoint

```
$ curl -x GET "http://localhost:5000/v3/globus-proxy/transfers/<client id>/<task id>?access_token=<access token>&refresh_token=<refresh token>

{
	"message": "successfully retrieved transfer task",
	"metadata": {},
	"result": {
		"DATA_TYPE": "task",
		"bytes_checksummed": 0,
		"bytes_transferred": 0,
		"canceled_by_admin": null,
		"canceled_by_admin_message": null,
		"command": "API 0.10",
		"completion_time": "2022-05-24T14:36:56+00:00",
		"deadline": "2022-05-25T14:36:54+00:00",
		"delete_destination_extra": false,
		"destination_endpoint": "<endpoint>",
		"destination_endpoint_display_name": "<endpoint name>",
		"destination_endpoint_id": "<endpoint id>",
		"directories": 0,
		"effective_bytes_per_second": 0,
		"encrypt_data": false,
		"fail_on_quota_errors": false,
		"fatal_error": null,
		"faults": 0,
		"files": 1,
		"files_skipped": 1,
		"files_transferred": 0,
		"filter_rules": null,
		"history_deleted": false,
		"is_ok": null,
		"is_paused": false,
		"label": "",
		"nice_status": null,
		"nice_status_details": null,
		"nice_status_expires_in": null,
		"nice_status_short_description": null,
		"owner_id": "f0d0fa76-d5ab-4819-8bcd-842648846d0b",
		"preserve_timestamp": false,
		"recursive_symlinks": "ignore",
		"request_time": "2022-05-24T14:36:54+00:00",
		"skip_source_errors": false,
		"source_endpoint": "esnet#57218f41-3200-11e8-b907-0ac6873fc732",
		"source_endpoint_display_name": "ESnet Read-Only Test DTN at Starlight",
		"source_endpoint_id": "57218f41-3200-11e8-b907-0ac6873fc732",
		"status": "SUCCEEDED",
		"subtasks_canceled": 0,
		"subtasks_expired": 0,
		"subtasks_failed": 0,
		"subtasks_pending": 0,
		"subtasks_retrying": 0,
		"subtasks_skipped_errors": 0,
		"subtasks_succeeded": 2,
		"subtasks_total": 2,
		"symlinks": 0,
		"sync_level": 1,
		"task_id": "<task id>",
		"type": "TRANSFER",
		"username": "<user name>",
		"verify_checksum": false
	},
	"status": "success",
	"version": "dev"
}
```

