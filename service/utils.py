## builtin
from multiprocessing import AuthenticationError as PythonAuthenticationError
from datetime import datetime, timedelta
import json
import os

## globus
import globus_sdk
from globus_sdk.scopes import ScopeBuilder, GCSCollectionScopeBuilder, TransferScopes, AuthScopes
from globus_sdk.services.transfer.errors import TransferAPIError

## tapis
from tapisservice.logs import get_logger
from tapisservice.config import conf as config
from tapisservice.tapisflask import utils
from tapisservice.errors import AuthenticationError

## local
from errors import *

logger = get_logger(__name__)


def activate_endpoint(tc, ep_id, username, password):
    '''
    ... with username and password
    '''
    activation_req = tc.endpoint_get_activation_requirements(ep_id).data
    for data in activation_req["DATA"]:
        if data["type"] == "myproxy":
            if data["name"] == "username":
                data["value"] = username
            if data["name"] == "passphrase":
                data["value"] = password
    try:
        tr = tc.endpoint_activate(ep_id, activation_req)
    except Exception as e:
        print(e)
        print("Endpoint requires manual activation, please open "
              "the following URL in a browser to activate the "
              "endpoint: \n")
        print("https://app.globus.org/file-manager?origin_id=%s" % ep_id)
        input("Press ENTER after activating the endpoint:")
        r = tc.endpoint_autoactivate(ep_id, if_expires_in=3600)
        print(r)
        return r
    return tr

def autoactivate_endpoint(transfer_client, endpoint_id):
    try:
        logger.info(f'Trying to autoactivate endpoint {endpoint_id}')
        result = transfer_client.endpoint_autoactivate(endpoint_id)
        msg = result['message']
        logger.debug(f'have res:: {msg}')
    except PythonAuthenticationError as e:
        logger.error(f'Endpoint activation failed due to invalid token. Endpoint {endpoint_id} must be manuallty activated')
        raise PythonAuthenticationError()
    except Exception as e:
        logger.error(f'Unknown exception activating endpoint with id {endpoint_id} :: {e}')
        # raise InternalServerError()
        raise GlobusError(msg=f"Endpoint activation failed due to unknown error. Endpoint {endpoint_id} must be manuallty activated")
    finally:
        if result['code'] == "AutoActivationFailed":
            logger.error(f'Endpoint activation failed. Endpoint {endpoint_id} must be manuallty activated')
            raise GlobusError(msg=f'Endpoint activation failed. Activate endpoint {endpoint_id} by going to https://app.globus.org/file-manager?origin_id={endpoint_id}')
            # TODO: spawn thread that waits for activation?

def check_consent_required(client, target):
    '''
    Checks if an endpoint required consent before operations can be made against it
    returns a list of scopes so we can send it through the auth flow again 
    '''
    consent_required_scopes = []
    try:
        ls_endpoint(client, target)
    except globus_sdk.TransferAPIError as e:
        if e.info.consent_required:
            consent_required_scopes.extend(e.info.consent_required.required_scopes)
    return consent_required_scopes

def check_tokens(client_id, refresh_token, access_token):
    '''
    *** oauth2_validate_token has been deprecated ***

    Small utility function to check the validity of a globus auth token pair. 
    If refresh_token is invalid, raises PythonAuthenticationError - you must then go through the auth process again to get a new token pair
    If access_token is expired, gets a new one

    returns valid token pair
    '''
    # client = globus_sdk.AuthClient(client_id=client_id)
    # # validate rf token, raise autherror if invalid
    # try:
    #     response = client.oauth2_validate_token(refresh_token)
    # except Exception as e:
    #     logger.error(f'exception while validating refresh token:: {e}')
    #     raise PythonAuthenticationError
    # else:
    #     active = response['active']
    #     if not active:
    #         raise PythonAuthenticationError
    # try:
    #     response= client.oauth2_validate_token(access_token)
    # except Exception as e:
    #     logger.error(f'exception while validating access token:: {e}')
    #     access_token = get_valid_token(client_id, refresh_token)

    return access_token, refresh_token

def format_path(path, default_dir=None):
        '''
        Force absoulte paths for now, due to Globus not ahndling /~/ the same way on all systems
        if a user provides a relative path, it will instead be returned as an INCORRECT abs path.
        '''
        logger.info(f'building path with path {path} and default {default_dir} ')
        
        return f"/{path.rstrip('/').lstrip('/')}"


def get_collection_id(client_id, client_secret, name):
    client = get_transfer_client_with_secret(client_id, client_secret)
    result = client.endpoint_search(filter_fulltext=name, filter_non_functional=False, limit=1)
    # print(f'have result:: {result["DATA"][0]["id"]}')
    return result["DATA"][0]["id"]


def get_transfer_client(client_id, refresh_token, access_token):
    logger.debug(f'Attempting auth for client {client_id} using token')
    print(f'Attempting auth for client {client_id} using token')
    client = globus_sdk.NativeAppAuthClient(client_id)
    # check_token(client_id, refresh_token, access_token)
    tomorrow = datetime.today() + timedelta(days=1)
    expires_at = tomorrow.timestamp()
    authorizer = globus_sdk.RefreshTokenAuthorizer(
        refresh_token=refresh_token, 
        auth_client=client, 
        access_token=access_token, 
        expires_at=expires_at
    )
    # get_token_introspect(client_id, refresh_token)
    transfer_client = globus_sdk.TransferClient(authorizer=authorizer)
    return transfer_client


def get_transfer_client_with_secret(client_id, client_secret, endpoint_id=None, addl_scopes=None):
    logger.debug(f'Attempting auth for client {client_id} using secret')
    try:
        auth_client = globus_sdk.ConfidentialAppAuthClient(client_id, client_secret)
    except Exception as e:
        msg = f'exception:: {e}'
        print(msg)
        logger.critical(msg)
        raise handle_transfer_error(e)
    scopes = f'urn:globus:auth:scope:transfer.api.globus.org:all'
    if endpoint_id:
        access_scope = f'[*https://auth.globus.org/scopes/{endpoint_id}/data_access]'
        scopes = scopes + access_scope
    
    logger.debug(scopes)
    try:
        cc_authorizer = globus_sdk.ClientCredentialsAuthorizer(auth_client, scopes)
    except Exception as e:
        logger.critical(f'failure instantiating cc_auth:: {e}')
        raise handle_transfer_error(e)
    # create a new client
    try:
        transfer_client = globus_sdk.TransferClient(authorizer=cc_authorizer)
    except Exception as e:
        logger.critical(f'failure getting transfer client:: {e}')
        raise handle_transfer_error(e)
    logger.debug(f'got client: {transfer_client} with endpoint: {endpoint_id} and scopes: {scopes}')
    return transfer_client


def get_valid_token(client_id, refresh_token):
    '''
    Utility function that takes a client id and refresh token
    and returns a valid access token

    This is useful if the token has been proved invalid by the check_token utility 
    but operations must be done with a valid token

    returns valid access token
    '''
    client = globus_sdk.NativeAppAuthClient(client_id=client_id)
    response = client.oauth2_refresh_token(refresh_token)
    return response['transfer.api.globus.org']['access_token']

def handle_transfer_error(exception, endpoint_id=None, msg=None):
        '''Tanslates transfer api errors into the configured basetapiserrors in ./errors.py'''
        logger.debug('in handle transfer error')
        message = None
        try:
            message = exception.message
        except AttributeError:
            logger.debug(f'exception has no attribute message. trying msg instead')
            try:
                message = exception.msg
            except:
                logger.debug(f'exception has no attribute msg.')

        logger.critical(f'\nhandling transfer API error:: {exception.code}:: with message {message}\n')
        error = InternalServerError(msg='Interal server error', code=500)
        if getattr(exception, "code", None) == None:
            logger.debug(f'exception {exception} has no code, therefore returning InternalServerError')
            return error
        if exception.code == "AuthenticationFailed":
            error = AuthenticationError(msg='Could not authenticate transfer client', code=401)
        if exception.code == "ClientError.NotFound":
            error = PathNotFoundError(msg='Path does not exist on given endpoint', code=404)
        if exception.code == "ExternalError.DirListingFailed.GCDisconnected":
            error = GlobusError(msg=f'Error connecting to endpoint {endpoint_id}. Please activate endpoint manually', code=407)
        if exception.code == 'ExternalError.DirListingFailed.LoginFailed':
            error = GlobusError(msg='Your identity does not have permission to access the requested collection. Contact the collection administrator to request access.', code=403)
        if exception.code == 'ConsentRequired':
            error = GlobusConsentRequired(msg=f'Endpoint {endpoint_id} requires additonal consent. Auth flow ust be manually re-run.', code=407)
        if exception.code == 'ExternalError.MkdirFailed.Exists':
            error = GlobusPathExists(msg=f'Directory with given path already exists.', code=409)
        if exception.code == 'EndpointPermissionDenied':
            error = GlobusUnauthorized(msg=exception.http_reason)
        if exception.code == 'EndpointError':
            if exception.http_reason == 'Bad Gateway':
                error = InternalServerError(msg="Bad Gateway", code=502)
        if exception.code == 400:
            error = GlobusInvalidRequestError(msg=message)
        logger.error(error)
        return error

def is_endpoint_activated(tc, ep):
    '''
    check if globus endpoint is activated
    '''
    logger.debug(f'in ep active? have {tc}')
    endpoint = tc.get_endpoint(ep)
    return endpoint['activated']

def is_endpoint_connected(transfer_client, endpoint_id):
    logger.debug(f'in is_endpoint_connected with tc: {transfer_client}, ep: {endpoint_id}')
    try:
        result = transfer_client.get_endpoint(endpoint_id)
    except Exception as e:
        logger.error(f'Unknown exception getting endpoint with id {endpoint_id}:: {e}')
    finally:
        try:
            connected = result["DATA"][0]["is_connected"]
        except Exception as e:
            logger.error(f'Unknown exception getting endpoint connection status with id: {endpoint_id}: {e}')
        logger.debug(f'endpoint connection status:: {connected}')
        # return connected
        return True

def is_gcp(endpoint_id):
    '''
    Given endpoint id, return type of collection
    Requires that we have a client ID and client secret in the config-local.json file
    '''
    logger.debug(f'in is_gcp with eid: {endpoint_id}')
    tapisconf = config.get_config_from_file()
    client_id = tapisconf['client_id']
    client_secret = tapisconf['client_secret']
    res = {}

    client = get_transfer_client_with_secret(client_id, client_secret)
    try:
        res = client.get_endpoint(endpoint_id)
    except TransferAPIError as e:
        # assume it's a gcp
        logger.error(f'got error checking collection type: {e}')
        res['is_globus_connect'] = 'true'
    except:
        logger.error(f'got error checking collection type: {e}')
        raise handle_transfer_error(e)
        
        
    gcp = True if res["is_globus_connect"] == 'true' else False
    logger.debug(f'Is collection {endpoint_id} a gcp? : {gcp}')
    return gcp

def ls_endpoint(tc, ep_id, path="~"):
    ls = tc.operation_ls(ep_id, path=path)
    return ls
    
def parse_args():
    pass

def precheck(client_id, endpoints, access_token, refresh_token):
        '''
        Performs several precheck opertations such as
            making sure the tokens are valid and exchanging an expired access token for an active one
            activating a transfer client
        
        returns authenticated transfer client
        '''
        # make sure tokens are provided
        if not access_token or not refresh_token:
            msg='Could not parse token from request parameters. Please provide valid token.'
            logger.error(f'error parsing tokens from args for client {client_id}')
            raise AuthenticationError(msg=msg, code=401)
        
        # check token validity
        try:
            access_token, refresh_token = check_tokens(client_id, refresh_token, access_token)
        except PythonAuthenticationError:
            # refresh token is invalid, must redo auth process
            logger.error(f'exception while validating tokens:: {e}')
            raise AuthenticationError(msg='Could not validate tokens. Please redo the Oauth2 process for this client_id')
            # TODO: handle more exceptions, figure out how to make them nice for the calling function

        # get transfer client
        transfer_client = None
        try:
            transfer_client = get_transfer_client(client_id, refresh_token, access_token)
            # transfer_client = get)get_transfer_client_with_secret(client_id, )
        except Exception as e:
            logger.error(f'unable to get transfer client or client {client_id}: {e}')
            raise GlobusError(msg='Exception while generating authorization. Please check your request syntax and try again')
        logger.debug(f'in precheck, have tc {transfer_client}')

        # allow operations that don't use endpoints to still use precheck
        if endpoints is None:
            return transfer_client
        
        # activate endpoint
        logger.debug(f'about to check eps:: {endpoints}')
        if not isinstance(endpoints, list):
            logger.debug('eps are not a list!')
            # convert to list if only given single endpoint_id as string
            endpoints = list(endpoints.split())
            logger.debug(f'have ep list:: {endpoints}')
        for endpoint_id in endpoints:
            endpoint_info = transfer_client.get_endpoint(endpoint_id)
            endpoint_type = endpoint_info["entity_type"]
            if endpoint_type == "GCP_mapped_collection": # if it's a globus connect personal ep
                connected = is_endpoint_connected(transfer_client, endpoint_id)
                if not connected:
                    logger.error(f'Endpoint {endpoint_id} is a Globus Connect Personal endpoint and must be manuallty connected')
                    raise GlobusError(msg=f'Endpoint {endpoint_id} is a Globus Connect Personal endpoint and must be manuallty connected')
            logger.debug(f'checking ep {endpoint_id}')
            if not is_endpoint_activated(transfer_client, endpoint_id):
                logger.debug(f'ep {endpoint_id} is not active')
                autoactivate_endpoint(transfer_client, endpoint_id)
        
        return transfer_client

def start_auth_flow(client, scopes=TransferScopes.all):
    client.oauth2_start_flow(refresh_tokens=True, requested_scopes=scopes)
    authorize_url = client.oauth2_get_authorize_url()
    return authorize_url

def transfer(tc, source_endpoint_id, dest_endpoint_id, files='', dirs='', label='Tapisv3', sync_level="size",verify_checksum=False):  
    '''
    # verify_checksum for now. if there's a bottleneck, reconsider
    '''
    '''
    start globus file transfer
    files is a list of dictionaries with the format {source: "/source/path/file.txt", dest: "/dest/path/file.txt"}
    dirs is a list of dictionaries with the format {source: "/source/path/dir", dest: "/dest/path/dir"}
    '''
    tdata = globus_sdk.TransferData(tc, source_endpoint_id, dest_endpoint_id, label=label, sync_level=sync_level, verify_checksum=verify_checksum)
    for file in files:
        try:
            # print('before ls ep init')
            ls_endpoint(tc, dest_endpoint_id, path=file['destination_path'].rsplit('/', 1)[0])
            # logger.debug('after ls endpoint init')
        except Exception as e:
            print(file)
            return ('File Transfer Failed: {}'.format(e))
        # logger.debug('before add item')
        tdata.add_item(file['source_path'], file['destination_path'])
        # logger.debug('after add item')
    for dir in dirs:
        try:
            
            ls_endpoint(tc, dest_endpoint_id, _path=dir['source_path'])
        except Exception as e:
            logger.debug('Problem with remote directory: {}'.format(dir['source_path']))
            return ('Dir Transfer Failed: {}'.format(e))
        tdata.add_item(dir['source_path'], dir['destination_path'], recursive=True)
    transfer_result = tc.submit_transfer(tdata)
    return transfer_result
    


