from multiprocessing import AuthenticationError
from datetime import datetime, timedelta
import globus_sdk

from tapisservice.logs import get_logger
from tapisservice.tapisflask import utils

logger = get_logger(__name__)

def get_transfer_client(client_id, refresh_token, access_token):
    client = globus_sdk.NativeAppAuthClient(client_id)
    # client = globus_sdk.AuthClient(client_id=client_id)
    # check_token(client_id, refresh_token)
    # check_token(client_id, access_token)
    tomorrow = datetime.today() + timedelta(days=1)
    expires_at = tomorrow.timestamp()
    authorizer = globus_sdk.RefreshTokenAuthorizer(
        refresh_token=refresh_token, 
        auth_client=client, 
        access_token=access_token, 
        expires_at=expires_at
    )
    transfer_client = globus_sdk.TransferClient(authorizer=authorizer)
    return transfer_client

def check_tokens(client_id, refresh_token, access_token):
    '''
    Small utility function to check the validity of a globus auth token pair. 
    If refresh_token is invalid, raises AuthenticationError - you must then go through the auth process again to get a new token pair
    If access_token is expired, gets a new one

    returns valid token pair
    '''
    client = globus_sdk.AuthClient(client_id=client_id)
    # validate rf token, raise autherror if invalid
    try:
        response = client.oauth2_validate_token(refresh_token)
    except Exception as e:
        logger.error(f'exception while validating refresh token:: {e}')
        raise AuthenticationError
    else:
        active = response['active']
        if not active:
            raise AuthenticationError
    try:
        response= client.oauth2_validate_token(access_token)
    except Exception as e:
        logger.debug(f'exception while validating access token:: {e}')
        access_token = get_valid_token(client_id, refresh_token)

    return access_token, refresh_token

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

# stolen from neid code

def ls_endpoint(tc, ep_id, path="~"):
    ls = tc.operation_ls(ep_id, path=path)
    return ls
    
def transfer(tc, source_endpoint_id, dest_endpoint_id, files='', dirs='', label='', sync_level="size",verify_checksum=False):  
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

def activate_endpoint(tc, ep_id, username, password):
    '''
    ... with userame and password
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


def is_endpoint_activated(tc, ep):
    '''
    check if globus endpoint is activated
    '''
    endpoint = tc.get_endpoint(ep)
    return endpoint['activated']

def precheck(client_id, endpoints, access_token, refresh_token):
        '''
        Performs several precheck opertations such as
            making sure the tokens are valid and exchanging an expired access token for an active one
            activating a transfer client
        
        returns authenticated transfer client
        '''
        # check token validity
        try:
            access_token, refresh_token = check_tokens(client_id, refresh_token, access_token)
        except AuthenticationError:
            # refresh token is invalid, must redo auth process
            logger.error(f'exception while validating tokens:: {e}')
            return utils.error(
                msg='Error while validating tokens. Please redo the Oauth2 process for this client_id'
            )
            # TODO: handle more exceptions, figure out how to make them nice for the calling function

        # get transfer client
        try:
            transfer_client = get_transfer_client(client_id, refresh_token, access_token)
        except Exception as e:
            logger.error(f'unable to get transfer client or client {client_id}: {e}')
            return utils.error(
                msg='Exception while generating authorization. Please check your request syntax and try again'
            )
        
        # activate endpoint
        if not isinstance(endpoints, list):
            # convert to list if only given single endpoint_id as string
            endpoints = list(endpoints)
        for endpoint_id in endpoints:
            if not is_endpoint_activated(transfer_client, endpoint_id):
                logger.debug(f'ep {endpoint_id} is not active')
                autoactivate_endpoint(transfer_client, endpoint_id)
            

def autoactivate_endpoint(transfer_client, endpoint_id):
    try:
        result = transfer_client.endpoint_autoactivate(endpoint_id)
        if result['code'] == "AutoActivationFailed":
            raise AuthenticationError
    except AuthenticationError as e:
        logger.error(f'endpoint activation failed. Endpoint must be manuallty activated')
        return utils.error(
            msg=f'Endpoint {endpoint_id} must be manually activated'
        )
    except Exception as e:
        logger.debug(f'Unknown exception activating endpoint with id {endpoint_id}')
        pass
        # TODO: handle excpetions. 

    # return transfer client
    return transfer_client


