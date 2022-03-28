from multiprocessing import AuthenticationError
from datetime import datetime, timedelta
import globus_sdk

from tapisservice.logs import get_logger
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
