from multiprocessing import AuthenticationError
from os import access
import globus_sdk

from tapisservice.logs import get_logger
logger = get_logger(__name__)

def get_transfer_client(client_id, refresh_token, access_token):
    client = globus_sdk.NativeAppAuthClient(client_id)
    # client = globus_sdk.AuthClient(client_id=client_id)
    authorizer = globus_sdk.RefreshTokenAuthorizer(
        refresh_token=refresh_token, 
        auth_client=client, 
        access_token=access_token, 
        expires_at=""
    )
    transfer_client = globus_sdk.TransferClient(authorizer=authorizer)
    return transfer_client

def check_token(client_id, token):
        '''
        Small utility function to check the validity of a globus auth token. 
        Raises AuthernticationError if token is not active
        '''
        client = globus_sdk.AuthClient(client_id=client_id)
        try:
            response = client.oauth2_validate_token(token)
        except Exception as e:
            raise AuthenticationError
        else:
            logger.debug('token is active')
        return True
