from flask_restful import Resource
from flask import Flask, request
from tapisservice.errors import AuthenticationError, BaseTapisError

import globus_sdk
from globus_sdk import TransferAPIError

from utils import *
from errors import *

logger = get_logger(__name__)
app = Flask(__name__)


class AuthURLResource(Resource):
    """
    Return authorization URL given client Id
    """

    def get(self, client_id, endpoint_id):
        # TODO: a call to get_identities needs to be authenticated
        # there might not be a way to figure out if the client_id 
        # is valid or not without letting the user go to the url and find out

        try:
            client = globus_sdk.NativeAppAuthClient(client_id)
        except Exception as e:
            msg = f'Encountered exception while initializing globus_sdk for client {client_id}\n\t{e}'
            logger.error(msg)
            raise InternalServerError(msg=msg)
        
        # build scopes
        SCOPE = None
        if not is_gcp(endpoint_id):
            logger.debug(f'endpoint is not a gcp')
            DEPENDENT_SCOPE = f"https://auth.globus.org/scopes/{endpoint_id}/data_access"
            SCOPE = f"urn:globus:auth:scope:transfer.api.globus.org:all[*{DEPENDENT_SCOPE}]"
        else:
            logger.debug(f'endpoint is a gcp')

        session_client = client.oauth2_start_flow(refresh_tokens=True, requested_scopes=SCOPE)
        
        authorize_url = client.oauth2_get_authorize_url()
        # authorize_url = start_auth_flow(client)
        logger.debug(f"successfully got auth url for client {client_id}")
        return utils.ok(
                result = {"url": authorize_url, "session_id": session_client.verifier}, 
                msg = f'Please go to the URL and login. this is a test'
            )

class TokensResource(Resource):
    """
    exchange client_id, session_id, & auth code for access and refresh tokens
    """

    def get(self, client_id, session_id, auth_code):

        try:
            client = globus_sdk.NativeAppAuthClient(client_id)
            session_client = client.oauth2_start_flow(verifier=session_id)
        except Exception as e:
            msg = f'Encountered exception while initializing globus_sdk with client id:: {client_id}\n\t{e}\n\t'
            logger.error(msg)
            raise InternalServerError(msg=msg)


        # get access / refresh tokens
        try:
            token_response = client.oauth2_exchange_code_for_tokens(auth_code).by_resource_server
        except globus_sdk.services.auth.errors.AuthAPIError:
            msg = f'Invalid auth code given for client {client_id}'
            logger.error(msg)
            raise AuthenticationError(msg=msg, code=401)
        else:
            try:
                access_token = token_response['transfer.api.globus.org']['access_token']
                refresh_token = token_response['transfer.api.globus.org']['refresh_token']
            except KeyError as e:
                msg = f'Could not parse tokens from response:: {e}'
                logger.error(msg)
                raise InternalServerError(msg=msg)
        
        return utils.ok(
                result = {"access_token": access_token, "refresh_token": refresh_token}, 
                msg = "successfully authorized globus client"
              ) 

class CheckTokensResource(Resource):
    """
    check validity of auth / refresh tokens and exchange if needed
    """

    def get(self, endpoint_id):
        access_token = request.args.get('access_token')
        refresh_token = request.args.get('refresh_token')

        if access_token is None or refresh_token is None:
            return utils.error(
                msg = 'Access token and refresh token must be provided as query parameters'
            )

        # check access token
        # check refresh token
        # if access token is valid but refresh is not, return access token
        # if access token is invalid but refresh token is valid, get new token
        # if access token and refresh token is invalid, error

        ac_token = ''
        rf_token = ''

        ### 1/23/2024 oauth2_validate_token has been deprecated
        # check if given tokens are valid
        client = globus_sdk.NativeAppAuthClient(endpoint_id)
        # try:
        #     ac_response = client.oauth2_validate_token(access_token)
        #     rf_response = client.oauth2_validate_token(refresh_token)
        # except:
        #     logger.debug('Unknown error checking validity of tokens')
        #     return utils.error(
        #         msg = 'Unable to check validity of given tokens'
        #     )
        # else:
        #     logger.debug(f'ac:: {ac_response}')
        #     logger.debug(f'rf:: {rf_response}')
        #     ac_token = access_token if ac_response['active'] == True else None
        #     rf_token = refresh_token if rf_response['active'] == True else None

        # if either token is none, get new tokens
        if ac_token is None or rf_token is None:
            try:
                refresh_response = client.oauth2_refresh_token(str(refresh_token))
            except:
                logger.debug('Unknown error generating new tokens. Please try again later.')
            else:
                logger.debug(f'have token response:: {refresh_response}')
                return utils.ok(
                    msg = 'Successfully refreshed tokens',
                    result = {"access_token": refresh_response['access_token'], "refresh_token": rf_token}
                )

        return utils.ok(
                result = {"access_token": ac_token, "refresh_token": rf_token},
                msg = 'Successfully validated tokens'
              )