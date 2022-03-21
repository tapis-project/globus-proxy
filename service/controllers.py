import json

from flask import Flask, current_app, request
from flask_restful import Resource

from tapisservice.tapisflask import utils
from tapisservice.tapisflask.resources import ReadyResource
from tapisservice.logs import get_logger

import globus_sdk
from globus_sdk import TransferAPIError

from utils import check_token, get_transfer_client

from multiprocessing import AuthenticationError

logger = get_logger(__name__)
app = Flask(__name__)


class HealthcheckResource(ReadyResource):
    pass

class AuthURLResource(Resource):
    """
    Return authorization URL given client Id
    """

    def get(self, client_id):
        # TODO: a call to get_identities needs to be authenticated
        # there might not be a way to figure out if the client_id 
        # is valid or not without letting the user go to the url and find out
        try:
            client = globus_sdk.NativeAppAuthClient(client_id)
        except Exception as e:
            logger.debug(f'Encountered exception while initializing globus_dsk::\n\t{e}')
            return utils.error(
                msg = 'Unknown error occurred'
            )
        session_client = client.oauth2_start_flow(refresh_tokens=True)
        authorize_url = client.oauth2_get_authorize_url()

        return utils.ok(
                # result = {"url": authorize_url, "uuid": session_id}, 
                result = {"url": authorize_url, "session_id": session_client.verifier}, 
                msg = f'Please go to this URL and login: {authorize_url}'
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
            logger.error(f'Encountered exception while initializing globus_sdk::\n\t{e}')
            return utils.error(
                msg= 'Unknown error occurred. Unable to authenticate client'
            )


        # get access / refresh tokens
        try:
            token_response = client.oauth2_exchange_code_for_tokens(auth_code)
        except globus_sdk.services.auth.errors.AuthAPIError:
            return utils.error(
                msg = 'Invalid auth code given for client'
            )
        else:
            try:
                logger.debug(token_response)
                access_token = token_response['transfer.api.globus.org']['access_token']
                refresh_token = token_response['transfer.api.globus.org']['refresh_token']
            except KeyError:
                logger.error('Could not parse tokens from ')
        
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

        logger.debug(f'in check tokens with ac: {access_token} & rf: {refresh_token}')

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

        # check if given tokens are valid
        client = globus_sdk.NativeAppAuthClient(endpoint_id)
        try:
            ac_response = client.oauth2_validate_token(access_token)
            rf_response = client.oauth2_validate_token(refresh_token)
        except:
            logger.debug('Unknown error checking validity of tokens')
            return utils.error(
                msg = 'Unable to check validity of given tokens'
            )
        else:
            logger.debug(f'ac:: {ac_response}')
            logger.debug(f'rf:: {rf_response}')
            ac_token = access_token if ac_response['active'] == True else None
            rf_token = refresh_token if rf_response['active'] == True else None

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
            

class LsResource(Resource):

    def get(self, client_id, endpoint_id, path):
        # grab access token from query & make sure it's valid
        try:
            access_token = request.args.get('access_token')
            refresh_token = request.args.get('refresh_token')
            check_token(client_id, access_token)
            check_token(client_id, refresh_token)
        except AuthenticationError:
            logger.error(f'Invalid token given for client {client_id}')
            return utils.error(
                msg='Given tokens are not valid. Try again with active auth tokens'
            )
        except Exception as e:
            logger.error(f'exception while parsing params for client {client_id}: {e}')
            return utils.error(
                msg='Exception while parsing request parameters. Please check your request syntax and try again'
                )
        try:
            transfer_client = get_transfer_client(client_id, refresh_token, access_token)
        except Exception as e:
            logger.error(f'unable to get transfer client or client {client_id}: {e}')
            return utils.error(
                msg='Exception while generating authorization. Please check your request syntax and try again'
            )
        try:
            # call operation_ls to make the directory
            logger.debug(f'have endpoint id:: {endpoint_id}')
            logger.debug(f'have path:: {path}')
            logger.debug(f'have transfer_client:: {transfer_client}')
            result = transfer_client.operation_ls(
                endpoint_id=str(endpoint_id),
                path=str(path)
            )
            logger.debug(f'after ls ')
            # logger.debug(f'with {result}')
            # logger.debug('\n{result.data}')
            # logger.debug('\n{result.text}')
        except TransferAPIError as e:
            logger.error(f'transfer api error for client {client_id}: {e}')
            if e.code == "AuthenticationFailed":
                return utils.error(
                    msg='Could not authenticate transfer client for ls operation'
                )
        except Exception as e:
            logger.error(f'exception while doing ls operation for client {client_id}:: {e}')
            return utils.error(
                msg='Exception while performing ls operation'
            )
        else:
            # TODO: send access token back, even if it's the same one
            # if the tokens get refreshed live, we could have a race condition 
            # figure out a way to test if refreshed access tokens will cause a call to fail
                # especially for concurrent ops
            result_dict = {}
            for entry in result:
                logger.debug(entry)
                
            return utils.ok(
                msg='Successfully listed files',
                result=json.dumps(result.text)
            )
            
        return utils.error(
            msg='Unknown error performing list operation'
        )

def MkdirResource(Resource):
    def post(self):
        pass













