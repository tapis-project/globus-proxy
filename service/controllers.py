import os
import uuid

from flask import Flask, current_app, request
from flask_restful import Resource

from tapisservice.tapisflask import utils
from tapisservice.tapisflask.resources import ReadyResource
from tapisservice.logs import get_logger

import globus_sdk
import requests

logger = get_logger(__name__)
app = Flask(__name__)


class HealthcheckResource(ReadyResource):
    pass

class AuthURLResource(Resource):
    """
    receive tokens using oauth2 
    """
    def get(self, client_id):
        logger.debug("in get for tokens resource")
        # init globus_sdk client
        # try:
        #    id_client = globus_sdk().AuthClient()
        #    id_response = id_client.get_identities(ids=client_id)
        #except Exception as e:
        #    logger.debug(f'Encountered exception while checking identity::\n\t{e}')
        # else:
        #    logger.debug(f'got response checking id:: {id_response}')
        try:
            client = globus_sdk.NativeAppAuthClient(client_id)
        except Exception as e:
            logger.debug(f'Encountered exception while initializing globus_dsk::\n\t{e}')
        client.oauth2_start_flow(refresh_tokens=True)
        client_uuid = uuid.uuid4()

        # save client in memory
        local_client_uuid = locals()['client_uuid']
        setattr(current_app, str(local_client_uuid), client)

        authorize_url = client.oauth2_get_authorize_url()
        return utils.ok(
                result = {"url": authorize_url, "uuid": client_uuid}, 
                msg = f'Please go to this URL and login: {authorize_url}'
              )

class TokensResource(Resource):
    """
    exchange auth code for access and refresh tokens
    """
    def get(self, uuid, auth_code):
        # retrieve client from memory
        # TODO: return 404 if not found
        client = getattr(current_app, uuid)
        delattr(current_app, uuid)
        try:
            logger.debug('after delete, have ', getattr(current_app, uuid))
        except Exception as e:
            logger.debug('item was deleted successfully')
        # TODO: clean up any objects older than 10 mintues

        # get access / refresh tokens
        token_response = client.oauth2_exchange_code_for_tokens(auth_code)
        access_token = token_response['access_token']
        refresh_token = token_response['refresh_token']
        
        return utils.ok(
                result = {"access_token": access_token, "refresh_token": refresh_token}, 
                msg = "successfully authorized globus client"
              ) 

class CheckTokensResource(Resource):
    """
    check validity of auth / refresh tokens and exchange if needed
    """
    def get(self, endpoint_id):
        # query = str(request.query_string)
        # logger.debug(query)
        query = request.args
        access_token = query.get('access_token')
        refresh_token = query.get('refresh_token')
        
        # debug
        logger.debug('have tokens')
        logger.debug(access_token)
        logger.debug(refresh_token)
        ###

        ac_token = ''
        rf_token = ''

        # check if given tokens are valid
        client = globus_sdk.NativeAppAuthClient(endpoint_id)
        try:
            ac_response = client.oauth2_validate_token(access_token)
        except:
            logger.debug('Unknown error checking validity of access token. Please try again later.')
        else:
            logger.debug(f'ac:: {ac_response}')
            ac_token = access_token if ac_response['active'] == True else None
        try:
            rf_response = client.oauth2_validate_token(refresh_token)
        except:
            logger.debug('Unknown error checking validity of access token. Please try again later.')    
        else:
            logger.debug(f'rf:: {rf_response}')
            rf_token = refresh_token if rf_response['active'] == True else None

        # if either token is none, get new tokens
        if ac_token is None or rf_token is None:
            try:
                client.oauth2_refresh_token(str(refresh_token))
            except:
                logger.debug('Unknown error generating new tokens. Please try again later.')
        return utils.ok(
                result = {"access_token": ac_token, "refresh_token": rf_token},
                msg = {'Successfully validated tokens'}
              )
            
















