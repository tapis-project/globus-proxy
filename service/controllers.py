import os
import uuid
from datetime import datetime, timedelta

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
        # TODO: a call to get_identities needs to be authenticated
        # there might not be a way to figure out if the client_id 
        # is valid or not without letting the user go to the url and find out
        try:
            client = globus_sdk.NativeAppAuthClient(client_id)
        except Exception as e:
            logger.debug(f'Encountered exception while initializing globus_dsk::\n\t{e}')
            return utils.error()
        client.oauth2_start_flow(refresh_tokens=True)
        client_uuid = uuid.uuid4()

        # local_client_uuid = locals()['client_uuid']
        # grab client list from memory if it exists
        # if not, create it
        try:
            local_client_dict = getattr(current_app, 'local_client_dict')
        except Exception as e:
            local_client_dict = {}
        finally:
            # save client into the dict then save the dict back to mem
            local_client_dict[str(client_uuid)] = {'timestamp': datetime.now(), 'client': client}
            setattr(current_app, 'local_client_dict', local_client_dict)
            logger.debug('have local_client_dict::')
            logger.debug(local_client_dict)

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
        try:
            local_client_dict = getattr(current_app, 'local_client_dict')
            # client = getattr(current_app, uuid)
            client = local_client_dict[uuid]['client']
            # debug
            logger.debug('got client from memory::')
            logger.debug(client)
        except KeyError:
            return utils.error(
                msg='Could not authenticate Globus. Please try the authentication process over again'
            )
        except Exception as e:
            return utils.error(
            )
        finally:
            # delete object from mem & cleanup any objects > 10 minutes old
            del local_client_dict[uuid]
            for key in local_client_dict:
                timestamp = datetime.now()
                # TODO: fix this line - key['datetime'] is getting the string
                # indeced of the key instad of the value in the dict
                if timestamp - key['datetime'] > timedelta(minutes=10):
                    logger.debug('client is older than 10 minutes')
            setattr(current_app, 'local_client_dict', local_client_dict)

        # get access / refresh tokens
        try:
            token_response = client.oauth2_exchange_code_for_tokens(auth_code)
        except globus_sdk.services.auth.errors.AuthAPIError:
            return utils.error(
                msg = 'Invalid auth code given for client'
            )
        else:
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
        query = request.args
        access_token = query.get('access_token')
        refresh_token = query.get('refresh_token')
        
        # debug
        # logger.debug('have tokens')
        # logger.debug(access_token)
        # logger.debug(refresh_token)
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
            
















