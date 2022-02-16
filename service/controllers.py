import os
import uuid

from flask import Flask, current_app
from flask_restful import Resource
from models import AuthClient

from tapisservice.tapisflask import utils
from tapisservice.logs import get_logger

import globus_sdk

logger = get_logger(__name__)
app = Flask(__name__)



class TestResource(Resource):
    """
    A simple test to make sure the service is running, avoiding the built-in functions
    """
    def get(self):
        logger.debug("starting test resource response")
        return utils.ok(result='200', msg="service has passed the test")

class AuthURLResource(Resource):
    """
    receive tokens using oauth2 
    """
    def get(self, client_id):
        logger.debug("in get for tokens resource")
        client = globus_sdk.NativeAppAuthClient(client_id)
        client.oauth2_start_flow(refresh_tokens=True)
        client_uuid = uuid.uuid4()
        local_client_uuid = locals()['client_uuid']
        # current_app.locals()['client_id'] = client
        setattr(current_app, str(client_uuid), client)
        logger.debug(f'in url ep, have current_app = {getattr(current_app, str(client_uuid))}')

        authorize_url = client.oauth2_get_authorize_url()
        # print("Please go to this URL and login: {0}".format(authorize_url))
        # return a uuid for use on the second endpoint
        return utils.ok(result = {"url": authorize_url, "uuid": client_uuid}, msg = f'Please go to this URL and login: {authorize_url}')

class TokensResource(Resource):
    """
    exchange auth code for access and refresh tokens
    """
    def get(self, uuid, auth_code):
        # TODO: use the uuid from the first 
        client = getattr(current_app, uuid)
        logger.debug(f'have client:: {client}')
        
        # client.oauth2_start_flow(refresh_tokens=True)
        token_response = client.oauth2_exchange_code_for_tokens(auth_code)
        logger.debug('got token response', token_response)
        access_token = token_response['access_token']
        refresh_token = token_response['refresh_token']
        return utils.ok(result = {"access_token": access_token, "refresh_token": refresh_token}, msg = "successfully authorized globus client") 

