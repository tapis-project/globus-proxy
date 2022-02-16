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
        # init globus_sdk client
        client = globus_sdk.NativeAppAuthClient(client_id)
        client.oauth2_start_flow(refresh_tokens=True)
        client_uuid = uuid.uuid4()

        # save client in memory
        local_client_uuid = locals()['client_uuid']
        setattr(current_app, str(client_uuid), client)

        authorize_url = client.oauth2_get_authorize_url()
        return utils.ok(
                result = {"url": authorize_url, "uuid": client_uuid}, 
                msg = f'Please go to this URL and login: {authorize_url}')

class TokensResource(Resource):
    """
    exchange auth code for access and refresh tokens
    """
    def get(self, uuid, auth_code):
        # retrieve client from memory
        client = getattr(current_app, uuid)

        # get access / refresh tokens
        token_response = client.oauth2_exchange_code_for_tokens(auth_code)
        access_token = token_response['access_token']
        refresh_token = token_response['refresh_token']
        
        return utils.ok(
                result = {"access_token": access_token, "refresh_token": refresh_token}, 
                msg = "successfully authorized globus client") 

