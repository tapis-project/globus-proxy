
import os
from flask import Flask
from tapisservice.tapisflask.resources import HelloResource, ReadyResource
from tapisservice.tapisflask.utils import TapisApi, flask_errors_dict

# from service.controllers import AuthURLResource, TokensResource
from service.controllers import *
# from service import app
app = Flask(__name__)
app.secret_key = os.urandom(16)

# flask api
api = TapisApi(app, errors=flask_errors_dict)

# error handling
# TODO

# Resources
api.add_resource(AuthURLResource, '/v3/globus-proxy/auth/url/<client_id>')
api.add_resource(TokensResource, '/v3/globus-proxy/auth/tokens/<uuid>/<auth_code>')
# api.add_resource(TestResource.post, '/v3/globus-proxy/auth/test/<client_id>')
# api.add_resource(TestResource.put, '/v3/globus-proxy/auth/test/<auth_code>')

# Health checks
api.add_resource(ReadyResource, '/v3/globus-proxy/ready')
api.add_resource(HelloResource, '/v3/globus-proxy/hello')
# api.add_resource(TestResource, '/v3/globus-proxy/test')
