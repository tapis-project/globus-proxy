
import os
from flask import Flask
from werkzeug.routing import BaseConverter
from tapisservice.tapisflask.resources import HelloResource, ReadyResource
from tapisservice.tapisflask.utils import TapisApi, flask_errors_dict, handle_error

# from service.controllers import AuthURLResource, TokensResource
# from service.controllers import *
from controllers import *
# from service import app
app = Flask(__name__)
app.secret_key = os.urandom(16)

class RegexConverter(BaseConverter):
    def __init__(self, url_map, *items):
        super(RegexConverter, self).__init__(url_map)
        self.regex = items[0]

# flask api
api = TapisApi(app, errors=flask_errors_dict)
app.url_map.converters['regex'] = RegexConverter

# Set up error handling
api.handle_error = handle_error
api.handle_exception = handle_error
api.handle_user_exception = handle_error

# Resources
api.add_resource(AuthURLResource, '/v3/globus-proxy/auth/url/<client_id>')
api.add_resource(TokensResource, '/v3/globus-proxy/auth/tokens/<client_id>/<session_id>/<auth_code>')
api.add_resource(CheckTokensResource, '/v3/globus-proxy/auth/check_tokens/<endpoint_id>')
api.add_resource(OpsResource, '/v3/globus-proxy/ops/<client_id>/<endpoint_id>/<regex("(.+)"):path>')

# transfer resourced are separated due to inconsistent url pattern
api.add_resource(TransferResource, '/v3/globus-proxy/transfers/<client_id>')
api.add_resource(ModifyTransferResource, '/v3/globus-proxy/transfers/<client_id>/<task_id>')


# Health checks
api.add_resource(ReadyResource, '/v3/globus-proxy/ready')
api.add_resource(HealthcheckResource, '/v3/globus-proxy/healthcheck')
api.add_resource(HelloResource, '/v3/globus-proxy/hello')
