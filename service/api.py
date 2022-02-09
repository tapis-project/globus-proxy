from flask import Flask
from tapisservice.tapisflask.resources import HelloResource, ReadyResource
from tapisservice.tapisflask.utils import TapisApi, flask_errors_dict

# from service import app
app = Flask(__name__)

# flask api
api = TapisApi(app, errors=flask_errors_dict)

# error handling
# TODO

# Resources

# Health checks
api.add_resource(ReadyResource, '/v3/globus-proxy/ready')
api.add_resource(HelloResource, '/v3/globus-proxy/hello')
