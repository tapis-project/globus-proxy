from tapisservice.tapisflask.resources import HelloResource, ReadyResource

# flask api
api = TapisApi(app, errors=flask_errors_dict)

# error handling
# TODO

# Resources

# Health checks
api.add_resource(ReadyResource, '/v3/globus-proxy/ready')
api.add_resource(HelloResource, '/v3/globus-proxy/hello')
