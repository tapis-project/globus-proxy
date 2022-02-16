import globus_sdk as globus

class AuthClient(object):
    """
    storage of a globus auth client for authentication using two endpoints
    """
    def __init__(self, client_id, client):
        self.client_id = client_id
        self.client = client

