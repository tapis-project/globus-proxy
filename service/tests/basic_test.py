from base64 import b64encode
import pytest
import json
from unittest import TestCase
from service.api import app
from tapisservice import auth
from tapisservice.config import conf

# These tests are intended to be run locally.

@pytest.fixture
def client():
    app.debug = True
    return app.test_client()


def get_basic_auth_header():
    user_pass = bytes(f"tenants:{conf.allservices_password}", 'utf-8')
    return {'Authorization': 'Basic {}'.format(b64encode(user_pass).decode()),
            'X-Tapis-Tenant': 'admin'}


# healthchecks
def test_healthcheck(client):
    with client:
        response = client.get(
            "http://localhost:5000/v3/globus-sdk/healthcheck",
            content_type='application/json',
            headers=get_basic_auth_header()
        )
        print(f"response.data: {response.data}")
        assert response.status_code == 200
