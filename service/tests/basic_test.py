from base64 import b64encode
import pytest
import json
from unittest import TestCase
from flask import Flask
# from service.api import app
from tapisservice import auth
from tapisservice.config import conf

# These tests are intended to be run locally.

@pytest.fixture
def client():
    app = Flask(__name__)
    app.debug = True
    return app.test_client()


def get_basic_auth_header():
    user_pass = bytes(f"tenants:{conf.allservices_password}", 'utf-8')
    return {'Authorization': 'Basic {}'.format(b64encode(user_pass).decode()),
            'X-Tapis-Tenant': 'admin'}


# healthchecks
# def test_healthcheck(client):
#     with client:
#         response = client.get(
#             "http://localhost:5000/v3/globus-proxy/healthcheck",
#             content_type='application/json',
#             # headers=get_basic_auth_header()
#         )
#         print(f"response.data: {response.data}")
#         assert response.status_code == 200


def test_ls(client):
    with client:
        base_url = "http://localhost:5000/v3/globus-proxy/ops/"
        client_id = "64e62ddd-9a10-42c4-823e-411f77bfa265"
        endpoint_id = "1515bf28-9fb5-11ec-bf8a-ab28bf5d96bb"
        path = "."
        access_token = "Agy2gd1P59bNPzO8DQBVmpqjqeQxY2qKV5wa7kxp2qk5qK1OJVSVCJq82kwdN4W5Y5GYMwOVqdQkB1tOmk7MYC7dWx"
        refresh_token="Ag13xjBG1o3Xzxj4rvvEEDlwJjyBoV1VK93NOnXxPNnVlKW6MgHNUpkMkQmD7MW2XPo5wgO41eBqeX20MyO8apYk8Dbnp"
        
        request_url = f'{base_url}/{client_id}/{endpoint_id}/{path}?access_token={access_token}&refresh_token={refresh_token}'
        print(f'request:: {request_url}')

        response = client.get(
            request_url
        )
        print(f'got response :: {response}')
        assert response.status_code == 200