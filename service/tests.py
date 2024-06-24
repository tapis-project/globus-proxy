import sys
import os
from datetime import datetime
import json
import requests
from typing import List
from functools import partial

# tapis
from tapisservice.tapisflask import utils
from tapisservice.logs import get_logger

# local
from utils import *
from controllers.auth import *


logger = get_logger(__name__)

class Base:
    config = None 
    cid = None 
    gcp_eid = None 
    ls6_eid = None
    frontera_eid = None 
    corral_eid = None
    source = None 
    at = None 
    rt = None 
    gcp_at = None
    gcp_rt = None
    base_url = None
    secret = None

    def __init__(self):
        self.config = self.load_config()

    def load_config(self):
        with open(os.path.join(f"{os.path.expanduser('~')}/gpsettings.json")) as file:
            self.config = json.loads(file.read())
            self.cid = self.config["client_id"]
            self.gcp_eid = self.config["kprice01_gcp_endpoint_id"]
            self.source_eid = "722751ce-1264-43b8-9160-a9272f746d78" # ESnet CERN DTN (Anonymous read-only testing)
            self.at = self.config["access_token"]
            self.rt = self.config["refresh_token"]
            self.gcp_at = self.config["gcp_at"]
            self.gcp_rt = self.config["gcp_rt"]
            self.base_url = self.config["base_url"]
            self.secret = self.config['client_secret']
            self.ls6_eid = self.config['ls6_endpoint_id']
            return self.config

# TODO: write setup / teardown functions that can be run by the tests indivudially so the success of one test isn't dependant on another
## setup / teardown
def make_dir(path):
    os.mkdir(path)

def rm_dir(path):
    os.rmdir(path)

## utils
def get_endpoint_test(epid):
    info = get_collection_type(epid)
    print(f'got ep info:: {info}')

def get_collection_id_test(client_id, client_secret, name):
    info = get_collection_id(client_id, client_secret, name)
    print(f'got ep id:: {info}')

def is_gcp_test(endpoint_id):
    res = is_gcp(endpoint_id)
    print(res)

# def get_gcp_auth_url_test(client_id, client_secret, endpoint_id=None)
#     print(f'about to fetch url for {endpoint_id} using client {client_id}')


def get_transfer_client_with_secret_test(client_id, client_secret, endpoint_id=None, addl_scopes=None):
    print(f'about to auth {client_id} with endpoint {endpoint_id} and scopes {addl_scopes}')
    tc = get_transfer_client_with_secret(client_id, client_secret, endpoint_id=endpoint_id, addl_scopes=addl_scopes)
    print(f'authd:: {tc}')

def build_scopes_test(scopes:list, eid=None):
    print(f'about to test building a scope')
    s_list = ['']
    scopes = build_scopes(s_list, collection_id=eid)

## ops    
def ls_test(base, path):
    url = f'{base.base_url}/ops/{base.cid}/{base.gcp_eid}/{path}'
    query = {"access_token": base.at,
             "refresh_token": base.rt}
    response = requests.get(url, params=query)
    if response.status_code != 200:
        raise Exception(f'{response.status_code}:: {response.text}')

def rm_test(base, path):
    pass

def mv_test(base, src, dest):
    logger.debug(f'trying mv with src {src}, and dest {dest}')
    url = f'{base.base_url}/ops/{base.cid}/{base.gcp_eid}/{src}'
    body = {"destination": f'\"{dest}\"'}
    query = {"access_token": base.at,
             "refresh_token": base.rt}
    
    response = requests.put(url, json=body, params=query)
    if response.status_code != 200:
        raise Exception(f'{response.status_code}:: {response.text}')

def mkdir_test(base, path):
    url = f'{base.base_url}/ops/{base.cid}/{base.gcp_eid}/{path}'
    body = {}
    query = {"access_token": base.at,
             "refresh_token": base.rt}
    response = requests.post(url, data=body, params=query)
    if response.status_code != 200:
        raise Exception(f'{response.status_code}:: {response.text}')

## transfers
def make_xfer_test(base):
    pass

def get_xfer_test(base):
    pass

def rm_xfer_test(base):
    pass

if __name__ == '__main__':
    base = Base()
    fails = {}
    base_path = os.path.expandvars('~')

    try:
        # base tests
        # try:
        #     get_endpoint_test(base.gcp_eid)
        # except Exception as e:
        #     print(e)
        #     fails['base_test_1'] = e
        # ls tests
        # try:
        #     ls_test(base, base_path)
        # except Exception as e:
        #     print(e)
        #     fails['ls_test_1'] = e
        # try:
        #     ls_test(base, f'{base_path}/test')
        # except Exception as e:
        #     print(e)
        #     fails['ls_test_2'] = e
        # try:
        #     ls_test(base, f'{base_path}/test.py')  
        # except Exception as e:
        #     print(e)
        #     fails['ls_test_3'] = e
        # # mkdir tests
        # try:
        #     mkdir_test(base, f'{base_path}/mkdirtest')
        # except Exception as e:
        #     print(e)
        #     fails['mkdir_test_1'] = e
        # # rename tests
        # try:
        #     mv_test(base, f'{base_path}/mkdirtest', f'{base_path}/mkdirtest2')
        # except Exception as e:
        #     print(e)
        #     fails['mv_test_1'] = e
        # # rm tests
        # try:
        #     rm_test(base, f'{base_path}/mkdirtest2')
        # except Exception as e:
        #     print(e)
        #     fails['rm_test_1'] = e
        
        try:
            client_id = base.cid
            client_secret = base.secret
            get_transfer_client_with_secret_test(client_id, client_secret)
        except Exception as e:
            print(e)
            fails['auth_test_1'] = e 

        try:
            client_id = base.cid
            client_secret = base.secret
            endpoint_id = base.ls6_eid
            get_transfer_client_with_secret_test(client_id, client_secret, endpoint_id=endpoint_id)
        except Exception as e:
            print(e)
            fails['auth_test_2'] = e 

        # try:
        #     client_id = base.cid
        #     client_secret = base.secret
        #     endpoint_id = base.gcp_eid
        #     get_gcp_auth_url_test(client_id, client_secret, endpoint_id=endpoint_id)
        # except Exception as e:
        #     print(e)
        #     fails['gcp_test_1'] = e 

        # try:
        #     client_id = base.cid
        #     client_secret = base.secret
        #     endpoint_id = base.ls6_eid
        #     addl_scopes = 'manage_projects'
        #     get_transfer_client_with_secret_test(client_id, client_secret, endpoint_id=endpoint_id, addl_scopes=addl_scopes)
        # except Exception as e:
        #     print(e)
        #     fails['auth_test_3'] = e         

    except Exception as e:
        print(f'Unknown error running tests:: {e}')
        exit(1)

    if len(fails) > 0:
        print(f'{len(fails)} tests failed::\n{fails}')
    else:
        print('All tests successful')
