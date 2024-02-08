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


logger = get_logger(__name__)

class Base:
    config = None 
    cid = None 
    gcp_eid = None 
    source = None 
    at = None 
    rt = None 
    base_url = None

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
            self.base_url = self.config["base_url"]
            return self.config


def get_endpoint_test():
    base = Base()
    try:
        tc = get_transfer_client(base.cid, base.rt, base.at)
        # print(f'have tc:: {tc}')
    except Exception as e:
        print(f'get tc fail! {e}')

    try:
        info = tc.get_endpoint(base.gcp_eid)
        print(info)
    except Exception as e:
        print(f'get endpoint fail! {e}')
    
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
        # ls tests
        try:
            ls_test(base, base_path)
        except Exception as e:
            print(e)
            fails['ls_test_1'] = e
        try:
            ls_test(base, f'{base_path}/test')
        except Exception as e:
            print(e)
            fails['ls_test_2'] = e
        try:
            ls_test(base, f'{base_path}/test.py')  
        except Exception as e:
            print(e)
            fails['ls_test_3'] = e
        # mkdir tests
        try:
            mkdir_test(base, f'{base_path}/mkdirtest')
        except Exception as e:
            print(e)
            fails['mkdir_test_1'] = e
        # rename tests
        try:
            mv_test(base, f'{base_path}/mkdirtest', f'{base_path}/mkdirtest2')
        except Exception as e:
            print(e)
            fails['mv_test_1'] = e
        # rm tests
        try:
            rm_test(base, f'{base_path}/mkdirtest2')
        except Exception as e:
            print(e)
            fails['rm_test_1'] = e
        

    except Exception as e:
        print(f'Unknown error running tests:: {e}')
        exit(1)

    if len(fails) > 0:
        print(f'{len(fails)} tests failed::\n{fails}')
    else:
        print('All tests successful')
