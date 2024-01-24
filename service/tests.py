import sys
import os
from datetime import datetime
import json
import requests

# tapis
from tapisservice.tapisflask import utils

# local
from utils import *


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

def transfer_test():
    base = Base()

    data = {
        "source_endpoint": base.source_eid,
        "destination_endpoint": base.gcp_eid,
        "transfer_items": [

            {
                "source_path": "/1M.dat",
                "destination_path": "/home/kprice/tmp/globus_xfer/1M.dat",
                "recursive": "true"
            }
        ]
    }
    query = {
        "access_token": base.at,
        "refresh_token": base.rt
    }
    headers = {
        "Content-Type": "application/json"
    }

    try:
        response = requests.post(f"{base.base_url}/transfers/{base.cid}", json=data, params=query, headers=headers)
    except Exception as e:
        print(f'exception calling globus-proxy:: {e}')

    print(response.status_code)
    try:
        assert response.status_code == 200
    except AssertionError as e:
        print(f'assertion failed. Status code is {response.status_code}.\n\t{response.text}')
    
    task_id = response.json()['result']['task_id']
    logger.debug(f'Submitted transfer job with client {base.cid} and task id {task_id}')

    # poll for status of transfer
    exit = False
    runs = 0
    while not exit:
        response = requests.get(f'{base.base_url}/transfers/{base.cid}/{task_id}?access_token={base.at}&refresh_token={base.rt}')
        if not response.ok:
            continue ## this means we got some other bogus code so just try again
        logger.debug(f'got response:: {response.text}')
        response = response.json()
        status = None
        try:
            status = response['result']['status']
        except Exception as e:
            print(f'IDK bro {e}')
            exit = True

        if status == 'SUCCEEDED':
            logger.info('polling completed. Transfer success')
            exit = True
        elif runs == 10:
            exit = True
            logger.info(f'polling ran 10 times but didn\'t get success state. Bummer.')


def endpoint_test():
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

def ls_test():
    base = Base()
    try:
        tc = get_transfer_client(base.cid, base.rt, base.at)
        # print(f'have tc:: {tc}')
    except Exception as e:
        print(f'get tc fail! {e}')

    url = f'{base.base_url}/ops/{base.cid}/{base.gcp_eid}/~'
    query = {"access_token": base.at,
             "refresh_token": base.rt}
    logger.debug(f'have url:: {url} and params {query}')
    response = requests.get(url, params=query)
    logger.debug(response)
    logger.debug(response.text)

    

if __name__ == '__main__':
    # endpoint_test()
    transfer_test()
    ls_test()
