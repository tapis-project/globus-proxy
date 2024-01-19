import sys
import os
from datetime import datetime
import json
import requests
from tapisservice.tapisflask import utils
from utils import *


class Base:
    config = None 
    cid = None 
    gcp_eid = None 
    source = None 
    at = None 
    rt = None 

    def __init__(self):
        config = self.load_config()

    def load_config(self):
        with open(os.path.join(f"{os.path.expanduser('~')}/gpsettings.json")) as file:
            self.config = json.loads(file.read())
            self.cid = self.config["client_id"]
            self.gcp_eid = self.config["kprice01_gcp_endpoint_id"]
            self.source_eid = "722751ce-1264-43b8-9160-a9272f746d78" # ESnet CERN DTN (Anonymous read-only testing)
            self.at = self.config["access_token"]
            self.rt = self.config["refresh_token"]
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
        response = requests.post(f"https://dev.kprice01.tacc.utexas.edu/v3/globus-proxy/transfers/{base.cid}", json=data, params=query, headers=headers)
    except Exception as e:
        print(f'exception calling globus-proxy:: {e}')

    print(response.status_code)
    try:
        assert response.status_code == 200
    except AssertionError as e:
        print(f'assertion failed. Status code is {response.status_code}.\n\t{response}')


def endpoint_test():
    base = Base()
    try:
        tc = get_transfer_client(base.cid, base.rt, base.at)
        # print(f'have tc:: {tc}')
        info = tc.get_endpoint(base.cid)
        print(info)
    except Exception as e:
        print(f'fail! {e}')

if __name__ == '__main__':
    endpoint_test()
