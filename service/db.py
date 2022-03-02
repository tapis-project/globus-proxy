from datetime import datetime, timedelta
import logging
import redis

from tapisservice.config import conf


def get_redis_connection():
    return redis.StrictRedis(
            host=conf.redis_host, 
            port=conf.redis_port,
            password=''
        )


# db access
client_store = get_redis_connection()

def check_for_session(client_uuid):
    """
    looks into db to find an active auth flow session client object
    if none found, raises keyerror
    """
    try:
        client = client_store.get(cleint_uuid = client_uuid)
    except Exception as e:
        logging.critical(f'Got exception trying to check database for active client. e: {e}')
    return client

def add_client_to_store(client_uuid, client):
    """
    Adds client to the store, using a given uuid as the key
    """
