from flask import g, request
from tapisservice.config import conf
from tapisservice import auth
from tapisservice import tapisflask
from tapisservice import errors as common_errors
from tapisservice.tenants import TenantCache

# get the logger instance -
from tapisservice.logs import get_logger
logger = get_logger(__name__)


def authn_and_authz():
    """
    Entry point for checking authentication and authorization for all requests to the authenticator.
    :return:
    """
   # skip_sk = False
    authentication()
    #authorization(skip_sk)

def authentication():
    """
    Entry point for checking authentication for all requests to the authenticator.
    :return:
    """
    # The tenants API has both public endpoints that do not require a token as well as endpoints that require
    # authorization.
    # we always try to call the primary tapis authentication function to add authentication information to the
    # thread-local. If it fails due to a missing token, we then check if there is a public endpoint
    logger.debug(request.headers)
    try:
        tapisflask.auth.authentication()
        logger.debug(f"Threadlocal tenant id: "+str(conf.tenant[g.tenant_id]))
    except common_errors.NoTokenError as e:
            logger.debug(f"Caught NoTokenError: {e}")
            g.no_token = True
            g.username = None
            g.tenant_id = None

            if request.method == 'GET' and (request.endpoint == 'helloresource' or request.endpoint == 'readyresource'):
                return True

            # to check the health of service we pass tenant_id as query parameter
            if request.method == 'GET' and (request.endpoint == 'healthcheckresource'):
                g.tenant_id = request.args.get('tenant')
                logger.debug(f"Threadlocal tenant id: "+str(g.tenant_id))
                return True

# this is the Tapis client that tenants will use for interacting with other services, such as the security kernel.
Tenants = TenantCache()
t = auth.get_service_tapis_client(tenant_id=conf.service_tenant_id, tenants=Tenants)
logger.debug(t.service_tokens)
t.x_username = conf.streams_user