from flask_restful import Resource
from flask import Flask, request
from tapisservice.errors import AuthenticationError, BaseTapisError

import globus_sdk
from globus_sdk import TransferAPIError

from utils import *
from errors import *

logger = get_logger(__name__)
app = Flask(__name__)


class TransferResource(Resource):
    def post(self, client_id):
        logger.info(f'Beginning creation of transfer task for client: {client_id} with args: {request.args} and json: {request.json}')
        # logger.debug(f'request headers:: {request.headers}')
        # logger.debug(f'request json:: {request.json}')

        # setup
        access_token = None
        refresh_token = None
        src = None
        dest = None
        items = None

        ## parse args
        try:
            access_token = request.args.get('access_token')
            assert access_token is not None 
        except AssertionError:
            logger.error('Missing required access_token param')
            raise handle_transfer_error(GlobusInvalidRequestError(msg='Invalid request: Missing access_token'))
        try:
            refresh_token = request.args.get('refresh_token')
            assert refresh_token is not None
        except AssertionError:
            logger.error('Missing required refresh_token param')
            raise handle_transfer_error(GlobusInvalidRequestError(msg='Invalid request: Missing refresh token'))
        if request.json is None:
            logger.error('Missing required transfer data')
            raise handle_transfer_error(GlobusInvalidRequestError(msg='Invalid request: Missing required transfer data'))

        ## parse transfer data
        try:
            # access_token = request.args.get('access_token')
            # refresh_token = request.args.get('refresh_token')
            src = request.json.get('source_endpoint')
            dest = request.json.get('destination_endpoint')
            items = request.json.get('transfer_items')
        except Exception as e:
            logger.error(f'Error parsing args for request:: {e}')

        # logger.debug(f'have setup args \naccess_token: {access_token}\nrefresh_token: {refresh_token}\nsrc: {src}\ndest: {dest}\nitems: {items}\n')

        if not access_token or not refresh_token:
            logger.error('error parsing args')
            raise AuthenticationError(msg='Exception while parsing request parameters. Please check your request syntax and try again')

        ## get xfer client
        transfer_client = None
        try:
            transfer_client = precheck(client_id, [src, dest], access_token, refresh_token)
            logger.debug(f'have tc:: {transfer_client}')
        except TransferAPIError as e:
            logger.error(f'got TransferAPIError trying to submit transfer job:: {e}')
            raise handle_transfer_error(e.http_reason)
        except GlobusError as e:
            raise handle_transfer_error(e)
        except Exception as e:
            logger.error(f'failed to authenticate transfer client :: {e}')
            # raise InternalServerError(msg='Failed to authenticate transfer client')
            raise handle_transfer_error(e)

        ## perform request
        result = (transfer(transfer_client, src, dest, items))
        if "File Transfer Failed" in result:
            logger.error(f'File transfer failed due to {result}')
            raise GlobusError(msg='File transfer failed')

        logger.info(f'Successful transfer for client {client_id} from {src} to {dest}')
        return utils.ok(
            result=result.data,
            msg=f'Success'
        )

class ModifyTransferResource(Resource):
    # TODO: 
    # Make sure tokens are valid
    # 
    def get(self, client_id, task_id):
        access_token = request.args.get('access_token')
        refresh_token = request.args.get('refresh_token')

        try:
            # transfer_client = get_transfer_client(client_id, refresh_token, access_token)
            transfer_client = precheck(client_id, None, access_token, refresh_token)
        except Exception as e:
            logger.error(f'error while getting transfer client for client id {client_id}: {e}')
            # raise InternalServerError(msg='Error while authenticating globus client')
            raise handle_transfer_error(e)
        try:
            result = transfer_client.get_task(task_id)
        except Exception as e:
            logger.error(f'error while getting transfer task with id {task_id}: {e}')
            # raise InternalServerError(msg='Error retrieving transfer task')
            raise handle_transfer_error(e)
        logger.info(f'Successful modify with client {client_id} of task {task_id}')
        return utils.ok(
            result=result.data,
            msg='successfully retrieved transfer task'
        )
        

    def delete(self, client_id, task_id):
        access_token = request.args.get('access_token')
        refresh_token = request.args.get('refresh_token')

        try:
            # transfer_client = get_transfer_client(client_id, refresh_token, access_token)
            transfer_client = precheck(client_id, None, access_token, refresh_token)
        except Exception as e:
            logger.error(f'error while getting transfer client for client id {client_id}: {e}')
            raise AuthenticationError(msg='Error while authenticating globus client')
        try:
            result = transfer_client.cancel_task(task_id)
        except Exception as e:
            logger.error(f'error while canceling transfer task with id {task_id}: {e}')
            # raise AuthenticationError(msg='Error retrieving transfer task')
            raise handle_transfer_error(e)
        logger.info(f'Successful delete with client {client_id} of task {task_id}')
        return utils.ok(
            result=result.data,
            msg='successfully canceled transfer task'
        )
