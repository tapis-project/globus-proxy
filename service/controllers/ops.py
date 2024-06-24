import os
from functools import partial
from typing import List

from flask_restful import Resource
from flask import Flask, request
from tapisservice.errors import AuthenticationError, BaseTapisError

import globus_sdk
from globus_sdk import TransferAPIError
from globus_sdk.experimental.auth_requirements_error import GlobusAuthRequirementsError

from utils import *
from errors import *

logger = get_logger(__name__)
app = Flask(__name__)


class OpsResource(Resource):
                
    def retry(
        self,
        fn: partial,
        attempts=0,
        max_attempts=1,
        reraise: List[Exception] = []
    ):
        try:
            result = fn()
            if result.http_status != 200:
                raise Exception(f"Expected http status code 200 | Recieved {str(result.http_status)}")
            return result
        except Exception as e:
            if type(e) in reraise:
                logger.debug(f"Re-raising exception | {e}")
                raise e
            logger.warn(f"Error while retrying: {str(e)}")
            attempts += 1
            if attempts == max_attempts:
                logger.error(f"Error: Max retries reached | Last Error: {e}")
                raise e
            
            return self.retry(fn, attempts=attempts, max_attempts=max_attempts, reraise=reraise)
        

    # ls
    def do_ls(self, transfer_client, endpoint_id, path, filter_, query_dict):
        logger.debug(f'in do_ls with {endpoint_id} {path} {filter_} {query_dict}')
        result = None
        try:
            result = transfer_client.operation_ls(
                endpoint_id=(endpoint_id),
                path=path,
                show_hidden=False,
                filter=filter_,
                query_params=query_dict if query_dict != {} else None
            )
        except globus_sdk.TransferAPIError as e:
            if e.code == 'ConsentRequired':
                pass # TODO
            logger.debug(f'Got transfer api error in do_ls {e.code}\n\t{e}')
            raise e
        except Exception as e:
            logger.error(f'exception while doing ls:: {e}')
            raise e
        
        if not result: 
            logger.debug(f'ls operation returned no results with path {path}, filter {filter_}, and query {query_dict}')
        else:
            logger.debug(f'ls operation returned result {result.http_status}')
        return result

    def get(self, client_id, endpoint_id, path):
        # parse args & perform precheck
        path = format_path(path)
        logger.debug(f'beginning ls with client:: {client_id} & path:: {path}')
        transfer_client = None
        access_token = request.args.get('access_token')
        refresh_token = request.args.get('refresh_token')
        query_dict = {
            "limit": request.args.get('limit'),
            "offset": request.args.get('offset')
        }
        filter_ = request.args.get('filter')

        try:
            transfer_client = precheck(client_id, endpoint_id, access_token, refresh_token)
        except PythonAuthenticationError:
            logger.error(f'Invalid token given for client {client_id}')
            msg='Access token invalid. Please provide valid token.'
            raise AuthenticationError(msg=msg, code=401)

        # perform ls op
        logger.debug(f"performing ls with client {client_id} on endpoint {endpoint_id} and path {path}")
        
        list_files_op = partial(
            self.do_ls,
            transfer_client=transfer_client,
            endpoint_id=endpoint_id,
            path=path,
            filter_=filter_,
            query_dict=query_dict
        )
        try:
            result = self.retry(list_files_op, max_attempts=5, reraise=[TransferAPIError])
        except TransferAPIError as e:
            logger.debug(f'encountered {e.code} while checking {path}')
            if e.code == 'ExternalError.DirListingFailed.NotDirectory':
                print('got not directory error - trying parent dir')
                # requested object is not a dir - assume single file instead

                parent_dir, filename = os.path.split(path)
                # If parent dir is empty string, assume it's root
                parent_dir = parent_dir or "/"
                logger.debug(f'trying single file filter "name:{filename}" on parent dir "{parent_dir}" / filename "{filename}"')
                list_files_op = partial(
                    self.do_ls,
                    transfer_client=transfer_client,
                    endpoint_id=endpoint_id,
                    path=parent_dir,
                    filter_=f'name:{filename}',
                    query_dict=query_dict
                )

                result = self.retry(list_files_op, max_attempts=5)

                return utils.ok(
                    msg='Successfully listed files',
                    result=result.data,
                    metadata={'access_token': access_token}
                )
            
            raise handle_transfer_error(e)
        except GlobusAuthRequirementsError as e:
            logger.error(f'Got Globus auth requirements error in GET: {e}')
            raise handle_transfer_error(e)
        except Exception as e:
            logger.error(f'this should not print. You got:: {e}')
            raise handle_transfer_error(e)
        # TODO: if the tokens get refreshed live, we could have a race condition 
        # figure out a way to test if refreshed access tokens will cause a call to fail
            # especially for concurrent ops
        # logger.debug(f'result is {result}')
        logger.info(f'Successfully listed files on path:: {path} for client: {client_id}')
        return utils.ok(
            msg='Successfully listed files',
            result=result.data,
            metadata={'access_token': access_token}
        )

    # mkdir
    def do_mkdir(self, transfer_client, endpoint_id, path):
        logger.debug(f'In do_mkdir with {endpoint_id}:{path}')
        result = transfer_client.operation_mkdir(
                endpoint_id=endpoint_id,
                path=path
            )
        return result

    def post(self, client_id, endpoint_id, path):
        # parse args and perform precheck
        logger.debug(f'in mkdir, have path:: {path}')
        transfer_client = None
        access_token = request.args.get('access_token')
        refresh_token = request.args.get('refresh_token')

        if not access_token or not refresh_token:
            logger.error(f'error parsing args for client {client_id}')
            raise AuthenticationError(msg='Exception while parsing request parameters. Please check your request syntax and try again')

        try:
            transfer_client = precheck(client_id, endpoint_id, access_token, refresh_token)
        except PythonAuthenticationError:
            logger.error(f'Invalid token given for client {client_id}')
            raise AuthenticationError(msg='Given tokens are not valid. Try again with active auth tokens')
        except TransferAPIError as e:
            logger.error(f'transfer api error for client {client_id}: {e}, code:: {e.code}')
            # api errors come through as specific codes, each one can be handled separately
            raise handle_transfer_error(e)
        except Exception as e:
            logger.error(f'exception performing mkdir for client {client_id} at path {path}:: {e}')
            raise InternalServerError(msg=f"Unkown error performing mkdir at path {path}. Please check request syntax and try again.")

        # perform mkdir op
        try:
            result = self.do_mkdir(transfer_client, endpoint_id, path)
        except TransferAPIError as e:
            logger.error(f'transfer api error for client {client_id}: {e}, code:: {e.code}')
            # api errors come through as specific codes, each one can be handled separately
            raise handle_transfer_error(e)
            # TODO: handle intermediate folder creation? e.g. path/to/thing instead of path/
        except Exception as e:
            logger.error(f'exception while performing mkdir operation for client {client_id} at path {path}:: {e}')
            raise InternalServerError(msg=f'Unknown error while performing mkdir operation at path {path}')
        
        logger.info(f'successfull mkdir for client {client_id} at path {path}')
        return utils.ok(
            msg=f'Successfully created directory at {path}',
            result=result.data,
            metadata={'access_token': access_token}
        )

    # delete
    def do_delete(self, transfer_client, delete_task):
        result = transfer_client.submit_delete(delete_task)
        return result

    def delete(self, client_id, endpoint_id, path):
        # parse args and perform precheck
        logger.debug(f'in delete, have path:: {path}')
        transfer_client = None
        access_token = request.args.get('access_token')
        refresh_token = request.args.get('refresh_token')
        recurse = request.args.get('recurse', False)

        if not access_token or not refresh_token:
            logger.error('error parsing args')
            raise AuthenticationError(msg='Exception while parsing request parameters. Please check your request syntax and try again')

        try:
            transfer_client = precheck(client_id, endpoint_id, access_token, refresh_token)
        except PythonAuthenticationError:
            logger.error(f'Invalid token given for client {client_id}')
            raise AuthenticationError(msg='Given tokens are not valid. Try again with active auth tokens')
        except Exception as e:
            logger.error(f'exception while performing delete operation for client {client_id} at path {path}:: {e}')
            raise InternalServerError()
            # TODO: handle more exceptions?
            

        # perform delete
        try:
            delete_task = globus_sdk.DeleteData(
                transfer_client=transfer_client,
                endpoint=endpoint_id,
                recursive=bool(recurse)
            )
            delete_task.add_item(path)
            logger.debug(f'have delete task:: {delete_task}')
            # result = transfer_client.submit_delete(delete_task)
            result = self.do_delete(transfer_client, delete_task)
        except TransferAPIError as e:
            logger.error(f'transfer api error for client {client_id}: {e}, code:: {e.code}')
            # api errors come through as specific codes, each one can be handled separately
            raise handle_transfer_error(e)
        except Exception as e:
        # TODO: make sure path exists on endpoint
            logger.error(f'exception while performing delete operation for client {client_id} at path {path}:: {e}')
            raise InternalServerError()
        logger.info(f'Successful delete for client {client_id} at path {path}')
        return utils.ok(
            result=result.data,
            msg='Success'
        )


    # rename
    def do_rename(self, transfer_client, endpoint_id, oldpath, newpath):
        result = transfer_client.operation_rename(endpoint_id, oldpath=oldpath, newpath=newpath)
        return result

    def put(self, client_id, endpoint_id, path):
        logger.debug(f'In rename op with client {client_id}, endpoint {endpoint_id}, and oldpath {path}')
        # parse args and perform precheck
        transfer_client = None
        logger.debug(f'args:: {request.args}\njson:: {request.json}')
        access_token = request.args.get('access_token')
        refresh_token = request.args.get('refresh_token')
        dest = request.json.get('destination')

        if not access_token or not refresh_token:
            logger.error('error parsing args')
            raise AuthenticationError(msg='Exception while parsing request parameters. Please check your request syntax and try again')

        try:
            transfer_client = precheck(client_id, endpoint_id, access_token, refresh_token)
        except PythonAuthenticationError:
            logger.error(f'Invalid token given for client {client_id}')
            raise AuthenticationError(msg='Given tokens are not valid. Try again with active auth tokens')
        except Exception as e:
            return utils.error(f'exception while performing rename operation for client {client_id} at path {path}:: {e}')
            # TODO: handle more exceptions?

        # perform rename
        try:
            # result = transfer_client.operation_rename(endpoint_id, oldpath=path, newpath=dest)
            result = self.do_rename(transfer_client, endpoint_id, path, dest)
        except TransferAPIError as e:
            logger.error(f'transfer api error for client {client_id}: {e}, code:: {e.code}')
            if e.code == 'EndpointError':
                logger.error(f'e code is endpoint error. text is {e.text} \nand reason is {e.http_reason} \nand message is {e.message}')
                if 'No such file or directory' in e.text:
                    raise handle_transfer_error(PathNotFoundError())
                if e.http_reason == 'PATH_NOT_FOUND':
                    raise handle_transfer_error(PathNotFoundError())
                else:
                    logger.error(f'exception code is endpoint error but "No such file or directory" not in exception text')
            logger.error(f'bro idk whats going on here')
            raise handle_transfer_error(e)
        except Exception as e:
            logger.error(f'exception in rename with client {client_id}, endpoint {endpoint_id} and path {path}:: {e}')
            raise handle_transfer_error(e)
        logger.info(f'Successful rename for client {client_id} at path {path}')
        return utils.ok(
            msg=f'Success',
            result = result.data
        )
