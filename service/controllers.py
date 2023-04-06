from ast import Pass
from distutils.log import error
import json
from os import access
import traceback

from flask import Flask, current_app, request
from flask_restful import Resource

from tapisservice.tapisflask import utils
from tapisservice.tapisflask.resources import ReadyResource
from tapisservice.logs import get_logger
from tapisservice.errors import AuthenticationError

import globus_sdk
from globus_sdk import TransferAPIError

from utils import check_tokens, get_transfer_client, precheck, transfer, is_endpoint_activated, autoactivate_endpoint
from errors import InternalServerError

from multiprocessing import AuthenticationError as PythonAuthenticationError

logger = get_logger(__name__)
app = Flask(__name__)


class HealthcheckResource(ReadyResource):
    pass

class AuthURLResource(Resource):
    """
    Return authorization URL given client Id
    """

    def get(self, client_id):
        # TODO: a call to get_identities needs to be authenticated
        # there might not be a way to figure out if the client_id 
        # is valid or not without letting the user go to the url and find out
        try:
            client = globus_sdk.NativeAppAuthClient(client_id)
        except Exception as e:
            msg = f'Encountered exception while initializing globus_sdk for client {client_id}\n\t{e}'
            logger.error(msg)
            raise InternalServerError(msg=msg)
        session_client = client.oauth2_start_flow(refresh_tokens=True)
        authorize_url = client.oauth2_get_authorize_url()
        logger.debug(f"successfully got auth url for client {client_id}")
        return utils.ok(
                result = {"url": authorize_url, "session_id": session_client.verifier}, 
                msg = f'Please go to the URL and login'
            )
 
class TokensResource(Resource):
    """
    exchange client_id, session_id, & auth code for access and refresh tokens
    """

    def get(self, client_id, session_id, auth_code):

        try:
            client = globus_sdk.NativeAppAuthClient(client_id)
            session_client = client.oauth2_start_flow(verifier=session_id)
        except Exception as e:
            msg = f'Encountered exception while initializing globus_sdk with client id:: {client_id}\n\t{e}\n\t'
            logger.error(msg)
            raise InternalServerError(msg=msg)


        # get access / refresh tokens
        try:
            token_response = client.oauth2_exchange_code_for_tokens(auth_code).by_resource_server
        except globus_sdk.services.auth.errors.AuthAPIError:
            msg = f'Invalid auth code given for client {client_id}'
            logger.error(msg)
            raise AuthenticationError(msg=msg, code=500)
        else:
            try:
                access_token = token_response['transfer.api.globus.org']['access_token']
                refresh_token = token_response['transfer.api.globus.org']['refresh_token']
            except KeyError as e:
                msg = f'Could not parse tokens from response:: {e}'
                logger.error(msg)
                raise InternalServerError(msg=msg)
        
        return utils.ok(
                result = {"access_token": access_token, "refresh_token": refresh_token}, 
                msg = "successfully authorized globus client"
              ) 

class CheckTokensResource(Resource):
    """
    check validity of auth / refresh tokens and exchange if needed
    """

    def get(self, endpoint_id):
        access_token = request.args.get('access_token')
        refresh_token = request.args.get('refresh_token')

        if access_token is None or refresh_token is None:
            return utils.error(
                msg = 'Access token and refresh token must be provided as query parameters'
            )

        # check access token
        # check refresh token
        # if access token is valid but refresh is not, return access token
        # if access token is invalid but refresh token is valid, get new token
        # if access token and refresh token is invalid, error

        ac_token = ''
        rf_token = ''

        # check if given tokens are valid
        client = globus_sdk.NativeAppAuthClient(endpoint_id)
        try:
            ac_response = client.oauth2_validate_token(access_token)
            rf_response = client.oauth2_validate_token(refresh_token)
        except:
            logger.debug('Unknown error checking validity of tokens')
            return utils.error(
                msg = 'Unable to check validity of given tokens'
            )
        else:
            logger.debug(f'ac:: {ac_response}')
            logger.debug(f'rf:: {rf_response}')
            ac_token = access_token if ac_response['active'] == True else None
            rf_token = refresh_token if rf_response['active'] == True else None

        # if either token is none, get new tokens
        if ac_token is None or rf_token is None:
            try:
                refresh_response = client.oauth2_refresh_token(str(refresh_token))
            except:
                logger.debug('Unknown error generating new tokens. Please try again later.')
            else:
                logger.debug(f'have token response:: {refresh_response}')
                return utils.ok(
                    msg = 'Successfully refreshed tokens',
                    result = {"access_token": refresh_response['access_token'], "refresh_token": rf_token}
                )

        return utils.ok(
                result = {"access_token": ac_token, "refresh_token": rf_token},
                msg = 'Successfully validated tokens'
              )
            

class OpsResource(Resource):

    def handle_transfer_error(code):
        if code == "AuthenticationFailed":
            raise AuthenticationError(msg='Could not authenticate transfer client', code=401)
        elif code == "ClientError.NotFound":
            raise PathNotFoundError(msg='Path does not exist on given endpoint', code=404)
        elif code == "ExternalError.DirListingFailed.GCDisconnected":
            raise GlobusError(msg=f'Error connecting to endpoint {endpoint_id}. Please activate endpoint manually', code=407)

    # ls
    def get(self, client_id, endpoint_id, path):
        # parse args & perform precheck
        logger.debug(f'beginning ls with client:: {client_id} & path:: {path}')
        transfer_client = None
        access_token = request.args.get('access_token')
        refresh_token = request.args.get('refresh_token')
        limit = request.args.get('limit')
        offset = request.args.get('offset')
        filter = request.args.get('filter')

        if not access_token or not refresh_token:
            msg='Could not parse token from request parameters. Please provide valid token.'
            logger.error(f'error parsing tokens from args for client {client_id}')
            raise AuthenticationError(msg=msg, code=401)

        try:
            transfer_client = precheck(client_id, endpoint_id, access_token, refresh_token)
        except PythonAuthenticationError:
            logger.error(f'Invalid token given for client {client_id}')
            msg='Access token invalid. Please provide valid token.'
            raise AuthenticationError(msg=msg, code=401)
        # except Exception:
        #     logger.error(f'Unidentified error attempting to instatiate Globus SDK with client id: {client_id}')
        #     logger.error(traceback.print_exc())
        #     raise InternalServerError(msg="Internal server error")

        # perform ls op
        try:
            query_dict = {}
            if limit: 
                query_dict['limit'] = limit
            if offset:
                query_dict['offset'] = offset
            logger.debug(f'have query dict:: {query_dict}')
            # call operation_ls to list everything in the directory
            
            split_path = path.rsplit("/", 1)
            
            if len(split_path) == 1:
                    if split_path[0] == '.' or split_path[0] == '~':
                        parent_dir = path # home directory, no need to change anything
                    else:
                        logger.error(f"{split_path} length is 1 but it's not the home directory.") 
                        raise InternalServerError()
            elif len(split_path) > 1:
                parent_dir = path.rsplit("/", 1)[0]
                child_name = path.rsplit("/", 1)[1]
                # need to find out if requested object if a file or directory
                logger.debug(f'checking parent dir: {parent_dir}')
                try:
                    result = transfer_client.operation_ls(
                        endpoint_id=(endpoint_id),
                        path=parent_dir
                    )
                    logger.debug("looping through gathered items")
                    for item in result.data["DATA"]:
                        name = item["name"]
                        logger.debug(f"checking item with name {name}")
                        if item["name"] != child_name: continue
                        if item["type"] == "file":
                            return utils.ok(
                                result = item,
                                msg="Successfully retrieved file"
                            )
                        elif item["type"] == "dir": break
                except Exception as e:
                    logger.error(f"encountered exception checking parent directory of path: {path} with client id {client_id}:: {e}")               
                    raise InternalServerError()
            else:
                # something went wrong. This should never be 0.
                logger.error(f'length of split path -- {path} -- was 0. This should never happen.')
                raise PathNotFoundError(code=404)
            result = transfer_client.operation_ls(
                endpoint_id=(endpoint_id),
                path=path,
                filter=filter,
                query_params=query_dict if query_dict != {} else None
            )
            # logger.debug(f'got result::{result}')
        except TransferAPIError as e:
            logger.error(f'transfer api error for client {client_id}: {e}, code:: {e.code}')
            # api errors come through as specific codes, each one can be handled separately
            handle_transfer_error(e.code)
        except Exception as e:
            logger.error(f'exception while doing ls operation for client {client_id}:: {e}')
            raise InternalServerError()
        else:
            # TODO: if the tokens get refreshed live, we could have a race condition 
            # figure out a way to test if refreshed access tokens will cause a call to fail
                # especially for concurrent ops
            
            logger.info(f'Successfully listed files on path:: {path} for client {client_id}')
            return utils.ok(
                msg='Successfully listed files',
                result=result.data,
                metadata={'access_token': access_token}
            )
        logger.error(f"Unknown error preforming list operation for client {client_id}")
        raise InternalServerError()

    # mkdir
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
            handle_transfer_error(e.code)
        except Exception as e:
            logger.error(f'exception performing mkdir for client {client_id} at path {path}:: {e}')
            raise InternalServerError(msg=f"Unkown error performing mkdir at path {path}. Please check request syntax and try again.")

        # perform mkdir op
        try:
            result = transfer_client.operation_mkdir(
                endpoint_id=endpoint_id,
                path=path
            )
        except TransferAPIError as e:
            logger.error(f'transfer api error for client {client_id}: {e}, code:: {e.code}')
            # api errors come through as specific codes, each one can be handled separately
            handle_transfer_error(e.code)
            # TODO: handle intermediate folder creation? e.g. path/to/thing instead of path/
        except Exception as e:
            logger.error(f'exception while performing mkdir operation for client {client_id} at path {path}:: {e}')
            raise InternalServerError(msg=f'Unknown error while performing mkdir operation at path {path}')
        else:
            logger.info(f'successfull mkdir for client {client_id} at path {path}')
            return utils.ok(
                msg=f'Successfully created directory at {path}',
                result=result.data,
                metadata={'access_token': access_token}
            )
        raise InternalServerError(msg=f'exception while performing mkdir operation for client {client_id} at path {path}')

    # delete
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
            result = transfer_client.submit_delete(delete_task)
        except TransferAPIError as e:
            logger.error(f'transfer api error for client {client_id}: {e}, code:: {e.code}')
            # api errors come through as specific codes, each one can be handled separately
            handle_transfer_error(e.code)
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
    def put(self, client_id, endpoint_id, path):
        # parse args and perform precheck
        transfer_client = None
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
            result = transfer_client.operation_rename(endpoint_id, oldpath=path, newpath=dest)
        except TransferAPIError as e:
            logger.error(f'transfer api error for client {client_id}: {e}, code:: {e.code}')
            # api errors come through as specific codes, each one can be handled separately
            handle_transfer_error(e.code)
        except Exception as e:
            logger.error(f'exception in rename with client {client_id}, endpoint {endpoint_id} and path {path}:: {e}')
            raise InternalServerError(msg='Unknown error while performing rename')
        logger.info(f'Successful rename for client {client_id} at path {path}')
        return utils.ok(
            msg=f'Success',
            result = result.data
        )


class TransferResource(Resource):
    def post(self, client_id):
        access_token = request.args.get('access_token')
        refresh_token = request.args.get('refresh_token')
        src = request.json.get('source_endpoint')
        dest = request.json.get('destination_endpoint')
        items = request.json.get('transfer_items')

        logger.debug(f'have setup args \n{access_token}\n{refresh_token}\n{src}\n{dest}\n{items}')

        if not access_token or not refresh_token:
            logger.error('error parsing args')
            raise AuthenticationError(msg='Exception while parsing request parameters. Please check your request syntax and try again')

        transfer_client = None
        try:
            transfer_client = precheck(client_id, [src, dest], access_token, refresh_token)
            logger.debug(f'have tc:: {transfer_client}')
        except Exception as e:
            logger.error(f'failed to authenticate transfer client :: {e}')
            raise InternalServerError(msg='Failed to authenticate transfer client')

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
            raise InternalServerError(msg='Error while authenticating globus client')
        try:
            result = transfer_client.get_task(task_id)
        except Exception as e:
            logger.error(f'error while getting transfer task with id {task_id}: {e}')
            raise InternalServerError(msg='Error retrieving transfer task')
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
            raise AuthenticationError(msg='Error retrieving transfer task')
        logger.info(f'Successful delete with client {client_id} of task {task_id}')
        return utils.ok(
            result=result.data,
            msg='successfully canceled transfer task'
        )




