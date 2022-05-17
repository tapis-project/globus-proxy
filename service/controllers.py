from ast import Pass
import json
from os import access
import traceback

from flask import Flask, current_app, request
from flask_restful import Resource

from tapisservice.tapisflask import utils
from tapisservice.tapisflask.resources import ReadyResource
from tapisservice.logs import get_logger

import globus_sdk
from globus_sdk import TransferAPIError

from utils import check_tokens, get_transfer_client, transfer, is_endpoint_activated, autoactivate_endpoint

from multiprocessing import AuthenticationError

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
            logger.debug(f'Encountered exception while initializing globus_dsk::\n\t{e}')
            return utils.error(
                msg = 'Unknown error occurred'
            )
        session_client = client.oauth2_start_flow(refresh_tokens=True)
        authorize_url = client.oauth2_get_authorize_url()

        return utils.ok(
                # result = {"url": authorize_url, "uuid": session_id}, 
                result = {"url": authorize_url, "session_id": session_client.verifier}, 
                msg = f'Please go to this URL and login: {authorize_url}'
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
            logger.error(f'Encountered exception while initializing globus_sdk::\n\t{e}')
            return utils.error(
                msg= 'Unknown error occurred. Unable to authenticate client'
            )


        # get access / refresh tokens
        try:
            token_response = client.oauth2_exchange_code_for_tokens(auth_code).by_resource_server
        except globus_sdk.services.auth.errors.AuthAPIError:
            return utils.error(
                msg = 'Invalid auth code given for client'
            )
        else:
            try:
                access_token = token_response['transfer.api.globus.org']['access_token']
                refresh_token = token_response['transfer.api.globus.org']['refresh_token']
            except KeyError as e:
                logger.error(f'Could not parse tokens from response:: {e}')
                return utils.error(
                    msg='Internal server error'
                )
        
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
    def ops_precheck(self, client_id, endpoint_id, access_token, refresh_token):
        '''
        Performs several precheck opertations such as
            making sure the tokens are valid and exchanging an expired access token for an active one
            activating a transfer client
        
        returns authenticated transfer client
        '''
        # check token validity
        try:
            access_token, refresh_token = check_tokens(client_id, refresh_token, access_token)
        except AuthenticationError:
            # refresh token is invalid, must redo auth process
            logger.error(f'exception while validating tokens:: {e}')
            return utils.error(
                msg='Error while validating tokens. Please redo the Oauth2 process for this client_id'
            )
            # TODO: handle more exceptions, figure out how to make them nice for the calling function

        # get transfer client
        try:
            transfer_client = get_transfer_client(client_id, refresh_token, access_token)
        except Exception as e:
            logger.error(f'unable to get transfer client or client {client_id}: {e}')
            return utils.error(
                msg='Exception while generating authorization. Please check your request syntax and try again'
            )
        
        # activate endpoint
        try:
            result = transfer_client.endpoint_autoactivate(endpoint_id)
            if result['code'] == "AutoActivationFailed":
                raise AuthenticationError
        except AuthenticationError as e:
            logger.error(f'endpoint activation failed. Endpoint must be manuallty activated')
            return utils.error(
                msg=f'Endpoint {endpoint_id} must be manually activated'
            )
        except Exception as e:
            pass
            # TODO: handle excpetions. 
        
        # return trans client
        return transfer_client

    # ls
    def get(self, client_id, endpoint_id, path):
        # parse args & perform precheck
        logger.debug(f'in ls with path:: {path}')
        transfer_client = None
        access_token = request.args.get('access_token')
        refresh_token = request.args.get('refresh_token')
        limit = request.args.get('limit')
        offset = request.args.get('offset')
        filter = request.args.get('filter')
        if not access_token or not refresh_token:
            logger.error('error parsing args. Check syntax and try again')
            return utils.error(
                msg='Exception while parsing request parameters. Please check your request syntax and try again'
                )
        try:
            transfer_client = self.ops_precheck(client_id, endpoint_id, access_token, refresh_token)
        except AuthenticationError:
            logger.error(f'Invalid token given for client {client_id}')
            return utils.error(
                msg='Given tokens are not valid. Try again with active auth tokens'
            )
        except Exception as e:
            pass
            # TODO: handle more exceptions?

        # perform ls op
        try:
            query_dict = {}
            if limit: 
                query_dict['limit'] = limit
            if offset:
                query_dict['offset'] = offset
            logger.debug(f'have query dict:: {query_dict}')
            # call operation_ls to make the directory
            #TODO: Fix query params not doing anything
            result = transfer_client.operation_ls(
                endpoint_id=(endpoint_id),
                path=path,
                filter=filter,
                query_params=query_dict if query_dict != {} else None
            )
            logger.debug(f'got result::{result}')
        except TransferAPIError as e:
            logger.error(f'transfer api error for client {client_id}: {e}, code:: {e.code}')
            # api errors come through as specific codes, each one can be handled separately 
            # TODO: change this to be a handle function so that I dont have to repeat all this code
            if e.code == "AuthenticationFailed":
                return utils.error(
                    msg='Could not authenticate transfer client for ls operation'
                )
            elif e.code == "ClientError.NotFound":
                return utils.error(
                    msg='Path does not exist on given endpoint'
                )
            elif e.code == "ExternalError.DirListingFailed.GCDisconnected":
                return utils.error(
                    msg=f'Error connecting to endpoint {endpoint_id}. Please activate endpoint manually'
                )
        except Exception as e:
            logger.error(f'exception while doing ls operation for client {client_id}:: {e}')
            return utils.error(
                msg='Unknown error while performing ls operation'
            )
        else:
            # TODO: send access token back, even if it's the same one
            # if the tokens get refreshed live, we could have a race condition 
            # figure out a way to test if refreshed access tokens will cause a call to fail
                # especially for concurrent ops
                
            return utils.ok(
                msg='Successfully listed files',
                result=result.data,
                metadata={'access_token': access_token}
            )
            
        return utils.error(
            msg='Unknown error performing list operation'
        )

    # mkdir
    def post(self, client_id, endpoint_id, path):
        # parse args and perform precheck
        logger.debug(f'in mkdir, have path:: {path}')
        transfer_client = None
        access_token = request.args.get('access_token')
        refresh_token = request.args.get('refresh_token')
        if not access_token or not refresh_token:
            logger.error('error parsing args')
            return utils.error(
                msg='Exception while parsing request parameters. Please check your request syntax and try again'
                )

        try:
            transfer_client = self.ops_precheck(client_id, endpoint_id, access_token, refresh_token)
        except AuthenticationError:
            logger.error(f'Invalid token given for client {client_id}')
            return utils.error(
                msg='Given tokens are not valid. Try again with active auth tokens'
            )
        except Exception as e:
            return utils.error(f'exception while performink mkdir operation for client {client_id} at path {path}:: {e}')
            # TODO: handle more exceptions?

        # perform mkdir op
        try:
            result = transfer_client.operation_mkdir(
                endpoint_id=endpoint_id,
                path=path
            )
        except TransferAPIError as e:
            logger.error(f'transfer api error for client {client_id}: {e}')
            if e.code == "AuthenticationFailed":
                return utils.error(
                    msg='Could not authenticate transfer client for mkdir operation'
                )
            # TODO: handle the path already existing
        except Exception as e:
            logger.error(f'exception while performink mkdir operation for client {client_id} at path {path}:: {e}')
            return utils.error(
                msg=f'Unknown error while performing mkdir operation at path {path}'
            )
        else:
            return utils.ok(
                msg=f'Successfully created directory at {path}',
                result=result.data,
                metadata={'access_token': access_token}
            )
        return utils.error(
            msg=f'exception while performink mkdir operation for client {client_id} at path {path}'
        )

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
            return utils.error(
                msg='Exception while parsing request parameters. Please check your request syntax and try again'
                )

        try:
            transfer_client = self.ops_precheck(client_id, endpoint_id, access_token, refresh_token)
        except AuthenticationError:
            logger.error(f'Invalid token given for client {client_id}')
            return utils.error(
                msg='Given tokens are not valid. Try again with active auth tokens'
            )
        except Exception as e:
            return utils.error(f'exception while performing delete operation for client {client_id} at path {path}:: {e}')
            # TODO: handle more exceptions?

        # perform delete
        try:
            delete_task = globus_sdk.DeleteData(
                transfer_client=transfer_client,
                endpoint=endpoint_id,
                recursive=recurse
            )
            delete_task.add_item(path)
            logger.debug(f'have delete task:: {delete_task}')
            result = transfer_client.submit_delete(delete_task)
        except Exception as e:
            logger.error(f'exception while performing delete operation for client {client_id} at path {path}:: {e}')
            return utils.error(
                msg=f'Unknown error performing delete operation'
            )
        return utils.ok(
            result=result.data,
            msg='Successfully deleted path'
        )
    # rename
    def put(self, client_id, endpoint_id, path):
        # parse args and perform precheck
        transfer_client = None
        access_token = request.args.get('access_token')
        refresh_token = request.args.get('refresh_token')
        dest = request.json.get('destination')
        # logger.debug(f'in put (rename) have path {path} and dest {dest} given form {request.form} given values {request.values} given json {request.json}')
        if not access_token or not refresh_token:
            logger.error('error parsing args')
            return utils.error(
                msg='Exception while parsing request parameters. Please check your request syntax and try again'
                )

        try:
            transfer_client = self.ops_precheck(client_id, endpoint_id, access_token, refresh_token)
        except AuthenticationError:
            logger.error(f'Invalid token given for client {client_id}')
            return utils.error(
                msg='Given tokens are not valid. Try again with active auth tokens'
            )
        except Exception as e:
            return utils.error(f'exception while performing rename operation for client {client_id} at path {path}:: {e}')
            # TODO: handle more exceptions?

        # perform rename
        try:
            transfer_client.operation_rename(endpoint_id, oldpath=path, newpath=dest)
        except Exception as e:
            logger.error(f'exception in rename with client {client_id}, endpoint {endpoint_id} and path {path}:: {e}')
            return utils.error(
                msg='Unknown error while performing rename'
            )
        return utils.ok(
            msg=f'Successfully renamed file'
        )


class TransferResource(Resource):
    # TODO: make sure that the eps are activated before starting anything
    # TODO make sure that the tokens are valid
    def post(self, client_id):
        access_token = request.args.get('access_token')
        refresh_token = request.args.get('refresh_token')
        src = request.json.get('source_endpoint')
        dest = request.json.get('destination_endpoint')
        items = request.json.get('transfer_items')

        logger.debug(f'have setup args \n{access_token}\n{refresh_token}\n{src}\n{dest}\n{items}')

        # TODO: add the error handling here instead?
        transfer_client = OpsResource.ops_precheck(self, client_id, src, access_token, refresh_token)
        if not is_endpoint_activated(transfer_client, src):
            logger.debug('src is not active')
            autoactivate_endpoint(transfer_client, src)
        if not is_endpoint_activated(transfer_client, dest): 
            logger.debug('dest is not active')   
            autoactivate_endpoint(transfer_client, dest)
        result = (transfer(transfer_client, src, dest, items))
        if "File Transfer Failed" in result:
            logger.error(f'File transfer failed due to {result}')
            return utils.error(
                msg='File transfer failed'
            )
        logger.debug(f'got res:: {result}')

        return utils.ok(
            result=result.data,
            msg=f'Successfully completed transfer'
        )

class ModifyTransferResource(Resource):
    # TODO: 
    # Make sure tokens are valid
    # 
    def get(self, client_id, task_id):
        access_token = request.args.get('access_token')
        refresh_token = request.args.get('refresh_token')
        # transfer_client = OpsResource.ops_precheck(self, client_id, src, access_token, refresh_token)
        try:
            transfer_client = get_transfer_client(client_id, refresh_token, access_token)
        except Exception as e:
            logger.debug(f'error while getting transfer client for client id {client_id}: {e}')
            return utils.error(
                msg='Error while authenticating globus client'
            )
        try:
            result = transfer_client.get_task(task_id)
        except Exception as e:
            logger.debug(f'error while getting transfer task with id {task_id}: {e}')
            return utils.error(
                msg='Error retrieving transfer task'
            )
        return utils.ok(
            result=result.data,
            msg='successfully retrieved transfer task'
        )
        

    def delete(self, client_id, task_id):
        access_token = request.args.get('access_token')
        refresh_token = request.args.get('refresh_token')
        try:
            transfer_client = get_transfer_client(client_id, refresh_token, access_token)
        except Exception as e:
            logger.debug(f'error while getting transfer client for client id {client_id}: {e}')
            return utils.error(
                msg='Error while authenticating globus client'
            )
        try:
            result = transfer_client.cancel_task(task_id)
        except Exception as e:
            logger.debug(f'error while canceling transfer task with id {task_id}: {e}')
            return utils.error(
                msg='Error retrieving transfer task'
            )
        return utils.ok(
            result=result.data,
            msg='successfully canceled transfer task'
        )




