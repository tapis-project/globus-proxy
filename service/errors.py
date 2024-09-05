from tapisservice.errors import BaseTapisError

### reference of base tapis error imported above
# class BaseTapisError(Exception):
#     """
#     Base Tapis error class. All Error types should descend from this class.
#     """
#     def __init__(self, msg=None, code=400):
#         """
#         Create a new TapisError object.
#         :param msg: (str) A helpful string
#         :param code: (int) The HTTP return code that should be returned
#         """
#         self.msg = msg
#         self.code = code


class InternalServerError(BaseTapisError):
    """Internal server error"""
    def __init__(self, msg="Internal Server Error", code=500):
        super().__init__(msg, code)
    
class PathNotFoundError(BaseTapisError):
    """Given path is not found on the endpoint"""
    def __init__(self, msg="Given path is not found on the endpoint", code=404):
        super().__init__(msg, code)

class GlobusError(BaseTapisError):
    """General error with the Globus SDK"""
    def __init__(self, msg="Uncaught Globus error", code=400):
        super().__init__(msg, code)

class GlobusInvalidRequestError(BaseTapisError):
    """malformed request or missing information"""
    def __init__(self, msg="Invalid request", code=400):
        super().__init__(msg, code)

class GlobusConsentRequired(BaseTapisError):
    def __init__(self, msg="Endpoint requires consent", code=403):
        super().__init__(msg, code)

class GlobusUnauthorized(BaseTapisError):
    def __init__(self, msg="Permission denied", code=401):
        msg=f"You do not have permission to perform that operation on this endpoint:: {msg}"
        super().__init__(msg, code)

class GlobusPathExists(BaseTapisError):
    def __init__(self, msg="A directory with given path already exists", code=409):
        super().__init__(msg, code)
