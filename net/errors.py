class Error(Exception):
    def __init__(self, message):
        super().__init__(message)

class AddressError(Error):
    def __init__(self, expression, reason):
        super().__init__(f'{expression}: {reason}')

class UnknownNetworkError(Error):
    def __init__(self, network: str):
        super().__init__(f'unkown network {network}')
