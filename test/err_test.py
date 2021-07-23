from net.errors import *

def raise_addr_error():
    try:
        raise AddressError('hostport', 'reason for throwing')
    except AddressError as e:
        raise e

def base_err():
    try:
        raise UnknownNetworkError('sntop')
    except Error as e:
        raise e

if __name__ == '__main__':
    base_err()
