from typing import Union, Optional
import ipaddress as ipaddr
import socket

class Addr:
    """
    Addr represents a network endpoint address
    """
    def __init__(self, addrinfo: tuple):
        """
        Parameters
        -----------
        addrinfo: tuple
            The addrinfo is the tuple that is returned by socket.getaddrinfo
            or is returned as a socket address from any socket connection.

        network: str, optional
            The network that the addrinfo represents. could be "tcp", "udp"
            or any other network. It also represents the type of socket
            connection Addr is associated with.
        """
        self.addrinfo = addrinfo

    def __str__(self) -> str:
        # return a string representation of addrinfo. The representation
        # is different for different socket connection types so
        # the individual addr classes should implement their own.
        return f'{self.addrinfo[0]}:{self.addrinfo[1]}'

    def __repr__(self) -> str:
        return self.__str__()

def join_host_port(host: str, port: str = '') -> str:
    if ':' in host:
        return f'[{host}]:{port}'
    return f'{host}:{port}'

class AddressError(Exception):
    pass

def split_host_port(hostport: str):
    """return the host:port into individual host, port

    see function resolve_addr for more info on form of hostport
    """
    try:
        if not hostport:
            # wtf do you want to split?
            raise AddressError(hostport, "missing host and port")

        i = hostport.rfind(':')
        # if there is no ':' in hostport or ':' is the last thing
        # hostport then throw an error into the callers face
        if i < 0 or len(hostport) == i+1:
            raise AddressError(hostport, "missing port")

        if '[' in hostport and ']' in hostport:
            # we are treading ipv6 zone
            end = hostport.rfind(']') # get index of ]
            if end+1 == len(hostport):
                # if index of ] is the last thing then there is no port
                raise AddressError(hostport, "missing port")
            elif end+1 == i:
                # this is what we expect
                pass
            else:
                if hostport[end+1] == ':':
                    # either ']' is followed by a colon or it is
                    # but its not the last one
                    raise AddressError(hostport, "too many colons")
                raise AddressError(hostport, "missing port")
            # host port is worthy ipv6 and should be stripped now.
            hostport = hostport.strip('[]')
        elif '[' in hostport or ']' in hostport:
            # contains only one of '[' ']'
            raise AddressError(hostport, "address has only one of '[' and ']'")
        else:
            # not string representation of ipv6 but has more than one ':'
            host = hostport[0 : i]
            if ':'in host:
                raise AddressError(hostport, "too many colons")
        
        # we've made it this far and its cool. we can now start the splitting.
        host = hostport[0 : i]
        port = hostport[i+1:]
        return host, port
    except AddressError:
        raise



class IPAddr(Addr):
    """IPAddr represents any type of address related to an IP network

    """
    def __init__(self, addrinfo: tuple):
        Addr.__init__(self, addrinfo)
        if addrinfo[0]:
            ip = ''
            if self.scope_id():
                ip = f'{self.addrinfo[0]}%{self.scope_id()}'
            else:
                ip = self.addrinfo[0]
            self.ipaddr = ipaddr.ip_address(ip)
        else:
            self.ipaddr = self.addrinfo

    def is_ipv6(self):
        if len(self.addrinfo) == 4:
            return True
        return False

    def scope_id(self) -> int:
        if self.is_ipv6():
            return self.addrinfo[2]
        return 0

    def flowinfo(self) -> int:
        if self.is_ipv6():
            return self.addrinfo[3]
        return 0

    def __str__(self):
        return join_host_port(str(self.ipaddr))

class TCPAddr(IPAddr):
    """
    TCPAddr wraps around an addrinfo associated with a tcp socket.
    """
    def __init__(self, addrinfo: tuple):
        IPAddr.__init__(self, addrinfo)

    def port(self):
        return self.addrinfo[1]

    def __str__(self):
        pass

class UDPAddr(IPAddr):
    """
    UDPAddr wraps an addrinfo associated with a udp socket.
    """
    def __init__(self, addrinfo: tuple):
        IPAddr.__init__(self, addrinfo)

    def port(self):
        return self.addrinfo[1]

    def __str__(self):
        pass

class InvalidAddrFormat(Exception):
    msg = 'addr is supposed to be of the format \
    <protocol>:<ipaddr>:<port> or <ipaddr>:<port> \
    or :<port>'
    def __init__(self, message=msg):
        super().__init__(message)

class AddrConfig:
    """AddrConfig is used to configure parameters for the getaddrino function
    
    """
    def __init__(self,
            host: str = '',
            port: str = '',
            family: Union[socket.AddressFamily, int] = 0,
            socktype: Union[socket.SocketKind, int] = 0,
            proto: int = 0, # integer of protocol to use.
            flags: int = 0, # multiple flags can be or-ed together
        ) -> None:
            self.__addr_config = {
               'host': host,
               'port': port,
               'family': family,
               'socktype': socktype,
               'proto': proto,
               'flags': flags,
            }

    def add_flag(self, flag: int):
        self.__addr_config['flags'] |= flag

    def set_socktype(self, socktype: socket.SocketKind):
        self.__addr_config['socktype'] = socktype

    def set_family(self, family: socket.AddressFamily):
        self.__addr_config['family'] = family

    def set_proto(self, proto: int):
        self.__addr_config['proto'] = proto

    def get_config(self) -> dict:
        return self.__addr_config

def resolve_addr_list(addr_config: dict) -> Optional[list[tuple]]:
    return socket.getaddrinfo(
            addr_config['host'],
            addr_config['port'],
            addr_config['family'],
            addr_config['socktype'],
            addr_config['proto'],
            addr_config['flags']
        ) 

def resolve_udp_addr(address: Optional[str], network: str='udp') -> UDPAddr:
    """
    resolve_tcp_addr returns an address of a udp endpoint

    Parameters:
    -----------
    network
    """
    return UDPAddr(addrinfo=())

def resolve_tcp_addr(address: Optional[str], network: str='udp') -> TCPAddr:
    return TCPAddr(addrinfo=())

def resolve_addr(address: Optional[str], network: Optional[str]=None):
    """ 
    resolve_addr returns an address that you can connect to, sendto or
    listen on.

    for tcp and udp networks the address is of the form "host:port". The
    host must be a literal ip, a hostname that can be resolved to a literal
    ip address or None which means a NULL will be passed to the C API that would
    eventually resolve the address.

    If the host is a literal IPv6 address, it must be enclosed in square brackets,
    as in "[::1]:80", "[2001::1]:80" or "[fe80::1%zone]:80". The zone specifies
    the scope of the literal IPv6 address as defined in RFC 4007.

    ports must be a literal number wrapped in a string or a service name. ex:
    "80" for a literal port number or "http" for the service name, both are valid.
    None defaults to passing NULL to the underlying c api

    examples:
    --------    
        resolve_addr("python.org:http" "tcp") -> TCPAddr
        resolve_addr("us.pool.ntp.org:ntp", "udp") -> UDPAddr
        resolve_addr("192.168.116.2:5555", "tcp") -> TCPAddr
        resolve_addr("[2001:db8::1]:53", "udp") -> UDPAddr
        resolve_addr(":80", "tcp6") -> TCPAddr

    Parameters
    ----------
    address: str, optional
        address is an network endpoint.

    network: str, optional
        network represents the network of the endpoint. networks supported
        this package are "tcp", "tcp4" (IPv4 only), "tcp6" (IPv6 only),
        "udp", "upd4" (IPv4 only), "udp6" (IPv6 only)
    """
    return UDPAddr(addrinfo=())
