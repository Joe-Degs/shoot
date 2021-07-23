from typing import Union, Optional
import ipaddress as ipaddr
import socket

from  .errors import *

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

def split_host_port(hostport: str):
    """return the host:port into individual host, port

    see function resolve_addr for more info on form of hostport
    """
    if not hostport:
        # wtf do you want to split?
        raise AddressError(hostport, "missing host and port in address")

    missing_port = "missing port in address"
    too_many_colons = "too many colons in address"
    host = ''
    port = ''

    i = hostport.rfind(':')
    # if there is no ':' in hostport or ':' is the last thing
    # hostport then throw an error into the callers face
    if i < 0 or len(hostport) == i+1:
        raise AddressError(hostport, missing_port)

    if '[' in hostport and ']' in hostport:
        # we are treading ipv6 zone
        end = hostport.rfind(']') # get index of ]
        if end+1 == len(hostport):
            # if index of ] is the last thing then there is no port
            raise AddressError(hostport, missing_port)
        elif end+1 == i:
            # this is what we expect
            pass
        else:
            if hostport[end+1] == ':':
                # either ']' is followed by a colon or it is
                # but its not the last one
                raise AddressError(hostport, too_many_colons)
            raise AddressError(hostport, missing_port)
        # host port is worthy ipv6 and should be stripped now.
        host, port = hostport[0 : i], hostport[i+1:]
        host = host.strip('[]')
    elif '[' in hostport or ']' in hostport:
        # contains only one of '[' ']'
        raise AddressError(hostport, "address has only one of '[' and ']'")
    else:
        # not string representation of ipv6 but has more than one ':'
        host, port = hostport[0 : i], hostport[i+1:]
        if ':'in host:
            raise AddressError(hostport, too_many_colons)
    
    # we've made it this far and its cool. we can now start the splitting.
    return host, port


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
        self.port = self.addrinfo[1]

    def __str__(self):
        return join_host_port(str(self.ipaddr), self.port)

class UDPAddr(IPAddr):
    """
    UDPAddr wraps an addrinfo associated with a udp socket.
    """
    def __init__(self, addrinfo: tuple):
        IPAddr.__init__(self, addrinfo)
        self.port = self.addrinfo[1]

    def __str__(self):
        return join_host_port(str(self.ipaddr), self.port)

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

    def set_socktype(self, socktype: Union[socket.SocketKind, int]):
        self.__addr_config['socktype'] = socktype

    def set_family(self, family: Union[socket.AddressFamily, int]):
        self.__addr_config['family'] = family

    def set_proto(self, proto: int):
        self.__addr_config['proto'] = proto

    def get_config(self) -> dict:
        return self.__addr_config

def resolve_addr_list(addr_config: dict):
    return socket.getaddrinfo(
            addr_config['host'],
            addr_config['port'],
            addr_config['family'],
            addr_config['socktype'],
            addr_config['proto'],
            addr_config['flags']
        )

def inet_addr_list(addr_config: dict, network: str):
    """internet_addr_list returns a list of TCPAddr | UDPAddr | IPAddr
    """
    if network:
        addrinfo_list = resolve_addr_list(addr_config)
        addr_obj = None
        if 'tcp' in network:
            addr_obj = TCPAddr
        elif 'udp' in network:
            addr_obj = UDPAddr
        elif 'ip' in network:
            addr_obj = IPAddr
        else:
            raise UnknownNetworkError(network)
        addr_list = []
        for addrinfo in addrinfo_list:
            addr_list.append(addr_obj(addrinfo[-1]))
        return addr_list
    else:
        raise UnknownNetworkError(network)

def config_inetaddr(host: str, port: str, network: str):
    """config_inetadr returns an AddrConfig instance.

    this instance can be resolved into an address endpoint
    that can be connected to, sent into or listened on.

    Parameters
    -----------
    host: str
        the host node of the address

    port: str
        the literal port number or service name

    network: str, optional
        the network endpoint type of address
    """
    config = AddrConfig(host, port,
            family=socket.AF_INET,
            flags=socket.AI_ADDRCONFIG)

    if '6' in network:
        # address family for ipv6
        config.set_family(socket.AF_INET6)
        if not socket.has_ipv6:
            # for machines without ipv6
            config.add_flag(socket.AI_V4MAPPED)
     
    if 'udp' in network:
        config.set_socktype(socket.SOCK_DGRAM)
        config.set_proto(socket.IPPROTO_UDP)
        return config
    elif 'tcp' in network:
        config.set_socktype(socket.SOCK_STREAM)
        config.set_proto(socket.IPPROTO_TCP)
        return config
    elif not network:
        config.set_socktype(socket.SOCK_STREAM)
        config.set_family(socket.AF_UNSPEC)
        config.add_flag(socket.AI_PASSIVE)
        return config
    else:
        raise UnknownNetworkError(network)

def resolver(host: str, port: str, network: str) -> tuple[list, AddrConfig]:
    """return a list of resolved endpoints and the config used to resolve them
    """
    config = config_inetaddr(host, port, network)
    addr_list = inet_addr_list(config.get_config(), network)
    return addr_list, config

def loopback_addr(network) -> str:
    if '6' in network:
        return '::1'
    return '127.0.0.1'

def resolve_udp_addr(address: str, network: str='udp') -> Optional[UDPAddr]:
    """resolve_tcp_addr returns an address of a udp endpoint

    if the address is not a literal ip address and port number,
    resolve_udp_addr resolves the address to an endpoint of a udp network.
    if address is empty or None, it defaults to using the appropriate
    loopback ip

    see resolve_addr for more info on structure of address and network

    Parameters:
    -----------
    address: str
        the udp endpoint to resolve

    network: str
        the type of udp network to resolve.

    Raises
    ------
    UnknownNetworkError
    """
    if 'udp' in network:
        host, port = split_host_port(address)
        if not host:
            host = loopback_addr(network)
        udp_addr_list, _ = resolver(host, port, network)
        return udp_addr_list[0]
    else:
        raise UnknownNetworkError(network)

def resolve_tcp_addr(address: str, network: str='tcp') -> TCPAddr:
    """resolve_tcp_addr returns the tcp endpoint of address

    if the address is not a literal ip address and port number,
    resolve_tcp_addr resolves the address to an endpoint of a tcp network.
    if address is empty or None, it defaults to using the appropriate
    loopback ip

    see resolve_addr for more info on the structure of address and network.

    Parameters:
    -----------
    address: str
        address endpoint of the tcp connection

    network: str
        a tcp network name

    """
    if 'tcp' in network:
        host, port = split_host_port(address)
        if not host:
            host = loopback_addr(network)
        tcp_addr_list, _ = resolver(host, port, network)
        return tcp_addr_list[0]
    else:
        raise UnknownNetworkError(network)

def resolve_ip_addr(address: str, network: str = 'ip'):
    pass

def resolve_addr(address: str, network: str):
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

    Returns:
    --------
    TCPAddr | UDPAddr | IPAddr | Addr

    Raises:
    -------
    UnknownNetworkError
    """
    if 'tcp' in network:
        return resolve_tcp_addr(address, network)
    elif 'udp' in network:
        return resolve_udp_addr(address, network)
    elif 'ip' in network:
        return resolve_ip_addr(address, network)
    else:
        raise UnknownNetworkError(network)
