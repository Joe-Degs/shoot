import socket
import io
import os
from typing import Union, Optional

class _SocketWriter(io.BufferedIOBase):
    """
    A writtable and readable BufferedIOBase implementation for a socket. Most of it copied
    from https://github.com/python/cpython/blob/302df02789d041a09760f86295ea6b4dcd81aa1d/Lib/socketserver.py#L814
    """
    def __init__(self, sock):
        self.__sock = sock

    def writable(self) -> bool:
        return True
    
    def readable(self) -> bool:
        return True

    def read(self) -> bytes:
        # read from the socket until eof then return read bytes.
        # if an error occurs while reading throw it.
        chunks = []
        buf = ''
        while True:
            try:
                buf = self.__sock.recv(2048)
                chunks.append(buf)
                if buf == b'':
                    return b''.join(chunks)
            except Exception as e:
                raise e

    def write(self, buf) -> int:
        self.__sock.sendall(buf)
        with memoryview(buf) as view:
            return view.nbytes

class Addr:
    """ Addr represents a network endpoint address """
    def __init__(self, addrinfo: tuple, network: Optional[str] = None):
        self.network = network
        self.addrinfo = addrinfo

    def __str__(self) -> str:
        # return a string representation of addrinfo. This representation
        # has to be different for ipv4 and ipv6 but i can't be bothered
        # right now so ciao.
        if self.network:
            return f"{self.network}:{self.addrinfo[0]}:{self.addrinfo[1]}"
        return f"{self.addrinfo[0]}:{self.addrinfo[1]}"

    def __repr__(self) -> str:
        return self.__str__()
    
    @staticmethod
    def from_addrinfo(addrinfo: tuple) -> 'Addr':
        return Addr(addrinfo)

    def to_addr(self) -> 'Addr':
        return Addr(addrinfo=self.addrinfo)

class TCPAddr(Addr):
    """
    TCPAddr wraps around a addrinfo associated with a tcp connection.
    """
    def __init__(self, addrinfo: tuple, network = 'tcp'):
        Addr.__init__(self, addrinfo, network)

class UDPAddr(Addr):
   """
   UDPAddr wraps an addrinfo associated with a udp connection.
   """
   def __init__(self, addrinfo: tuple, network = 'udp'):
        Addr.__init__(self, addrinfo, network)

class Conn:
    """
    Conn is implements a generic wrapper around socket connections.
    It is implemented to look exactly like the way the net.Conn type
    in golang is. But i'm not sure it works the same way.
    """
    def __init__(self, sock: socket.socket):
        self.sock = sock
        self.settimeout(2.0)
        if os.name == 'nt':
            # windows socket file descriptors are not treated as
            # normal file descriptors and so cannot be wrapped in
            # file object. So its wrapped in _SocketWriter insted.
            self.__conn = _SocketWriter(self.sock)
        elif os.name == 'posix':
            self.__conn = io.open(self.sock.fileno(), 'ab')
        else:
            NotImplementedError(os.name)
    
    def write(self, buf: bytes):
        # write bytes to the underlying socket connection
        return self.__conn.write(buf)

    def read(self) -> bytes:
        # read data from the underlying socket connection.
        return self.__conn.read()

    def file(self) -> Union[_SocketWriter, io.BufferedRandom]:
        # file returns the file object that conn is wrapped in.
        return self.__conn

    def connect(self, addr: Union[Addr, TCPAddr, UDPAddr]):
        # connects underlying socket to addr.
        self.sock.connect(addr.addrinfo)

    def srv_bind(self, addr: Union[Addr, TCPAddr, UDPAddr], reuse=True):
        # srv_bind binds socket to addr. And it reuse is set to true
        # it sets socket option for address reuse.
        if reuse:
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(addr.addrinfo)
    
    def setblocking(self, flag: bool) -> None:
        # set whether socket should block or not.
        self.sock.setblocking(flag)

    def settimeout(self, timeout: float) -> None:
        # set a timeout value for socket.
        self.sock.settimeout(timeout)

    def close(self) -> None:
        # close all open file descriptors. both socket and io stream.
        self.sock.close()
        self.__conn.close()

    def shutdown(self, flag: str) -> None:
        # shutdown the socket connection(read, write or both) and close
        # all open file descriptors.
        # options === (SHUT_RD, SHUT_WR, SHUT_RDWR)
        self.sock.shutdown(flag)
        self.close()

class TCPConn(Conn):
    """
    TCPConn implements a tcp connection wrapper.
    """
    def __init__(self, addr: Union[Addr, TCPAddr], conn_type: Optional[str]=None, sock: Optional[socket.socket]=None):
        if sock == None:
            Conn.__init__(self, socket.socket(socket.AF_INET, socket.SOCK_STREAM))
        else:
            Conn.__init__(self, sock)
        self.addr = addr
        try:
            if conn_type == 'listen':
                # a socket opened for listening
                # bind socket to addr provided
                self.srv_bind(self.addr)
            elif conn_type == 'connect':
                # socket opened to connect to a remote host
                # connect to addr provided and change addr
                # to the arbitrary host:port from the kernel
                self.connect(addr)
                self.addr = TCPAddr(self.sock.getsockname())
            elif not conn_type:
                # you listened and recieved a connection
                # you just assign it to self.sock and leave it
                # at that.
                return
            else:
                # we recieved a conn_type thats not any of the
                # of the 3 above so we throw an exception.
                # we don't know what it is.
                raise NotImplementedError(conn_type)
        except:
            self.sock.close()
            raise
    
    def local_addr(self) -> Union[Addr, TCPAddr]:
        # return the local addr associated with socket.
        return self.addr

    def remote_addr(self):
        # return remote address associated with socket.
        return TCPAddr(self.sock.getpeername())

class UDPConn(Conn):
    """ A  simple UDP Connnection """
    def __init__(self, addr: Union[Addr, UDPAddr], conn_type: Optional[str]=None, sock: Optional[socket.socket]=None):
        if sock == None:
            Conn.__init__(self, socket.socket(socket.AF_INET, socket.SOCK_DGRAM))
        else:
            Conn.__init__(self, sock)
        self.addr = addr
        self.max_packet_size = 8192
        try:
            if conn_type == 'listen':
                self.srv_bind(self.addr, reuse=False)
            elif conn_type == 'connect':
                self.connect(addr)
                self.addr = UDPAddr(self.sock.getsockname())
            elif conn_type == '':
                # remote socket conn, do not bind, do not connect
                # don't do shit
                return
            else:
                raise NotImplementedError(conn_type)
        except:
            self.sock.close()
            raise

    def read_from(self) -> tuple[bytes, Addr]:
        # read_from reads from the socket connection and returns
        # the bytes read with the remote host address read from
        data, raddr = self.sock.recvfrom(self.max_packet_size)
        return data, Addr(addrinfo=raddr)

    def read_from_udp(self) -> tuple[bytes, UDPAddr]:
        # does the same thing as read_from but returns a UDPAddr
        # class instead.
        data, addr = self.read_from()
        return data, UDPAddr(addr.addrinfo)

    def write_to(self, buf: bytes, addr: Union[Addr, UDPAddr]) -> int:
        # write_to write buf[bytes] to the underlying socket connection.
        return self.sock.sendto(buf, addr.addrinfo)

    def write_to_udp(self, buf: bytes, addr: UDPAddr) -> int:
        # write_to but writes to only other udp addresses.
        return self.sock.sendto(buf, addr.addrinfo)

    def local_addr(self) -> UDPAddr:
        return UDPAddr(addrinfo=self.sock.getsockname())

    def remote_addr(self) -> UDPAddr:
        return UDPAddr(addrinfo=self.sock.getpeername())


class TCPListener(TCPConn):
    """ 
    TCPListener is a wrapper around TCPConn that provides capabilities
    to listen for connections.
    """
    queue_size = 10

    def __init__(self, addr: Union[Addr, TCPAddr], queue_size: int=queue_size):
        # create a tcp socket ready to listen on addr.
        TCPConn.__init__(self, addr, 'listen')
        self.sock.listen(queue_size)

    def accept(self) -> Conn:
        # accept returns the generic Conn type
        sock, _ = self.sock.accept()
        return Conn(sock)

    def accept_tcp(self) -> TCPConn:
        # return a TCPConn from the underlying listening socket.
        sock, addrinfo = self.sock.accept()
        return TCPConn(addr=Addr(addrinfo), sock=sock)

class InvalidAddrFormat(Exception):
    msg = f'''
    addr is supposed to be of the format
    <protocol>:<ipaddr>:<port> or <ipaddr>:<port>
    '''
    def __init__(self, message=msg):
        super().__init__(message)

def parse_str_addr(addr_str):
    """ addr_str is in the form '<network>:<ipaddress>:<port>' """
    s = addr_str.split(':')
    return Addr((s[1], s[2]), s[0])

def get_host_and_port(name):
    name = name.split(':')
    host, port = name[0], name[1]
    try:
        port = int(port)
    except:
        raise InvalidAddrFormat
    return host, port

def get_addrinfo(host: str, port: int, iptype: int):
    if iptype == 6:
        return socket.getaddrinfo(host, port, socket.AF_INET6)
    return socket.getaddrinfo(host, port, socket.AF_INET) 

def parse_ipv6(network, name):
    host, port = get_host_and_port(name)
    addrinfos = get_addrinfo(host, port, 6)
    return Addr(addrinfos[-1][-1])

def parse_ipv4(network, name):
    host, port = get_host_and_port(name)
    addrinfos = get_addrinfo(host, port, 4)
    return Addr(addrinfos[-1][-1])

def parse_udp_addr(addr_str):
    return UDPAddr(ResolveAddr(addr_str).addrinfo)

def ResolveAddr(addr: str, network: Optional[str]=None):
    """ 
    ResolveAddr does exactly what the name suggests, it resolve a name
    and returns the address of the endpoint. The address returned can
    be of any network type or it can be network agnostic.
    """
    pass

def Dial(addr: str, network: Optional[str]=None):
    """ 
    Dial connects to the address on a named network.
    it returns a subclass of Conn
    """
    if conn_type == 'tcp':
        # return a tcp conn ready for reading and writing
        #
        return TCPConn(ResolveAddr(addr), 'connect')
    elif conn_type == 'udp':
        # return a udpconn ready for reading and writing
        return UDPConn(parse_udp_addr(addr), 'connect')
    else:
        # unimplemented protocol type
        # return Unimplemented(conn_type)
        NotImplementedError()

def Listen(conn_type: str, addr: str):
    """ spun a new socket connection thats ready to listen and respond
    to packets like a champ! """
    if conn_type == 'tcp':
        return TCPListener(ResolveAddr(addr))
    elif conn_type == 'udp':
        return UDPConn(parse_udp_addr(addr), 'listen')
