import socket
#import ipaddress as ipaddr

class _SocketWriter(socket.io.BufferedIOBase):
    """
    Simple BufferedIOBase implementation for a socket.
    Does not buffer!
    """
    def __init__(self, sock):
        self.__sock = sock

    def writable(self):
        return True

    def read(self) -> bytes:
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

    def write(self, buf):
        self.__sock.sendall(buf)
        with memoryview(buf) as view:
            return view.nbytes

class Addr:
    """ Addr represents a network endpoint address """
    def __init__(self, network: str, addrinfo: tuple):
        self.network = network
        self.addrinfo = addrinfo

    def __str__(self) -> str:
        """ return address in <network>:<ipaddress>:<port> format. """
        if self.network:
            return f"{self.network}:{self.addrinfo[0]}:{self.addrinfo[1]}"
        return f"{self.addrinfo[0]}:{self.addrinfo[1]}"

    def __repr__(self) -> str:
        return self.__str__()

class Conn:
    """ It will be nice to achieve all that out of the box read and writing,
    by just wrapping the socket file descriptor in a os.file type object.
    So you get all the read and write implementations out of the box.
    Atleast thats how golang does it and its super intuitive.

    """
    def __init__(self, sock):
        self.sock = sock
        self.settimeout(2.0)
        if socket.os.name == 'nt':
            # windows socket file descriptors are not treated as
            # normal file descriptors and so cannot be wrapped in
            # file io stream for easy use.
            self.__conn = _SocketWriter(self.sock)
        elif socket.os.name == 'posix':
            self.__conn = socket.io.open(self.sock.fileno(), 'ba')
    
    def write(self, buf: bytes):
        """ send buf of len(buf) bytes into the underlying socket. """
        return self.__conn.write(buf)

    def read(self):
        return self.__conn.read()

    def file(self):
        """ returns a opened file object for reading and writing """
        return self.__conn

    def connect(self, addr: Addr):
        self.sock.connect(addr.addrinfo)

    def srv_bind(self, addrinfo, reuse=True):
        if reuse:
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(addrinfo)
    
    def setblocking(self, flag: bool) -> None:
        """ set socket mode to blocking or non-blocking """
        self.sock.setblocking(flag)

    def settimeout(self, timeout: float) -> None:
        """ set timeout on the socket """
        self.sock.settimeout(timeout)

    def close(self):
        """ close all the connections (socket and io stream) """
        self.sock.close()
        self.__conn.close()

    def shutdown(self, flag: str) -> None:
        """ shutdown the socket connection(read, write or both)
        options === (SHUT_RD, SHUT_WR, SHUT_RDWR)"""
        self.sock.shutdown(flag)
        self.close()

class TCPConn(Conn):
    """ A robust TCP Connection type 

    this connection is like a base connection type it could be opened for 
    listening, connected socket or domant.

    conn_type could be => 'listen'  -> open socket for listening.
                                  'connect' -> connect socket to a remote host.
                                  ''        -> socket already bound to a remote host.
    """

    def __init__(self, addr: Addr, conn_type: str, sock=None):
        if sock == None:
            Conn.__init__(self, socket.socket(socket.AF_INET, socket.SOCK_STREAM))
        else:
            Conn.__init__(self, sock)
        self.addr = addr
        try:
            if conn_type == 'listen':
                self.srv_bind(self.addr.addrinfo)
            elif conn_type == 'connect':
                self.connect(addr)
                self.addr = Addr('tcp', self.sock.getsockname())
            elif conn_type == '':
                return
            else:
                raise NotImplementedError(conn_type)
        except:
            self.sock.close()
            raise
    
    def local_addr(self):
        return self.addr

    def remote_addr(self):
        return Addr('tcp', self.sock.getpeername())

class UDPAddr(Addr):
   """ This represents a udp address """ 
   def __init__(self, network='udp', addrinfo=()):
        Addr.__init__(self, network, addrinfo)

class UDPConn(Conn):
    """ A  simple UDP Connnection """
    def __init__(self, addr: UDPAddr, conn_type: str, sock=None):
        if sock == None:
            Conn.__init__(self, socket.socket(socket.AF_INET, socket.SOCK_DGRAM))
        else:
            Conn.__init__(self, sock)
        self.addr = addr
        self.max_packet_size = 8192
        try:
            if conn_type == 'listen':
                self.srv_bind(self.addr.addrinfo, reuse=False)
            elif conn_type == 'connect':
                self.connect(addr)
                self.addr = Addr('tcp', self.sock.getsockname())
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
        """ Read data from the underlying connection """
        data, raddr = self.sock.recvfrom(self.max_packet_size)
        return data, Addr(addrinfo=raddr)

    def read_from_udp(self) -> tuple[bytes, UDPAddr]:
        data, addr = self.read_from()
        return data, UDPAddr(addrinfo=addr)

    def write_to(self, buf: bytes, addr: Addr) -> int:
        return self.sock.sendto(buf, addr.addrinfo)

    def write_to_udp(self, buf: bytes, addr: UDPAddr) -> int:
        return self.sock.sendto(buf, addr.addrinfo)

    def local_addr(self) -> UDPAddr:
        return UDPAddr(addrinfo=self.sock.getsockname())

    def remote_addr(self) -> UDPAddr:
        return UDPAddr(addrinfo=self.sock.getpeername())


class TCPListener(TCPConn):
    """ A tcp listener """
    queue_size = 10

    def __init__(self, addr: Addr, queue_size=queue_size):
        TCPConn.__init__(self, addr, 'listen')
        self.sock.listen(queue_size)

    def accept(self):
        """ return the next  socket connection in the listen queue """
        self.sock.accept()

    def accept_tcp(self) -> TCPConn:
        """ return a new tcp connection """
        return TCPConn(self.sock.accept().getsockname(), '')

def parse_str_addr(addr_str):
    """ addr_str is in the form '<network>:<ipaddress>:<port>' """
    s = addr_str.split(':')
    return Addr(s[0], (s[1], s[2]))

class InvalidAddrFormat(Exception):
    msg = f'''
    addr is supposed to be of the format
    <protocol>:<ipaddr>:<port> or <ipaddr>:<port>
    '''
    def __init__(self, message=msg):
        super().__init__(message)

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
    return Addr(network, addrinfos[-1][-1])

def parse_ipv4(network, name):
    host, port = get_host_and_port(name)
    addrinfos = get_addrinfo(host, port, 4)
    return Addr(network, addrinfos[-1][-1])

def parse_udp_addr(addr_str):
    return UDPAddr(ResolveAddr(addr_str).addrinfo)

def ResolveAddr(addr: str, addr_type='ipv4', network=None):
    """ spun a new Addr type. if the addr field starts with
    1. tcp/udp then parse_addr_string 
    2. if network is of the form <name>:<port> ex, google.com:80 or 
        localhost:1

    NOTE:
    "addr" always has to be either of the form  '<network>:<ipaddress>:<port>'
    or just '<ipaddress>:<port>'
    """

    if addr.startswith('tcp:') or addr.startswith('udp:'):
        return parse_str_addr(addr)
    else:
        if addr_type == 'ipv6':
            return parse_ipv6(network, addr)
        else:
            return parse_ipv4(network, addr)

def Dial(conn_type: str, addr: str):
    """ Dial connects to the address on a named network.
    it returns a subclass of Conn"""
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
