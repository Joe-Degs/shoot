from typing import Union, Optional, Type, TypeVar
import socket
import io
import os

from .address import *

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
    def __init__(self, addr: Union[Addr, TCPAddr], conn_type: Optional[str]=None,
            sock: Optional[socket.socket]=None) -> None:
        if sock == None:
            Conn.__init__(self, socket.socket(socket.AF_INET, socket.SOCK_STREAM,
                    socket.IPPROTO_TCP))
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
    def __init__(self, addr: Union[Addr, UDPAddr], conn_type: Optional[str]=None,
            sock: Optional[socket.socket]=None) -> None:
        if sock == None:
            Conn.__init__(self, socket.socket(socket.AF_INET, socket.SOCK_DGRAM,
                socket.IPPROTO_UDP))
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


def dial(address: str, network: Optional[str]=None):
    """ 
    dial connects to network the address endpoint
    
    see function resolve_addr for description of network and address parameters
    """
    return NotImplementedError()

def listen(address: str, network: str):
    """ listen announces and waits for connections on a local network address.

    the network must be a "tcp", "tcp4", "tcp6", "udp", "udp4" or "udp6"
    """
    return NotImplementedError()
