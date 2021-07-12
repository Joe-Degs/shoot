import socket

def Addr(host: str):
    return socket.getaddrinfo(host='google.com', port=None, \
                              family=socket.AF_INET, type=socket.SOCK_STREAM)[0]

def OpenSocket():
    ai = Addr('localhost')
    return socket.socket(ai[0], ai[1])


def OpenSrvSock():
    socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    return s.bind((socket.gethostname(), 6969))

PORT = 6996

# it doesnt hurt to have a conn object
class Conn:
    """
        The Conn is an idealized customized socket connection that a p2p chat system
        will be built on. It will be tweaked to be used as the backbone for all communications
        in the network, this include both tcp and tcp.
        All other communication channels are going to be overlayed on the stream. It is going to
        be extensible because thats what good design is.

        Most of the methods on the socket.socket class need flags. I have not figured that out.
        On figuring them out. I'll have to have to set the flags necessary to allow me to build the
        type of system i want on this transport layer network.

        Sockets have to be ipversion agnostic, whether you are using ipv4 or ipv6 or both you might be
        able to just communicate on this system. Its an inclusive system and everybody can join in the
        conversation.

        For stream sockets, there is really much to do i think, apart from the numerous configurations
        that tcp has. Implementing stream sockets itself might be difficult but using them is cool

        UDP connections are going to have to keep track of ip addresses of the remote party at the other
        edge of the socket connection. The ipaddress module will do for this kind of stuff.

        The connections need to be unblocking i think. And socket programming comes with the added task of
        having to know about multiplexing, multithreading and polling and all this concurrency related stuff.
        I do not want the sockets to block, i want like a poll sort of thing. where you are off somewhere,
        when connections come, they get handled and everything is alright. So concurrency and stuff.

        Since this is a distributed system, the conn objects will have to be shared with other nodes in
        the system if you want to be discovered and all those sorts of things.
        If a peer is actively participating in the system, it means it might be listening and so it shares
        its ip address with the group.
    """

    sock_family = socket.AF_INET
    sock_type = socket.SOCK_STREAM
    
    def __init__(self, family=sock_family, stype=sock_type, sock_obj=None):
        if sock_obj != None:
            self.sock = sock_obj
        else:
            self.sock = self.open(family, stype)

    def open(self, family=sock_family, stype=sock_type):
        self.sock = socket.socket(family, stype)

    def sockopts(self):
        """ Socket options for servers. """
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.setnonblocking(False)

    def srv_open(self, port=PORT):
        """ open a server socket to and probably listen on it for connections """
        self.sockopts()
        self.sock.bind((socket.getsockname(), port))

    def write(self, buf):
        """ sock.send(data[, flags]) -> count
            write msg of n bytes to into a tcp connection"""
        buflen = len(buf)
        tsent = 0
        while sent < buflen:
            sent = self.sock.send(buf[tsent:])
            if sent == 0:
                raise RuntimeError('socket is broken')
            tsent += sent

    def read(self, msg_len):
        """ read data from underlying socket into buffer and return it """
        chunks = []
        bytes_rcv = 0
        while bytes_rcd < msg_len:
            chunk = self.sock.recv(min(msg_len - bytes_rcd, 2048))
            if chunk == b'':
                raise RuntimeError('socket is broken')
            chunks.append(chunk)
            bytes_rcd += len(chunk)
        return b''.join(chunks)

    def writeto(self, buf, ipaddr):
        """ sock.sendto(data[, flags], address) -> count

            write data from buf into an underlying udp socket connection. """
        pass

    def read_from(self, buf):
        """ sock.recvfrom(buffersize[, flags]) -> (data, address info)

            read from underlying buffer but also return senders info
            what to do with the senders address incase we want to continue
            this convo """
        pass






"""
    GENERAL NOTE TO SELF:

    Coming from golang, dealing with errors comes naturally to me. Now that i am writing python
    i might forget the essence of handling errors, so always remember to handle all errors
    appropriately and return them if needed. Like Rob Pike said "errors are just values,
    nothing special you could do anything with it, you can even send on to your mama
"""
