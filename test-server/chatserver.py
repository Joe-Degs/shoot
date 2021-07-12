import netconn

class ChatSrv(netconn.Conn):
    def __init__(self):
        netconn.Conn.__init__(self)
        self.clients = []

    def add(self, name, sock, addrinfo: tuple) -> None:
        client = ChatClient(name, sock, addrinfo)
        self.clients.append(client)

    def remove(self, name: str) -> None:
        for i, cl in enumerate(self.clients):
            if cl.name == name:
                self.clients.pop(i)
                return

    def send(self, msg) -> None:
        for cl in enumerate(self.clients):
            cl.write(msg)

    def send_to(self, name, msg):
        for cl in self.clients:
            if cl.name == name:
                try:
                    cl.write(msg)
                    return
                except:
                    # throw error here
                return

    def start(self):
        """ Start the chat, listen and respond to messages like a champ. :) """
        self.sock.listen(20)
        

class ChatClient(netconn.Conn):
    def __init__(self, name: str, sock_object: socket.socket, addrinfo: tuple):
        netconn.Conn.__init__(self, sock_obj=sock_object)
        self.name = name
        self.addr = addrinfo


class Msg(Enum):
    JOIN    = 0x1
    LEAVE   = 0x2
    NORMAL  = 0x3
    PRIVATE = 0x4

PacketLen = 1 + 2 + 256 + 2048

class Packet:
    
    def __init__(self):
        self.msg_type = None    # 1 B
        self.len = None         # 2 B
        self.data = None        # 256 B
        self.data = None        # 2 KB
        self.packet = bytearray(PacketLen)

    def fill(self, mtype: str, name: str, data: str) -> None:
        self.msg_type = mtype
        self.name = name
        self.len = len(bytes(data.encode('utf8')))
        self.data = bytes(data.encode('utf8'))

    def marshal(self) -> bytearray:
        """
            put packets in bytearray and send them out.

            the header = 256 bytes
            length = 2 bytes
            data = 2 KB

            Returns:
                bytearray object
        """
        self.packet[0] = self.msg_type  # msg type
        self.packet[1:] = self.len      # data len
        self.packet[3:] = self.name     # peer name
        self.packet[260:] = self.data   # message
        return self.packet

    def unmarshal(self, packet: bytes) -> dict:
        """
            Unmarshal a recieved packet into a human readable dict.

            Returns:
                dict
        """
        return {
            msg_type: Msg(packet[0]),
            msg_len: packet[1:3],
            name: packet[3:260].decode('utf8'),
            data: packet[260:].decode('utf8')
        }
