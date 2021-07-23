import enum

class Msg(enum.IntFlag):
    ZERO    = 0x0
    JOIN    = 0x1
    LEAVE   = 0x2
    NORMAL  = 0x3
    PRIVATE = 0x4

PACKET_LEN = 1 + 2 + 256 + 2048

class Packet: 
    def __init__(self):
        self.msg_type: Msg = Msg.ZERO    # 1 B
        self.data_len: bytes = b''         # 2 B
        self.name: bytes = b''        # 256 B
        self.data: bytes =  b''       # 2 KB
        self.packet = bytearray(PACKET_LEN)

    def fill(self, msg_type: Msg, name: str, data: str) -> bytes:
        self.msg_type = msg_type
        self.name = bytes(name.encode('utf8'))
        self.data = bytes(data.encode('utf8'))
        self.data_len = bytes(len(self.data))
        return bytes(self.marshal_bytes())

    def marshal_bytes(self) -> bytearray:
        """
            put packets in bytearray and send them out.

            the header = 256 bytes
            length = 2 bytes
            data = 2 KB

            Returns:
                bytearray object
        """
        self.packet[0] = self.msg_type  # msg type
        self.packet[1:] = self.data_len  # data len
        self.packet[3:] = self.name     # client name
        self.packet[260:] = self.data   # message
        return self.packet

    def unmarshal(self, packet: bytes) -> dict:
        """
            Unmarshal a recieved packet into a  dict.

            Returns:
                dict
        """
        return {
            'msg_type': Msg(packet[0]),
            'data_len': int(packet[1:3]),
            'name': packet[3:260].decode('utf8'),
            'data': packet[260:].decode('utf8')
        }
