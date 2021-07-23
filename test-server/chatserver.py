import net

class ChatClient(net.TCPConn):
    def __init__(self, name: str, sock, addr: net.Addr):
        net.TCPConn.__init__(self, addr, '', sock)
        self.name = name

class ChatHandler:
    pass

class ChatSrv(net.TCPListener):
    def __init__(self, addr):
        net.TCPListener.__init__(self, addr)
        self.clients = []

    def start(self, handler: ChatHandler):
        try:
            # do some kind of polling here.
            # accept connections while at the same time checking
            # if any of the clients have sent something into
            # the wire.
        except Exception as e:
            raise e


    def add(self, name, sock, addrinfo: tuple) -> None:
        client = ChatClient(name, sock, net.Addr.from_addrinfo(addrinfo))
        self.clients.append(client)

    def remove(self, name: str) -> None:
        for i, cl in enumerate(self.clients):
            if cl.name == name:
                self.clients.pop(i)
                return

    def send(self, msg) -> None:
        for cl in self.clients:
            try:
                cl.write(msg)
            except Exception as e:
                raise e

    def sendto(self, name, msg):
        for cl in self.clients:
            if cl.name == name:
                try:
                    cl.write(msg)
                    return
                except Exception as e:
                    raise e
