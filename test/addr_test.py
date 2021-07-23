from net.address import *

def tcp():
    a = resolve_tcp_addr('localhost:80', 'tcp6')
    print(a)

def localb():
    a = resolve_tcp_addr('[localhost]:444', 'tcp')
    print(a)

def test_split():
    host, port = split_host_port('[::1]:80')
    print(host, port)

def resolve_python():
    a = resolve_tcp_addr('python.org:http', 'tcp')
    print(a)



if __name__ == '__main__':
    resolve_python()
