import socket, threading, pickle, requests
from Security_assignment2_RSA import *

#---------------------------------------------------------------------------------------#
class ProxyDispatcher(threading.Thread):

    def __init__(self, incoming_sock, outgoing_sock):
        threading.Thread.__init__(self)
        self.incoming_sock = incoming_sock
        self.outgoing_sock = outgoing_sock

    # Redefine run() from threading.Thread
    def run(self):
        incoming_address = self.incoming_sock.getpeername()
        outgoing_address = self.outgoing_sock.getpeername()

        while 1:
            data = self.incoming_sock.recv(1024)
            self.outgoing_sock.sendall(data)

        print('%s sent to %s: %s' % incoming_address, outgoing_address, data)

        self.outgoing_sock.close()
        self.incoming_sock.close()
#---------------------------------------------------------------------------------------#


#---------------------------------------------------------------------------------------#
class Proxy(threading.Thread):

    def __init__(self):#, incoming_socket):# , remote_addr, remote_port):
        threading.Thread.__init__(self)
        #self.incoming_socket = incoming_socket
        self.proxy_port = 11999
        self.proxy_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        #self.remote_addr = remote_addr
        #self.remote_port = remote_port

    # Redefine run() from threading.Thread
    def run(self):
        self.proxy_socket.bind(('', self.proxy_port))
        self.proxy_socket.listen(1)
        print("Proxy is now ready to receive.")
        cont = True
        while cont:
            incoming_socket, addr = self.proxy_socket.accept()
            received = pickle.loads(incoming_socket.recv(1024))
            print("Received: {}".format(received))
            if received == "end":
                cont = False
            else:
                request = requests.get(received)
                print(request.text[:1000])
                incoming_socket.sendall(pickle.dumps(request.text[:20]))
        # outgoing_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # outgoing_socket.connect((received[0], received[1]))
        #
        # outgoing_thread = ProxyDispatcher(self.incoming_socket, outgoing_socket)
        # outgoing_thread.start()
        # receiving_thread = ProxyDispatcher(outgoing_socket, self.incoming_socket)
        # receiving_thread.start()
#---------------------------------------------------------------------------------------#

        
"""
Starting server.
Server can listen to multiple clients at once.
It waits for connections, and when a client connects,
they exchange their public key. Once this is done they start a 
secure TCP channel with RSA encoding.

I assume that when a client contacts the server for the first time, 
the first thing it does is sending its public key.
"""

rsa = RSAencryption()
server_port, server_socket = 12000, socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.bind(('', server_port))
server_socket.listen(5)

print("The server is ready to receive")

connection_socket, addr = server_socket.accept()
print("Connection from: ", addr)
# Unpickle client's public key (sent as a tuple)
client_public_key = pickle.loads(connection_socket.recv(1024))
print("Received: {}".format(client_public_key))
connection_socket.sendall(pickle.dumps(rsa.public_key))
connection_socket.close()


#connection_socket, addr = server_socket.accept()
thread = Proxy()#connection_socket)
thread.start()