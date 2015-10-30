"""
*** Author: Laurent Hayez
*** Date: 13 october 2015
*** Course: Security
*** Objective:
"""


import socket, threading, pickle, requests
import Security_assignment2_RSA


#---------------------------------------------------------------------------------------#
class ProxyRequestsHandler(threading.Thread):

    def __init__(self, proxy_rsa, client_public_key):
        threading.Thread.__init__(self)
        self.proxy_rsa = proxy_rsa
        self.client_public_key = client_public_key
        self.proxy_port = 8080
        self.secure_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # Redefine run() from threading.Thread
    def run(self):
        self.secure_socket.bind(('', self.proxy_port))
        self.secure_socket.listen(1)
        print("The proxy is ready to receive your requests.")
        cont = True
        while cont:
            incoming_socket, addr = self.secure_socket.accept()
            received = pickle.loads(incoming_socket.recv(1024))
            print("Received: {}".format(received))
            decrypted_message = self.decrypt(received)
            print("Decrypted request: {}".format(decrypted_message))
            if decrypted_message == "end":
                cont = False
            else:
                request = requests.get(decrypted_message)
                encrypted_message = self.encrypt(request.text[:1000])
                incoming_socket.sendall(pickle.dumps(encrypted_message))

    def encrypt(self, message):
        return self.proxy_rsa.encrypt(message, self.client_public_key)

    def decrypt(self, message):
        return self.proxy_rsa.decrypt(message, self.proxy_rsa.private_key)
#---------------------------------------------------------------------------------------#

"""
*** class: Proxy
*** inherits: threading.Thread
*** Description:
***     Initializes with proxy's private key and client's public key.
***     At initialisation, a new thread is created to handle client's requests.
***     We also initialize the proxy's private key, the public's
"""
#---------------------------------------------------------------------------------------#
class Proxy(threading.Thread):

    def __init__(self):
        threading.Thread.__init__(self)
        self.proxy_rsa = Security_assignment2_RSA.RSAencryption()
        self.proxy_port = 12000
        self.proxy_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # Redefine run() from threading.Thread
    def run(self):

        #while 1:
        # self.proxy_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.proxy_socket.bind(('', self.proxy_port))
        self.proxy_socket.listen(5)

        print("The server is ready to receive")
        connection_socket, addr = self.proxy_socket.accept()
        print("Connection from: ", addr)
        # Unpickle client's public key (sent as a tuple)
        client_public_key = pickle.loads(connection_socket.recv(1024))
        print("Received: {}".format(client_public_key))
        connection_socket.sendall(pickle.dumps(self.proxy_rsa.public_key))

        connection_socket.close()

        requests_thread = ProxyRequestsHandler(self.proxy_rsa, client_public_key)
        requests_thread.start()
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


#connection_socket, addr = server_socket.accept()
thread = Proxy()#connection_socket)
thread.start()