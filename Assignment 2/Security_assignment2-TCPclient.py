"""
*** Author: Laurent Hayez
*** Date: 13 october 2015
*** Course: Security
*** Objective:
"""

import socket
import pickle
from Security_assignment2_RSA import *

"""
 Client
"""

# Host to contact and port to connect to.
HOST, PORT = 'localhost', 12000

# RSA module
rsa_client = RSAencryption()

def encrypt(data, key):
    return rsa_client.encrypt(data, key)

def decrypt(data):
    return rsa_client.decrypt(data, rsa_client.private_key)

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
# First contact with the server, send public key and receive server's public key.
sock.connect((HOST, PORT))
sock.sendall(pickle.dumps(rsa_client.public_key))
server_public_key = pickle.loads(sock.recv(1024))
print("Sent:     {}".format(rsa_client.public_key))
print("Received: {}".format(server_public_key))
sock.close()

#Need to re-initialize connection
connected = True

while connected == True:
    data = input("Send to rsa secured proxy > ")

    # Encryption of data with server's public key
    encrypted_data = encrypt(data, server_public_key)

    # Create a socket (SOCK_STREAM means a TCP socket)
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    try:
        sock.connect((HOST, 8080))
        sock.sendall(pickle.dumps(encrypted_data))
        received = pickle.loads(sock.recv(4096))
        decrypted_data = decrypt(received)
    finally:
        sock.close()
    if data == "end":
        connected = False
    print("Sent:     {}".format(data))
    print("Encrypted sent: {}".format(encrypted_data))
    print("Received: {}".format(received))
    print("Decrypted received: {}".format(decrypted_data))


