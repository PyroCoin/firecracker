import socket


socket_communication = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
socket_communication.bind((socket.gethostname(), 4004))

socket_communication.listen(10)

while True:
    clientSocket, address = socket_communication.accept()