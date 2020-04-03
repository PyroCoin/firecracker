import socket

yourHost = socket.gethostname()
yourIP = socket.gethostbyname(yourHost)

print(yourIP)
