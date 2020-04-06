import sys
import socket
import selectors
import traceback
import time
import threading

from Communication import libserver

class Server:

    def __init__(self, host, port):
        self.sel = selectors.DefaultSelector()
        self.host = host
        self.port = port
        self.recieved_messages = []


    def accept_wrapper(self, sock):
        conn, addr = sock.accept()  # Should be ready to read
        print("accepted connection from", addr)
        conn.setblocking(False)
        self.message = libserver.Message(self.sel, conn, addr)
        self.sel.register(conn, selectors.EVENT_READ, data=self.message)


    
    def mainConnection(self):
        lsock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # Avoid bind() exception: OSError: [Errno 48] Address already in use
        lsock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        lsock.bind((self.host, self.port))
        lsock.listen()
        print("listening on", (self.host, self.port))
        lsock.setblocking(False)
        self.sel.register(lsock, selectors.EVENT_READ, data=None)
        

        try:
            while True:
                events = self.sel.select(timeout=None)
                for key, mask in events:
                    if key.data is None:
                        self.accept_wrapper(key.fileobj)
                    else:
                        self.message = key.data
          
                        
                        try:
                            self.message.process_events(mask)
                            print(self.message.request)
                            
                        except Exception:
                            print(
                                "main: error: exception for",
                                f"{self.message.addr}:\n{traceback.format_exc()}",
                            )
                            
                            self.message.close()
                    data = self.message.getMessage()
                    self.recieved_messages.append(data)

                            
                            
                            
                            
       
        
        except KeyboardInterrupt:
            print("caught keyboard interrupt, exiting")
        finally:
            self.sel.close()

    def incomingData(self):
        while True:
            self.listClone = self.recieved_messages.copy()
            
            

            












