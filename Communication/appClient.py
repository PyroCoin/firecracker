import sys
import socket
import selectors
import traceback
import asyncio

from Communication import libclient

class Client(asyncio.Protocol):
    def __init__(self):
        self.sel = selectors.DefaultSelector()


    def create_request(self, value):
        return dict(
            type="binary/custom-client-binary-type",
            encoding="binary",
            content=bytes(value, encoding="utf-8"),
        )


    def start_connection(self, host, port, request):
        addr = (host, port)
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setblocking(False)
        sock.connect_ex(addr)
        events = selectors.EVENT_READ | selectors.EVENT_WRITE
        message = libclient.Message(self.sel, sock, addr, request)
        self.sel.register(sock, events, data=message)


    def send(self, message, host, port):
        value = message
        value = str(value)
        request = self.create_request(value) #THIS IS THE MESSAGE! This is where the message is sent!
        self.start_connection(host, port, request)


        try:
            while True:
                events = self.sel.select(timeout=1)
                for key, mask in events:
                    message = key.data
                    try:
                        message.process_events(mask)
                    except Exception:
                        print(
                            "main: error: exception for",
                            f"{message.addr}:\n{traceback.format_exc()}",
                        )
                        message.close()
                # Check for a socket being monitored to continue.
                if not self.sel.get_map():
                    break
        except KeyboardInterrupt:
            print("caught keyboard interrupt, exiting")
        finally:
            self.sel.close()



def ClientFunction(host, port):
    theClient = Client()

    theClient.send('HELLO!', host, port)
    print('hello')

async def connect_to_server(loop):
    try:
        await loop.create_connection(ClientFunction('127.0.0.1', 5050))
    except ValueError:
        pass
    


def main():
    loop = asyncio.get_event_loop()
    loop.create_task(connect_to_server(loop))
    loop.create_task(connect_to_server(loop))
    loop.create_task(connect_to_server(loop))
    loop.create_task(connect_to_server(loop))

    loop.run_until_complete(connect_to_server(loop))
    
            
