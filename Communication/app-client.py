import sys
import socket
import selectors
import traceback

import libclient

sel = selectors.DefaultSelector()


def create_request(value):
    return dict(
        type="binary/custom-client-binary-type",
        encoding="binary",
        content=bytes(value, encoding="utf-8"),
    )


def start_connection(host, port, request):
    addr = (host, port)
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setblocking(False)
    sock.connect_ex(addr)
    events = selectors.EVENT_READ | selectors.EVENT_WRITE
    message = libclient.Message(sel, sock, addr, request)
    sel.register(sock, events, data=message)


if len(sys.argv) != 3:
    sys.exit(1)

host, port = sys.argv[1], int(sys.argv[2])
value = {'HELLO FATHER'}
value = str(value)
request = create_request(value) #THIS IS THE MESSAGE! This is where the message is sent!
start_connection(host, port, request)


try:
    while True:
        events = sel.select(timeout=1)
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
        if not sel.get_map():
            break
except KeyboardInterrupt:
    print("caught keyboard interrupt, exiting")
finally:
    sel.close()