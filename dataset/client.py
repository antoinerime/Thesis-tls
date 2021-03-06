#!/usr/bin/env python

import socket
import subprocess
import os
import sys
import select
import threading
import struct
import errno

PTLS_PATH = "/home/antoine/Documents/Memoire/Thesis-tls/"
PACK_FMT = "<I"


def handle_new_connections(s, fd_list, connections, proc):
    while True:
        c, (addr, port) = s.accept()
        fd_list.append(c)
        connections[port] = c
        print("connection from %s:%s" % (addr, port))
        threading.Thread(target=handle_input, args=(c, fd_list, proc)).start()


def handle_input(s, fd_list, proc):
    while True:
        try:
            data = s.recv(2048)
            if len(data) == 0:
                break
            addr, int_port = s.getpeername()
            port = struct.pack(PACK_FMT, int_port)
            data_len = struct.pack(PACK_FMT, len(data))
            proc.stdin.write(port + data_len + data)
        except socket.error as serr:
            print ("handle_input: " + serr.strerror + " port: %s" % int_port)
            break
    fd_list.remove(s)
    # s.close()


def handle_output(proc, connections):
    while True:
        r, _, _ = select.select([proc.stdout], [], [], 0)
        if proc.stdout in r:
            header = os.read(proc.stdout.fileno(), 8)
            port = struct.unpack(PACK_FMT, header[:4])[0]
            data_len = struct.unpack(PACK_FMT, header[4:])[0]
            data = os.read(proc.stdout.fileno(), data_len)
            try:
                client = connections[port]
                client.send(data)
            except KeyError:
                print("KeyError: %s" % port)
            except socket.error as serr:
                print ("send_to_browser: " + serr.strerror + " port: %s" % port)
                connections.pop(port, None)


def main():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("127.0.0.1", 8081))
    s.listen(5)
    # proc = subprocess.Popen([PTLS_PATH + "cli", "localhost", "8443"],
    #                         stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=sys.stdout.fileno())
    proc = subprocess.Popen([PTLS_PATH + "cli", "-p", PTLS_PATH + "plugins/Padding/padding.plugin", "localhost", "8443"],
                            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=sys.stdout.fileno())
    connections = dict()
    fd_list = list()
    try:
        # client = ThreadedSocketServer((HOST, PORT), ClientHandler)
        # client.connections = connections
        # client.fd_list = fd_list

        # client_thread = threading.Thread(target=client.serve_forever)

        # client_thread.daemon = True
        # client_thread.start()

        thread_handle_output = threading.Thread(target=handle_output, args=(proc, connections))

        thread_handle_output.daemon = True
        thread_handle_output.start()

        handle_new_connections(s, fd_list, connections, proc)

    finally:
        proc.terminate()
        for s in fd_list:
            s.close()
        print('Ended')


if __name__ == "__main__":
    # Establish TLS tunnel
    main()
