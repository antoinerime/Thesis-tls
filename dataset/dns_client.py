#!/usr/bin/env python

import socket
import subprocess
import os
import sys
import select
import threading
import struct
import errno
import getopt

PTLS_PATH = "/home/antoine/Documents/Memoire/Thesis-tls/"
PACK_FMT = "<I"

HOST = ""
PORT = 0
PADDING = False

def handle_input(s, connections):
    global HOST, PORT, PADDING
    init_proc = True
    proc = None
    while True:
        try:
            data, (addr, port) = s.recvfrom(2048)
            port_int = port
            connections[port] = (addr, port)
            if init_proc:
                if PADDING:
                    args = ["../cli", "-p", "../plugins/Padding/padding.plugin", HOST, PORT]
                else:
                    args = ["../cli", HOST, PORT]
                proc = subprocess.Popen(args, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=sys.stdout.fileno())
                thread_handle_output = threading.Thread(target=handle_output, args=(proc, connections, s))

                thread_handle_output.daemon = True
                thread_handle_output.start()
                init_proc = False
            if len(data) == 0:
                break
            port = struct.pack(PACK_FMT, port)
            data_len = struct.pack(PACK_FMT, len(data))
            proc.stdin.write(port + data_len + data)
        except socket.error as serr:
            print ("handle_input: " + serr.strerror + " port: %s" % port_int)
            break
    # s.close()


def handle_output(proc, connections, s):
    while True:
        r, _, _ = select.select([proc.stdout], [], [], 0)
        if proc.stdout in r:
            header = os.read(proc.stdout.fileno(), 8)
            port = struct.unpack(PACK_FMT, header[:4])[0]
            data_len = struct.unpack(PACK_FMT, header[4:])[0]
            data = os.read(proc.stdout.fileno(), data_len)
            try:
                dst = connections[port]
                s.sendto(data, dst)
            except KeyError:
                print("KeyError: %s" % port)
            except socket.error as serr:
                print ("send_to_browser: " + serr.strerror + " port: %s" % port)
                connections.pop(port, None)


def main():
    global PADDING
    if os.geteuid() != 0:
        exit("You need to have root privileges to run this script.\nPlease try again, this time using 'sudo'. Exiting.")
    try:
        opts, args = getopt.getopt(sys.argv[1:], "", ["padding"])
    except getopt.GetoptError as err:
        print str(err)
        sys.exit(2)
    for o, a in opts:
        if o in "--padding":
            PADDING = True
    if len(args) != 2:
        print('Missing host and port')
        return
    global HOST, PORT
    HOST = args[0]
    PORT = args[1]

    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("127.0.0.1", 53))
    # s.listen(5)
    connections = dict()
    fd_list = list()
    try:
        # client = ThreadedSocketServer((HOST, PORT), ClientHandler)
        # client.connections = connections
        # client.fd_list = fd_list

        # client_thread = threading.Thread(target=client.serve_forever)

        # client_thread.daemon = True
        # client_thread.start()


        handle_input(s, connections)

    finally:
        for s in fd_list:
            s.close()
        print('Ended')


if __name__ == "__main__":
    # Establish TLS tunnel
    main()
