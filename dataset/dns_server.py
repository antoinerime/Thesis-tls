#!/usr/bin/env python

import socket
import subprocess
import os
import sys
import select
import struct
import threading
import getopt

PTLS_PATH = "/home/{}/Thesis-tls/"
PACK_FMT = "<I"
SOCKET_TIMEOUT = 120

def handle_input(s, proc, port):
    port = struct.pack(PACK_FMT, port)
    while True:
        try:
            data, addr = s.recvfrom(2048)
            if len(data) == 0:
                break
            data_len = struct.pack(PACK_FMT, len(data))
            proc.stdin.write(port + data_len + data)
        except socket.timeout as serr:
            break
        except struct.error as struct_err:
            print 'unpacck error'
            pass # UDP error ?
    s.close()


def handle_output(proc, connections):
    while True:
        r, _, _ = select.select([proc.stdout], [], [], 0)
        if proc.stdout in r:
            header = os.read(proc.stdout.fileno(), 8)
            port = struct.unpack(PACK_FMT, header[:4])[0]
            data_len = struct.unpack(PACK_FMT, header[4:])[0]
            data = os.read(proc.stdout.fileno(), data_len)

            if port in connections:
                sock = connections[port]
                sock.sendto(data, ("8.8.8.8", 53))
            else:
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.settimeout(SOCKET_TIMEOUT)
                threading.Thread(target=handle_input, args=(sock, proc, port)).start()
                try:
                    connections[port] = sock
                    sock.sendto(data, ("8.8.8.8", 53))
                except KeyError:
                    print("KeyError: %s" % port)


def main():
    padding = False
    try:
        opts, args = getopt.getopt(sys.argv[1:], "", ["padding"])
    except getopt.GetoptError as err:
        print str(err)
        sys.exit(2)
    for o, a in opts:
        if o in "--padding":
            padding = True
            if os.geteuid() != 0:
                exit("You need to have root privileges to run this script.\nPlease try again, this time using 'sudo'. Exiting.")

    if len(args) != 2:
        print('Missing host and port')
        return
    host = args[0]
    port = args[1]

    # Listen for traffic coming from browser
    # Establish TLS tunnel

    if padding:
        args = ["../cli", "-c", "../cert/certificate.pem", "-k", "../cert/key.pem", "-p", "../plugins/Padding/padding.plugin", host, port]
    else:
        args = ["../cli", "-c", "../cert/certificate.pem", "-k", "../cert/key.pem", host, port]
    proc = subprocess.Popen(args, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=sys.stdout.fileno())
    fd_list = list()
    connections = dict()
    port_map = dict()

    try:
        thread_handle_output = threading.Thread(target=handle_output, args=(proc, connections))

        thread_handle_output.daemon = True
        thread_handle_output.start()

        thread_handle_output.join()
    finally:
        proc.terminate()
        for s in fd_list:
            s.close()
        print('Ended')


if __name__ == "__main__":
    main()
