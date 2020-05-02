#!/usr/bin/env python

import socket
import subprocess
import os
import sys
import select
import struct
import threading

PTLS_PATH = "/home/antoine/Documents/Memoire/Thesis-tls/"
PACK_FMT = "<I"


def handle_input(s, proc, port):
    while True:
        try:
            data, addr = s.recvfrom(2048)
            if len(data) == 0:
                break
            port = struct.pack(PACK_FMT, port)
            data_len = struct.pack(PACK_FMT, len(data))
            proc.stdin.write(port + data_len + data)
        except socket.error as serr:
            print ("handle_input: " + serr.strerror)
            break
        except struct.error as struct_err:
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
                threading.Thread(target=handle_input, args=(sock, proc, port)).start()
                try:
                    connections[port] = sock
                    sock.sendto(data, ("8.8.8.8", 53))
                except KeyError:
                    print("KeyError: %s" % port)


def main():
    # Listen for traffic coming from browser
    # Establish TLS tunnel
    proc = subprocess.Popen(
        [PTLS_PATH + "cli", "-c", PTLS_PATH + "cert/certificate.pem", "-k", PTLS_PATH + "cert/key.pem", "-p", PTLS_PATH + "plugins/Padding/padding.plugin", "localhost",
         "8443"],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=sys.stderr.fileno())
    # proc = subprocess.Popen(
    #     [PTLS_PATH + "cli", "-c", PTLS_PATH + "cert/certificate.pem", "-k", PTLS_PATH + "cert/key.pem", "localhost",
    #      "8443"],
    #     stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=sys.stderr.fileno())
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
