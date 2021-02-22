#!/usr/bin/python

from proxy import Proxy
import socket
import sys
import re
import struct

SERVER_PORT = 210

class FTPProxy(Proxy):
    """ Represents HTTP proxy connection """

    ftp_dev = '/sys/class/fw/proxy/add_ftp'

    def pass_ftp_data(self, ftp_ip, ftp_port):
        client_ip = socket.inet_aton(ftp_ip)
        server_ip = socket.inet_aton(self.dst[0])

        if sys.byteorder == 'little':
            buf = client_ip + server_ip + struct.pack('<H', ftp_port)  # little-endian byte order
        else:
            buf = client_ip + server_ip + struct.pack('>H', ftp_port)  # big-endian byte order

        with open(self.ftp_dev, 'wb') as file:
            file.write(buf)

    def parse_ftp(self):
        port_command = re.findall('PORT (.*)\r\n')
        if not port_command:
            return
        i1, i2, i3, i4, p1, p2 = port_command[0].split(',')
        ip = '.'.join((i1, i2, i3, i4))
        port = 256 * int(p1) + int(p2)
        self.pass_ftp_data(ip, port)

    def client_logic(self):
        while self.is_alive() and not self.done:
            request = self.client_sock.recv(65535)
            if request:
                self.parse_ftp(request)
                self.server_sock.sendall(request)
            else:
                self.done = True

    def server_logic(self):
        while self.is_alive() and not self.done:
            response = self.client_sock.recv(65535)
            if response:
                self.parse_ftp()
                self.server_sock.sendall(response)
            else:
                self.done = True


def main():
    # Creating an HTTP proxy server
    sock = FTPProxy.setup_proxy(SERVER_PORT)
    proxies = []

    # Handle connections until ctrl^c is called
    while True:
        try:
            conn, addr = sock.accept()
        except KeyboardInterrupt:
            for proxy in proxies:
                proxy.done = True
            for proxy in proxies:
                proxy.join()
            break
        proxy = FTPProxy(conn, addr)
        proxies.append(proxy)
        proxy.start()

    print("Finished")


if __name__ == "__main__":
    main()
