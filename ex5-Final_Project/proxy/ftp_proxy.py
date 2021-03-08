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
        """ Sends to the firewall client (ip, port) of the new ftp data session """
        
        print('FTP data: ip = {}, port = {}'.format(ftp_ip, ftp_port))
        
        client_ip = socket.inet_aton(ftp_ip)
        server_ip = socket.inet_aton(self.dst[0])
        
        # endianness byte order considerations
        pack = struct.pack('<H', ftp_port) if sys.byteorder == 'little' else struct.pack('>H', ftp_port)
        buf = client_ip + server_ip + pack

        with open(self.ftp_dev, 'wb') as file:
            file.write(buf)

    def extract_port_command(self, message):
        ''' Extracts the port command from a message and pass it (if exists)'''
        
        port_command = re.findall('PORT (\S+)', message)
        
        if port_command:
            i1, i2, i3, i4, p1, p2 = port_command[0].split(',')
            ip = '.'.join((i1, i2, i3, i4))
            port = 256 * int(p1) + int(p2)
            self.pass_ftp_data(ip, port)

    def client_logic(self):
        while self.is_alive() and not self.done:
            request = self.collect_message(self.client_sock)
            if request:
                self.server_sock.sendall(request.encode())
                self.extract_port_command(request)
            else:
                self.done = True

    def server_logic(self):
        while self.is_alive() and not self.done:
            response = self.collect_message(self.server_sock)
            if response:
                self.client_sock.sendall(response.encode())
            else:
                self.done = True


def main():
    # Creating an HTTP proxy server
    sock = FTPProxy.setup_proxy(SERVER_PORT)
    proxies = []
    
    print("\nStarting")

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
        
        print("\nConnection accepted")
        
        proxy = FTPProxy(conn, addr)
        proxies.append(proxy)
        proxy.start()

    print("\nFinished")


if __name__ == "__main__":
    main()
