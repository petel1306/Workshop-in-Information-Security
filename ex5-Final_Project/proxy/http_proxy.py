#!/usr/bin/python

from proxy import Proxy
from dlp import detect_c_code
import socket
import re

SERVER_PORT = 800


class HTTPProxy(Proxy):
    """ Represents HTTP proxy connection """

    def enforce_content(self, message):
        
        # Extract header
        separator = '\r\n\r\n'  # indicates end of HTTP header
        header_loc = message.index(separator)
        header = message[0:header_loc]

        # Check if should block
        content_type = re.findall('Content-Type: (\S+)', header)
        print('Content type: {}'.format(content_type)) # debug
        
        return False if content_type and (content_type[0] in ['text/csv', 'application/zip']) else True

    def client_logic(self):
        while self.is_alive() and not self.done:
            request = self.collect_message(self.client_sock)
            if request:
                if detect_c_code(request):
                    print("C code was detected")
                else:
                    self.server_sock.sendall(request.encode())
            else:
                self.done = True

    def server_logic(self):
        while self.is_alive() and not self.done:
            response = self.collect_message(self.server_sock)
            if response:
                if self.enforce_content(response):
                    self.client_sock.sendall(response.encode())
                else:
                    print("HTTP packet dropped")
            else:
                self.done = True


def main():
    # Creating an HTTP proxy server
    sock = HTTPProxy.setup_proxy(SERVER_PORT)
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
        
        proxy = HTTPProxy(conn, addr)
        proxies.append(proxy)
        proxy.start()

    print("\nFinished")


if __name__ == "__main__":
    main()
