#!/usr/bin/python

from proxy import Proxy
import socket
import re

SERVER_PORT = 800


class HTTPProxy(Proxy):
    """ Represents HTTP proxy connection """

    def parse_http(self, sock):
        
        # Collect message
        message = ''
        chunk_size = 512
        
        while True:
            chunk = sock.recv(chunk_size)
            message += chunk.decode()
            if len(chunk) < chunk_size:
                break
        
        # Check if empty request (done with requests)
        if not message:
            return None, False

        # Extract header
        separator = '\r\n\r\n'  # indicates end of HTTP header
        header_loc = message.index(separator)
        header = message[0:header_loc]
        print('header:\n{}\n'.format(header))

        # Check if should block
        content_type = re.findall('Content-Type: (\S+)', header)
        should_block = True if content_type and (content_type[0] in ['text/csv', 'application/zip']) else False

        return message, should_block

    def client_logic(self):
        while self.is_alive() and not self.done:
            request, should_block = self.parse_http(self.client_sock)
            if request:
                self.server_sock.sendall(request.encode())
            else:
                self.done = True

    def server_logic(self):
        while self.is_alive() and not self.done:
            response, should_block = self.parse_http(self.server_sock)
            if response:
                if should_block:
                    print("HTTP packet dropped")
                else:
                    self.client_sock.sendall(response.encode())
            else:
                self.done = True


def main():
    # Creating an HTTP proxy server
    sock = HTTPProxy.setup_proxy(SERVER_PORT)
    proxies = []
    
    print("Starting")

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
        
        print("Connection accepted")
        
        proxy = HTTPProxy(conn, addr)
        proxies.append(proxy)
        proxy.start()

    print("\nFinished")


if __name__ == "__main__":
    main()