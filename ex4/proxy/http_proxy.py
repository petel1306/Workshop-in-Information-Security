#!/usr/bin/python

from proxy import Proxy
import socket
import re

SERVER_PORT = 800


class HTTPProxy(Proxy):
    """ Represents HTTP proxy connection """

    def parse_http(self, sock):
        message = ''
        chunk = ''
        separator = '\r\n\r\n'  # indicates end of HTTP header

        while separator not in chunk:
            chunk = sock.recv(512)
            if not chunk:
                return None
            message += chunk

        header_loc = message.index(separator)
        header = message[0:header_loc]

        content_length = re.findall('\r\nContent-Length: ([0-9+])', header)
        if not content_length:  # It's a request
            return message

        # It's a response

        content_type = re.findall('\r\nContent-Type: (\S+)\r\n', header)

        should_block = True if content_type[0] in ['text/csv', 'application/zip'] else False

        remains = int(content_length[0]) - (len(message) - (header_loc + len(separator)))
        message += sock.recv(remains)

        return message, should_block

    def client_logic(self):
        while self.is_alive() and not self.done:
            request = self.parse_http(self.client_sock)
            # Check if done with requests
            if request:
                self.server_sock.sendall(request)
            else:
                self.done = True

    def server_logic(self):
        while self.is_alive() and not self.done:
            response, should_block = self.parse_http(self.server_sock)
            # Check if done with requests
            if response:
                if should_block:
                    print("HTTP packet dropped")
                else:
                    self.client_sock.sendall(response)
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

    print("Finished")


if __name__ == "__main__":
    main()