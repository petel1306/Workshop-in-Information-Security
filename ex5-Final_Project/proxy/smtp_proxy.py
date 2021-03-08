#!/usr/bin/python

from proxy import Proxy
from dlp import detect_c_code
import socket
import re

SERVER_PORT = 250


class SMTPProxy(Proxy):
    """ Represents SMTP proxy connection """

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
                if detect_c_code(response):
                    print("C code was detected")
                else:
                    self.client_sock.sendall(response.encode())
            else:
                self.done = True


def main():
    # Creating an SMTP proxy server
    sock = SMTPProxy.setup_proxy(SERVER_PORT)
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
        
        proxy = SMTProxy(conn, addr)
        proxies.append(proxy)
        proxy.start()

    print("\nFinished")


if __name__ == "__main__":
    main()
