"""
*** Author:         Laurent Hayez
*** Date:           24 novembre 2015
*** Description:    Implementation of a simple HTTP proxy server.
"""

import ssl
from requests import get
from http.server import BaseHTTPRequestHandler, HTTPServer


class HTTPProxy(BaseHTTPRequestHandler):

    def do_GET(self):
        request = get(self.path)
        self.wfile.write(request.content)

    def do_POST(self):
        pass


def main():
    server = HTTPServer(('', 9999), HTTPProxy)
    print("HTTP proxy running.")
    server.serve_forever()

if __name__ == '__main__':
    main()

