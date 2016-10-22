"""
*** Author:         Laurent Hayez
*** Date:           24 november 2015
*** Description:    Implementation of a simple HTTP proxy server.
***                 It checks in a black list whether a url can be requested or not
***                 Upgrade: Addition of a cache filter.
***                          Using Redis as cache manager. Don't forget to start redis server by
***                             redis-server (started by default on port 6379)
"""
import re

from requests import get
from http.server import BaseHTTPRequestHandler, HTTPServer
import hashlib, redis, pickle


class HTTPProxy(BaseHTTPRequestHandler):

    @classmethod
    def parse_blacklist(cls):
        bl_file = open('blacklist.txt', 'r')
        # for all the lines in the blacklist.txt file, the following is applied:
        # ads.* => ads\.\* via re.escape
        # ads\.\* => ads\..* via .replace('\*', '.*') (Same for all lines in the file)
        # Every such element => elem1|elem2|elem3|... via '|'.join()
        # This string is compiled to a regex object which can be used to match the url.
        # Note: had to replace \| because it somehow escaped it too...
        cls.blacklist = re.compile(('|'.join([re.escape(x).replace('\\*', '.*').replace('\n', '')
                                              for x in bl_file])).replace('\|', '|'))

    @classmethod
    def init_cache(cls):
        cls.cache = redis.Redis("localhost")

    def put_in_cache(self, key, web_page):
        # hash key so that there is no forbidden caracters
        key = hashlib.sha1(key.encode('utf-8')).hexdigest()
        # web_page is the request done with requests.get(...). Pickle it so that we can get it later
        self.cache.set(key, pickle.dumps(web_page))

    def get_from_cache(self, key):
        key = hashlib.sha1(key.encode('utf-8')).hexdigest()
        return self.cache.get(key)

    def cachable(self, request):
        cache_control = request.headers.get('cache-control')
        print('\n\n', request.headers, '\n\n')
        #print("Cache-control: ", cache_control)
        #return cache_control != 'no-cache' and cache_control != 'no-store' and cache_control != 'max-age=0'
        return cache_control and not ('no-cache' in cache_control or 'no-store' in cache_control or 'max-age=0' in cache_control)

    def do_GET(self):
        # value can be None, so unpickle it only if it is not none
        value = self.get_from_cache(self.path)
        if value: # if value exists, then it is in the cache
            value = pickle.loads(value)
            print('Web page fetched from cache.')
            self.send_response(value.status_code)
            self.send_header('Content-type', value.headers.get('content-type'))
            self.end_headers()
            self.wfile.write(value.content)
        else: # else the value is not in the cache
            if self.treat_request(self.headers['host']):
                request = get(self.path)

                #check if we can cache the page
                if self.cachable(request):
                    print('Web page cached.')
                    self.put_in_cache(self.path, request)
                else:
                    print('Web page not cachable.')

                self.send_response(request.status_code)
                self.send_header('Content-type', request.headers.get('content-type'))
                self.end_headers()
                self.wfile.write(request.content)
            else:
                self.send_response(403)
                self.send_header('Content-type', 'text/html; charset=UTF-8')
                self.end_headers()
                self.wfile.write('<html><head><title>Error 403: Forbidden Access. </title></head>'.encode('utf-8'))
                self.wfile.write('<body><h1>Error 403: Forbidden Access.</h1>'.encode('utf-8'))
                self.wfile.write('<p>Content blocked by proxy</p></body></html>'.encode('utf-8'))

    def treat_request(self, url):
        return False if self.blacklist.match(url) else True


def main():
    HTTPProxy.parse_blacklist()
    HTTPProxy.init_cache()
    server = HTTPServer(('', 9999), HTTPProxy)
    print("HTTP proxy running.")
    server.serve_forever()

if __name__ == '__main__':
    main()
