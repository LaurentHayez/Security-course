"""
*** Author:         Laurent Hayez
*** Date:           24 november 2015
*** Description:    Implementation of a simple HTTP proxy server.
***                 It checks in a black list whether a url can be requested or not
***                 Upgrade: Addition of a cache filter.
"""
import re

from requests import get
from http.server import BaseHTTPRequestHandler, HTTPServer
from beaker.cache import CacheManager
from beaker.util import parse_cache_config_options
import memcache, hashlib


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
        cls.cache = memcache.Client(['127.0.0.1:9999'], debug=0)

    def put_in_cache(self, key, web_page):
        # self.cache.set(hashlib.sha1(web_page.headers['host'].encode('utf-8')).hexdigest(), web_page)
        self.cache.set(key, web_page.content)

    def get_from_cache(self, web_page):
        # return self.cache.get(hashlib.sha1(web_page.encode('utf-8')).hexdigest())
        return self.cache.get(web_page)

    def cachable(self, request):
        cache = request.headers.get('cache-control')
        if cache != 'no-cache' and cache != 'no-store' and cache != 'max-age=0':
            return True
        return False

    def do_GET(self):

        value = self.get_from_cache(self.path)
        if value:
            print("\n"+value.content[:100]+"\n")
            print('Web page fetched from cache.')
            self.send_response(value.status_code)
            self.send_header('Content-type', value.headers.get('content-type'))
            self.end_headers()
            self.wfile.write(value.content)
        else:
            if self.treat_request(self.headers['host']):
                request = get(self.path)

                #check if we can cache the page
                if self.cachable(request):
                    print('Web page cached.')
                    self.put_in_cache(self.path, request)

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
    """
    #Creating the cache manager
    cache_opts = {
        'cache.type': 'file',
        'cache.data_dir': '/tmp/cache/data',
        'cache.lock_dir': '/tmp/cache/lock'
    }
    cache = CacheManager(**parse_cache_config_options(cache_opts))
    @cache.cache('gophers', expire = 3600)
    def get_results(search_param):
        data = cache.get_cache()
        return data

    results = get_results('gophers')
    """


    HTTPProxy.parse_blacklist()
    HTTPProxy.init_cache()
    server = HTTPServer(('', 9999), HTTPProxy)
    print("HTTP proxy running.")
    server.serve_forever()

if __name__ == '__main__':
    main()
