# coding: utf-8
__doc__ = 'Helper methods to download and crawl web content using threads'

import os
import re
import collections 
import random
import urllib
import urllib2
import cookielib
import urlparse
import StringIO
import time
import datetime
import socket
import gzip
import threading
import contextlib
import requests
try:
    import hashlib
except ImportError:
    import md5 as hashlib
import adt
import alg
import common
import settings
try:
    import pdict
except ImportError:
    # sqlite not installed
    pdict = None

SLEEP_TIME = 0.1 # how long to sleep when waiting for network activity



class Download:
    """
    cache:
        a pdict object to use for the cache
    cache_file:
        filename to store cached data
    read_cache:
        whether to read from the cache
    write_cache:
        whether to write to the cache
    use_network:
        whether to download content not in the cache
    user_agent
        the User Agent to download content with
    timeout:
        the maximum amount of time to wait for http response
        also you can pass a tuple as (connect timeout, read timeout)
    delay:
        the minimum amount of time (in seconds) to wait after downloading content from a domain per proxy
    proxy_file:
        a filename to read proxies from
    proxy_get_fun:
        a method to fetch a proxy dynamically
    proxies:
        a list of proxies to cycle through when downloading content
    proxy:
        a proxy to be used for downloading
    opener:
        an optional opener to use instead of using urllib2 directly
    headers:
        the headers to include in the request
    data:
        what to post at the URL
        if None (default) then a GET request will be made
    num_retries:
        how many times to try downloading a URL when get an error
    num_redirects:
        how many times the URL is allowed to be redirected, to avoid infinite loop
    num_caches:
        how many cache database(SQLite) files to be used
    force_html:
        whether to download non-text data
    force_ascii:
        whether to only return ascii characters
    max_size:
        maximum number of bytes that will be downloaded, or None to disable
    default:
        what to return when no content can be downloaded
    pattern:
        a regular expression or function for checking the downloaded HTML whether valid or not
    acceptable_errors:
        a list contains all acceptable HTTP codes, don't try downloading for them e.g. no need to retry for 404 error
    keep_ip_ua:
        If it's True, one proxy IP will keep using the same User-agent, otherwise will use a random User-agent for each request.
    logger:
        Specify a logger instance.
    use_requests:
        whether to use requests intead of urllib2
    keep_session:
        whether to use the same session(cookies manager)
    """

    def __init__(self, cache=None, cache_file=None, read_cache=True, write_cache=True, use_network=True, 
            user_agent=None, timeout=30, delay=5, proxy=None, proxies=None, proxy_file=None, proxy_get_fun=None,
            opener=None, headers=None, data=None, num_retries=0, num_redirects=0, num_caches=1,
            force_html=False, force_ascii=False, max_size=None, default='', pattern=None, acceptable_errors=None, 
            keep_ip_ua=True, logger=None, use_requests=False, keep_session=False, **kwargs):
        if isinstance(timeout, tuple):
            connect_timeout, read_timeout = timeout
        else:
            connect_timeout = read_timeout = timeout
        if not use_requests:
            socket.setdefaulttimeout(read_timeout)
        self.logger = logger or common.logger
        need_cache = read_cache or write_cache
        if pdict and need_cache:
            self.cache = cache or pdict.PersistentDict(cache_file or settings.cache_file, num_caches=num_caches)
        else:
            self.cache = None
            if need_cache:
                self.logger.warning('Cache disabled because could not import pdict')
        # Requests session
        self.session = None
        # Urllib2 opener
        self.opener = opener
        self.settings = adt.Bag(
            read_cache = read_cache,
            write_cache = write_cache,
            use_network = use_network,
            delay = delay,
            proxies = (common.read_list(proxy_file) if proxy_file else []) or proxies or ([proxy] if proxy else []),
            proxy_file = proxy_file,
            proxy_get_fun = proxy_get_fun,
            user_agent = user_agent,
            opener = opener,
            headers = headers,
            data = data,
            num_retries = num_retries,
            num_redirects = num_redirects,
            num_caches=num_caches,
            force_html = force_html,
            force_ascii = force_ascii,
            max_size = max_size,
            default = default,
            pattern = pattern,
            keep_ip_ua = keep_ip_ua,
            acceptable_errors = acceptable_errors,
            use_requests=use_requests,
            keep_session=keep_session,
            connect_timeout=connect_timeout,
            read_timeout=read_timeout
        )
        self.last_load_time = self.last_mtime = time.time()


    def get(self, url, **kwargs):
        """Download this URL and return the HTML. 
        By default HTML is cached so only have to download once.

        url:
            what to download
        kwargs:
            override any of the arguments passed to constructor
        """
        self.reload_proxies()
        self.proxy = None # the current proxy
        self.final_url = None # for tracking redirects
        self.response_code = '' # keep response code
        self.response_headers = {} # keep response headers
        self.downloading_error = None # keep downloading error
        self.error_content = None # keep error content
        self.invalid_content = None # keep invalid content
                
        # update settings with any local overrides
        settings = adt.Bag(self.settings)
        settings.update(kwargs)
        if 'timeout' in kwargs:
            timeout = kwargs['timeout']
            if isinstance(timeout, tuple):
                settings.connect_timeout, settings.read_timeout = timeout
            else:
                settings.connect_timeout = settings.read_timeout = timeout        
        # check cache for whether this content is already downloaded
        key = self.get_key(url, settings.data)
        if self.cache and settings.read_cache:
            try:
                html = self.cache[key]
                if not self.valid_response(html, settings.pattern):
                    self.invalid_content = html
                    # invalid result from download
                    html = None
            except KeyError:
                pass # have not downloaded yet
            else:
                if not html and settings.num_retries >= 0:
                    # try downloading again
                    self.logger.debug('Redownloading')
                    settings.num_retries -= 1
                else:
                    # return previously downloaded content
                    return html or settings.default 
        if not settings.use_network:
            # only want previously cached content
            return settings.default 

        html = None
        # attempt downloading content at URL
        while settings.num_retries >= 0 and html is None:
            settings.num_retries -= 1
            if 'proxy' in settings:
                # 'proxy' argument has highest priority
                self.proxy = settings.proxy
            elif settings.proxy_get_fun:
                # fetch a proxy via proxy_get_fun
                self.proxy = settings.proxy_get_fun()
            else:
                self.proxy = self.get_proxy(settings.proxies)
            # crawl slowly for each domain to reduce risk of being blocked
            self.throttle(url, headers=settings.headers, delay=settings.delay, proxy=self.proxy) 
            html = self.fetch(url, headers=settings.headers, data=settings.data, proxy=self.proxy, user_agent=settings.user_agent, opener=settings.opener, pattern=settings.pattern, max_size=settings.max_size, 
                              keep_session=settings.keep_session, connect_timeout=settings.connect_timeout, read_timeout=settings.read_timeout, acceptable_errors=settings.acceptable_errors)


        if html:
            if settings.num_redirects > 0:
                # allowed to redirect
                redirect_url = get_redirect(url=url, html=html)
                if redirect_url:
                    # found a redirection
                    self.logger.debug('%s redirecting to %s' % (url, redirect_url))
                    settings.num_redirects -= 1
                    html = self.get(redirect_url, **settings) or ''
                    # make relative links absolute so will still work after redirect
                    relative_re = re.compile('(<\s*a[^>]+href\s*=\s*["\']?)(?!http)([^"\'>]+)', re.IGNORECASE)
                    try:
                        html = relative_re.sub(lambda m: m.group(1) + urlparse.urljoin(url, m.group(2)), html)
                    except UnicodeDecodeError:
                        pass
            html = self._clean_content(html=html, max_size=settings.max_size, force_html=settings.force_html, force_ascii=settings.force_ascii)

        if self.cache and settings.write_cache:
            # cache results
            self.cache[key] = html
            if url != self.final_url:
                # cache what URL was redirected to
                self.cache.meta(key, dict(url=self.final_url))
        
        # return default if no content
        return html or settings.default 


    def exists(self, url):
        """Do a HEAD request to check whether webpage exists
        """
        success = False
        key = self.get_key(url, 'head')
        try:
            if self.cache and self.settings.read_cache:
                success = self.cache[key]
            else:
                raise KeyError('No cache')
        except KeyError:
            # have not downloaded yet
            request = urllib2.Request(url)
            request.get_method = lambda : 'HEAD'
            try:
                response = urllib2.urlopen(request)
            except Exception, e:
                self.logger.warning('HEAD check miss: %s %s' % (url, e))
            else:
                success = True
                self.logger.info('HEAD check hit: %s' % url)
            if self.cache:
                self.cache[key] = success
        return success


    def get_key(self, url, data=None):
        """Create key for caching this request
        """
        key = url
        if data:
            key += ' ' + str(data)
        return key


    def _clean_content(self, html, max_size, force_html, force_ascii):
        """Clean up downloaded content

        html:
            the input to clean
        max_size:
            the maximum size of data allowed
        force_html:
            content must be HTML
        force_ascii:
            content must be ASCII
        """
        if max_size is not None and len(html) > max_size:
            self.logger.info('Webpage is too big: %s' % len(html))
            html = '' # too big to store
        elif force_html and not common.is_html(html):
            self.logger.info('Webpage is not html')
            html = '' # non-html content
        elif force_ascii:
            html = common.to_ascii(html) # remove non-ascii characters
        return html


    def get_proxy(self, proxies=None):
        """Return random proxy if available
        """
        if proxies:
            proxy = random.choice(proxies)
        elif self.settings.proxies:
            # select next available proxy
            proxy = random.choice(self.settings.proxies)
        else:
            proxy = None
        return proxy


    # cache the user agent used for each proxy
    proxy_agents = {}
    def get_user_agent(self, proxy, headers=None):
        """Get user agent for this proxy
        """
        if headers:
            for k, v in headers.items():
                if str(k).lower() == 'user-agent':
                    return v

        if self.settings.keep_ip_ua and proxy in Download.proxy_agents:
            # have used this proxy before so return same user agent
            user_agent = Download.proxy_agents[proxy]
        else:
            # assign random user agent to this proxy
            user_agent = alg.rand_agent()
            Download.proxy_agents[proxy] = user_agent
        return user_agent


    def valid_response(self, html, pattern):
        """Return whether the response matches the pattern
        """
        if html is None:
            return False
        if not pattern:
            return True
        elif callable(pattern):
            # Is a function
            return pattern(html)
        else:
            return re.compile(pattern, re.DOTALL|re.IGNORECASE).search(html)


    def fetch(self, url, headers=None, data=None, proxy=None, user_agent=None, opener=None, pattern=None, max_size=None, keep_session=False, connect_timeout=30, read_timeout=30, acceptable_errors=None):
        """Simply download the url and return the content
        """
        if self.settings['use_requests'] == False:
            # Use urllib2
            # create opener with cookies manager
            if not opener:
                if keep_session and self.opener:
                    opener = self.opener
                else:
                    cj = cookielib.CookieJar()
                    opener = urllib2.build_opener(urllib2.HTTPCookieProcessor(cj))
                    self.opener = opener
            else:
                if keep_session and self.opener != opener:
                    self.opener = opener

            # If with proxy, avoid reduplicate ProxyHandler - remove the previous ProxyHandler
            # If without proxy, remove previous ProxyHandler
            proxy_added = False
            for handler in opener.handlers:
                if handler.__class__.__name__ == 'ProxyHandler':
                    if handler.proxies.get('http') == proxy:
                        proxy_added = True
                    else:
                        opener.handlers.remove(handler)
                        opener.handle_open['http'].remove(handler)
                        opener.handle_open['https'].remove(handler)
                        del handler
            if proxy and not proxy_added:
                opener.add_handler(urllib2.ProxyHandler({'http' : proxy, 'https' : proxy}))
    
            headers = headers or {}
            headers['User-agent'] = user_agent or self.get_user_agent(proxy, headers)
            if not max_size:
                headers['Accept-encoding'] = 'gzip'
            for name, value in settings.default_headers.items():
                if name not in headers:
                    if name == 'Referer':
                        value = url
                    headers[name] = value
            
            if isinstance(data, dict):
                # encode data for POST
                data = urllib.urlencode(sorted(data.items()))
            self.logger.info('Downloading %s %s' % (url, data or ''))
    
            try:
                request = urllib2.Request(url, data, headers)
                with contextlib.closing(opener.open(request)) as response:
                    if max_size is not None:
                        content = response.read(max_size)
                    else:
                        content = response.read()
                    if response.headers.get('content-encoding') == 'gzip':
                        # data came back gzip-compressed so decompress it          
                        content = gzip.GzipFile(fileobj=StringIO.StringIO(content)).read()
                    self.final_url = response.url # store where redirected to
                    if not self.valid_response(content, pattern):
                        # invalid result from download
                        self.invalid_content = content
                        content = None
                        self.logger.warning('Content did not match expected pattern: %s, %s' % (url, proxy))
                    self.response_code = str(response.code)
                    self.response_headers = dict(response.headers)
            except Exception, e:
                self.downloading_error = str(e)
                if hasattr(e, 'code'):
                    self.response_code = str(e.code)
                if hasattr(e, 'read'):
                    try:
                        self.error_content = e.read()
                    except Exception, e:
                        self.error_content = ''
                # so many kinds of errors are possible here so just catch them all
                self.logger.warning('Download error: %s %s %s' % (url, e, proxy))
                if acceptable_errors and self.response_code in acceptable_errors:
                    content, self.final_url = self.settings.default, url
                else:
                    content, self.final_url = None, url
        else:
            # Use requests library
            if not keep_session or self.session == None:
                self.session = requests.Session()
                
            headers = headers or {}
            headers['User-Agent'] = user_agent or self.get_user_agent(proxy, headers)  
            for name, value in settings.default_headers.items():
                if name not in headers:
                    if name == 'Referer':
                        value = url
                    headers[name] = value            
            
            proxies = None
            if proxy:
                if '://' not in proxy:
                    _proxy = 'http://' + proxy
                else:
                    _proxy = proxy
                proxies = {'http': _proxy, 'https': _proxy}

            self.logger.info('Downloading %s %s' % (url, data or ''))
            try:
                resp = None
                if data is None:
                    # Get method
                    resp = self.session.get(url, headers=headers, proxies=proxies, timeout=(connect_timeout, read_timeout))
                else:
                    # Post method
                    if isinstance(data, basestring):
                        if 'Content-Type' not in headers:
                            headers['Content-Type'] = 'application/x-www-form-urlencoded'
                    resp = self.session.post(url, data=data, headers=headers, proxies=proxies, timeout=(connect_timeout, read_timeout))             
                if resp.status_code >= 400:
                    # HTTP ERROR
                    raise Exception('HTTP Error {}: {}'.format(resp.status_code, resp.reason))
            except Exception, e:
                if isinstance(e, requests.exceptions.ConnectTimeout):
                    error = '<Connect timeout error>'
                elif isinstance(e, requests.exceptions.ConnectionError):
                    error = '<Connection error>'
                elif isinstance(e, requests.exceptions.ReadTimeout):
                    error = '<Read timeout>'
                elif isinstance(e, requests.exceptions.InvalidHeader):
                    error = '<Invalid request header>'
                else:
                    error = str(e)
                self.downloading_error = error
                if not resp is None:
                    self.response_code = str(resp.status_code)
                    self.error_content = resp.content
                self.logger.warning('Download error with requests: %s %s %s' % (url, error, proxy))
                if acceptable_errors and self.response_code in acceptable_errors:
                    content, self.final_url = self.settings.default, url
                else:
                    content, self.final_url = None, url
            else:
                self.response_code = str(resp.status_code)  
                content = resp.content
                self.response_headers = resp.headers
                if resp.history:
                    self.final_url = resp.history[-1].headers.get('Location', resp.history[-1].url)
                else:
                    self.final_url = resp.url
                if not self.valid_response(content, pattern):
                    # invalid result from download
                    self.invalid_content = content
                    content = None
                    self.logger.warning('Content did not match expected pattern: %s, %s' % (url, proxy))
            
        return content


    _domains = adt.HashDict()
    def throttle(self, url, headers, delay, proxy=None, variance=0.5):
        """Delay a minimum time for each domain per proxy by storing last access time

        url
            what intend to download
        delay
            the minimum amount of time (in seconds) to wait after downloading content from this domain
        headers
            what headers to be sent
        proxy
            the proxy to download through
        variance
            the amount of randomness in delay, 0-1
        """
        if delay > 0:
            # Use a random delay value
            delay = delay * (1 + variance * (random.random() - 0.5))
            # To throttle by proxy
            key = str(proxy) + ':' + common.get_domain(url)
            self.__do_throttle(key, delay)
         
                
    def __do_throttle(self, key, delay):
        """Delay for key specified
        """
        if key in Download._domains:
            while datetime.datetime.now() < Download._domains.get(key):
                time.sleep(SLEEP_TIME)
        # update domain timestamp to when can query next
        Download._domains[key] = datetime.datetime.now() + datetime.timedelta(seconds=delay)


    def reload_proxies(self, timeout=600):
        """Check periodically for updated proxy file

        timeout:
            the number of seconds before check for updated proxies
        """
        if self.settings.proxy_file and time.time() - self.last_load_time > timeout:
            self.last_load_time = time.time()
            if os.path.exists(self.settings.proxy_file):
                if os.stat(self.settings.proxy_file).st_mtime != self.last_mtime:
                    self.last_mtime = os.stat(self.settings.proxy_file).st_mtime
                    self.settings.proxies = common.read_list(self.settings.proxy_file)
                    self.logger.debug('Reloaded proxies from updated file.')

        
    def save_as(self, url, filename=None, save_dir='images'):
        """Download url and save to disk

        url:
            the webpage to download
        filename:
            Output file to save to. If not set then will save to file based on URL
        """
        save_path = os.path.join(save_dir, filename or '%s.%s' % (hashlib.md5(url).hexdigest(), common.get_extension(url)))
        if not os.path.exists(save_path):
            # need to download
            _bytes = self.get(url, num_redirects=0)
            if _bytes:
                if not os.path.exists(save_dir):
                    os.makedirs(save_dir)
                open(save_path, 'wb').write(_bytes)
            else:
                return None
        return save_path


def get_redirect(url, html):
    """Check for meta redirects and return redirect URL if found
    """
    match = re.compile('<meta[^>]*?url=(.*?)["\']', re.IGNORECASE).search(html)
    if match:
        return urlparse.urljoin(url, common.unescape(match.groups()[0].strip())) 



class StopCrawl(Exception):
    """Raise this exception to interrupt crawl
    """
    pass


def threaded_get(url=None, urls=None, url_iter=None, num_threads=10, dl=None, cb=None, depth=True, **kwargs):
    """Download these urls in parallel

    url:
        the webpage to download
    urls:
        the webpages to download
    num_threads:
        the number of threads to download urls with
    cb:
        Called after each download with the HTML of the download. 
        The arguments are the url and downloaded html.
        Whatever URLs are returned are added to the crawl queue.
    dl:
        A callback for customizing the download.
        Takes the download object and url and should return the HTML.
    depth:
        True for depth first search
    """
    running = True
    lock = threading.Lock()
    def add_iter_urls():
        if lock.acquire(False):
            for url in url_iter or []:
                download_queue.append(url)
                break
            lock.release()


    def process_queue():
        """Thread for downloading webpages
        """
        D = Download(**kwargs)

        while True:
            try:
                url = download_queue.pop() if depth else download_queue.popleft()

            except IndexError:
                add_iter_urls()
                break

            else:
                # download this url
                html = dl(D, url, **kwargs) if dl else D.get(url, **kwargs)
                if cb:
                    try:
                        # use callback to process downloaded HTML
                        result = cb(D, url, html)
                    except StopCrawl:
                        common.logger.info('Stopping crawl signal')
                    except Exception:
                        # catch any callback error to avoid losing thread
                        common.logger.exception('\nIn callback for: ' + str(url))
                    else:
                        # add these URL's to crawl queue
                        for link in result or []:
                            download_queue.append(urlparse.urljoin(url, link))

    download_queue = collections.deque()
    if urls:
        download_queue.extend(urls)
    if url:
        download_queue.append(url)
    common.logger.debug('Start new crawl')

    # wait for all download threads to finish
    threads = []
    while running and (threads or download_queue):
        for thread in threads:
            if not thread.is_alive():
                threads.remove(thread)
        while len(threads) < num_threads and download_queue:
            # cat start more threads
            thread = threading.Thread(target=process_queue)
            thread.setDaemon(True) # set daemon so main thread can exit when receives ctrl-c
            thread.start()
            threads.append(thread)
        time.sleep(SLEEP_TIME)



class CrawlerCallback:
    """Example callback to crawl a website
    """
    def __init__(self, output_file=None, max_links=100, max_depth=1, allowed_urls='', banned_urls='^$', robots=None, crawl_existing=True):
        """
        output_file:
            where to save scraped data
        max_links:
            the maximum number of links to follow per page
        max_depth:
            the maximum depth to follow links into website (use None for no limit)
        allowed_urls:
            a regex for allowed urls, defaults to all urls
        banned_urls:
            a regex for banned urls, defaults to no urls
        robots:
            RobotFileParser object to determine which urls allowed to crawl
        crawl_existing:
            sets whether to crawl content already downloaded previously in the cache
        """
        self.found = adt.HashDict(int) # track depth of found URLs
        if output_file:
            self.writer = common.UnicodeWriter(output_file) 
        else:
            self.writer = None
        self.max_links = max_links
        self.max_depth = max_depth
        self.allowed_urls = re.compile(allowed_urls)
        self.banned_urls = re.compile(banned_urls)
        self.robots = robots
        self.crawl_existing = crawl_existing


    def __call__(self, D, url, html):
        # override this method to add scraping code ...
        return self.crawl(D, url, html)                                                                                                          


    def normalize(self, url, link):
        """Normalize the link to avoid duplicates

        >>> cb = CrawlerCallback()
        >>> cb.normalize('http://example.com', '../abc.html')
        'http://example.com/abc.html'
        >>> cb.normalize('http://example.com', 'abc.html#link')
        'http://example.com/abc.html'
        >>> cb.normalize('http://example.com', 'abc.html?a=1&amp;b=2')
        'http://example.com/abc.html?a=1&b=2'
        """
        link, _ = urlparse.urldefrag(link) # remove hash to avoid duplicates
        link = common.unescape(link) # parse escaped characters such as &amp;
        link = urlparse.urljoin(url, link) # support relative links
        while urlparse.urlsplit(link).path.startswith('/..'):
            # remove invalid parent directory
            link = link.replace('/..', '', 1)
        return link


    def crawl(self, D, url, html): 
        """Crawl website html and return list of URLs crawled
        """
        def valid(link):
            """Check if should crawl this link
            """
            # check if a media file
            if common.get_extension(link) not in common.MEDIA_EXTENSIONS:
                # check if a proper HTTP link
                if link.lower().startswith('http'):
                    # only crawl within website
                    if common.same_domain(domain, link):
                        # passes regex
                        if self.allowed_urls.match(link) and not self.banned_urls.match(link):
                            # not blocked by robots.txt
                            if not self.robots or self.robots.can_fetch(settings.user_agent, link):
                                # allowed to recrawl
                                if self.crawl_existing or (D.cache and link not in D.cache):
                                    return True
            return False

        domain = common.get_domain(url)
        depth = self.found[url]
        outstanding = []
        if depth != self.max_depth: 
            # extract links to continue crawling
            links_re = re.compile('<a[^>]+href=["\'](.*?)["\']', re.IGNORECASE)
            for link in links_re.findall(html):
                try:
                    link = self.normalize(url, link)
                except UnicodeDecodeError as e:
                    # unicode error when joining url
                    common.logger.info(e)
                else:
                    if link not in self.found:
                        self.found[link] = depth + 1
                        if valid(link):
                            # is a new link
                            outstanding.append(link)
                            if len(outstanding) == self.max_links:
                                break
        return outstanding
