class URL(object):
    """URL representation suitable for lookup"""

    def __init__(self, url):
        """Constructor.

        :param url: can be either of str or bytes type.
        """
        if type(url) is bytes:
            self.url = bytes(url)
        else:
            self.url = url.encode()

    @property
    def hashes(self):
        """Hashes of all possible permutations of the URL in canonical form"""
        for url_variant in self.url_permutations(self.canonical):
            url_hash = self.digest(url_variant)
            yield url_hash

    @property
    def canonical(self):
        """Convert URL to its canonical form."""
        def full_unescape(u):
            uu = urllib.unquote(u)
            if uu == u:
                return uu
            else:
                return full_unescape(uu)

        def full_unescape_to_bytes(u):
            uu = urlparse.unquote_to_bytes(u)
            if uu == u:
                return uu
            else:
                return full_unescape_to_bytes(uu)

        def quote(s):
            safe_chars = '!"$&\'()*+,-./:;<=>?@[\\]^_`{|}~'
            return urllib.quote(s, safe=safe_chars)

        url = self.url.strip()
        url = url.replace(b'\n', b'').replace(b'\r', b'').replace(b'\t', b'')
        url = url.split(b'#', 1)[0]
        if url.startswith(b'//'):
            url = b'http:' + url
        if len(url.split(b'://')) <= 1:
            url = b'http://' + url
        # at python3 work with bytes instead of string
        # as URL may contain invalid unicode characters
        if self.__py3 and type(url) is bytes:
            url = quote(full_unescape_to_bytes(url))
        else:
            url = quote(full_unescape(url))
        url_parts = urlparse.urlsplit(url)
        if not url_parts[0]:
            url = 'http://{}'.format(url)
            url_parts = urlparse.urlsplit(url)
        protocol = url_parts.scheme
        if self.__py3:
            host = full_unescape_to_bytes(url_parts.hostname)
            path = full_unescape_to_bytes(url_parts.path)
        else:
            host = full_unescape(url_parts.hostname)
            path = full_unescape(url_parts.path)
        query = url_parts.query
        if not query and '?' not in url:
            query = None
        if not path:
            path = b'/'
        has_trailing_slash = (path[-1:] == b'/')
        path = posixpath.normpath(path).replace(b'//', b'/')
        if has_trailing_slash and path[-1:] != b'/':
            path = path + b'/'
        port = url_parts.port
        host = host.strip(b'.')
        host = re.sub(br'\.+', b'.', host).lower()
        if host.isdigit():
            try:
                host = socket.inet_ntoa(struct.pack("!I", int(host)))
            except Exception:
                pass
        elif host.startswith(b'0x') and b'.' not in host:
            try:
                host = socket.inet_ntoa(struct.pack("!I", int(host, 16)))
            except Exception:
                pass
        quoted_path = quote(path)
        quoted_host = quote(host)
        if port is not None:
            quoted_host = '{}:{}'.format(quoted_host, port)
        canonical_url = '{}://{}{}'.format(protocol, quoted_host, quoted_path)
        if query is not None:
            canonical_url = '{}?{}'.format(canonical_url, query)
        return canonical_url

    @staticmethod
    def url_permutations(url):
        """Try all permutations of hostname and path which can be applied

        to blacklisted URLs
        """
        def url_host_permutations(host):
            if re.match(r'\d+\.\d+\.\d+\.\d+', host):
                yield host
                return
            parts = host.split('.')
            l = min(len(parts), 5)
            if l > 4:
                yield host
            for i in range(l - 1):
                yield '.'.join(parts[i - l:])

        def url_path_permutations(path):
            yield path
            query = None
            if '?' in path:
                path, query = path.split('?', 1)
            if query is not None:
                yield path
            path_parts = path.split('/')[0:-1]
            curr_path = ''
            for i in range(min(4, len(path_parts))):
                curr_path = curr_path + path_parts[i] + '/'
                yield curr_path

        protocol, address_str = urllib.splittype(url)
        host, path = urllib.splithost(address_str)
        user, host = urllib.splituser(host)
        host, port = urllib.splitport(host)
        host = host.strip('/')
        seen_permutations = set()
        for h in url_host_permutations(host):
            for p in url_path_permutations(path):
                u = '{}{}'.format(h, p)
                if u not in seen_permutations:
                    yield u
                    seen_permutations.add(u)

    @staticmethod
    def digest(url):
        """Hash the URL"""
        return hashlib.sha256(url.encode('utf-8')).digest()