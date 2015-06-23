__author__ = 'targaryen'

try:
    import dpkt

    IS_DPKT = True
except ImportError:
    IS_DPKT = False

class Http:
    def __init__(self):
        pass

    @staticmethod
    def check(tcpdata):
        """Checks the existence of HTTP Protocol in payload TCP.
        @param tcpdata: TCP payload.
        """
        try:
            r = dpkt.http.Request()
            r.method, r.version, r.uri = None, None, None
            r.unpack(tcpdata)
        except dpkt.dpkt.UnpackError:
            if not r.method is None or not r.version is None or \
                    not r.uri is None:
                return True
            return False

        return True

    @staticmethod
    def dissect(data):
        """
        Realize parser of payload of protocol TCP identified like HTTP protocol

        :param data: TCP payload
        :return: Dictionary with the headers and payload of protocol HTTP
        """

        http_package = {} # List containing package.
        #header = {}  # Dictionary of header

        try:
            http = dpkt.http.Request()
            http.unpack(data)
        except dpkt.dpkt.UnpackError:
            pass

        http_package["protocol_name"] = 'HTTP'
        http_package["layer"] = 7
        http_package["version"] = http.version # Version of protocol HTTP in use
        http_package["method"] = http.method # Method of request HTTP
        http_package["header"]= http.headers # Add Header HTTP do http package hierarchy

        # Attribute HOST in header treatment
        # The host attribute is checked for the treatment of HTTP requests that do not use the standard port,
        # for example, instead of using the door 80, some web servers may respond to ports 8080, 8180, etc.
        #if "host" in http.headers:
        #    header["host"] = http.headers["host"]
        #else:
        #    header["host"] = ''

        # Manually deal with cases when destination port is not the default one,
        # and it is  not included in host header.
        #netloc = header["host"]
        #if data.dport != 80 and ':' not in netloc:
        #    netloc += ':' + str(http_package["port"])

        # Mount the URI complete
        #http_package["uri"] = urlunparse(("http", http.uri, None, None, None))
        # Body of request/response HTTP, considered the payload of request HTTP. according of RFC 2616
        http_package["body"] = http.body #DPKT only parse body of HTTP request when the method is POST. GET Method return a empty string
        http_package["uri"] = http.uri #URI Request

        return http_package
