__author__ = 'targaryen'

from lib.cuckoo.common.utils import convert_to_printable
from urlparse import urlunparse

try:
    import dpkt

    IS_DPKT = True
except ImportError:
    IS_DPKT = False

class Http:
    def __init__(self):
        self.http_package = [] # List containing package.
        self.header = {} # Dictionary of header

    @staticmethod
    def check(tcpdata, destinationPort):
        """Checks the existence of HTTP Protocol in payload TCP.
        @param tcpdata: TCP payload.
        """
        try:
            r = dpkt.http.Request()
            r.method, r.version, r.uri = None, None, None
            r.unpack(tcpdata, destinationPort)
        except dpkt.dpkt.UnpackError:
            if not r.method is None or not r.version is None or \
                    not r.uri is None:
                return True
            return False

        return True

    @staticmethod
    def dissect(self, data, destinationPort):
        """
        Realize parser of payload of protocol TCP identified like HTTP protocol

        :param data: TCP payload
        :return: Dictionary with the headers and payload of protocol HTTP
        """

        header={}

        try:
            http = dpkt.http.Request()
            http.unpack(data)
        except dpkt.dpkt.UnpackError:
            pass

        try:
            self.http_package["version"] = convert_to_printable(http.version) #Version of protocol HTTP in use
            self.http_package["method"] = convert_to_printable(http.method) #Method of request HTTP

            # Parser HTTP headers, assuming it is not possible to determine the items in the header,
            # converting the data of each attribute to readable format
            for k in http.headers.iteritems():
                self.header[k] = convert_to_printable(http.headers[k])

            self.http_package["header"]=header # Add Header HTTP converted to printable String

            # Attribute HOST in header treatment
            # The host attribute is checked for the treatment of HTTP requests that do not use the standard port,
            # for example, instead of using the door 80, some web servers may respond to ports 8080, 8180, etc.
            if "host" in http.headers:
                header["host"] = convert_to_printable(http.headers["host"])
            else:
                header["host"] = ""

            # Destination port of TCP header
            self.http_package["port"] = destinationPort

            # Manually deal with cases when destination port is not the default one,
            # and it is  not included in host header.
            netloc = self.http_package["host"]
            if destinationPort != 80 and ":" not in netloc:
                netloc += ":" + str(self.http_package["port"])

            # Mount the URI complete
            self.http_package["uri"] = convert_to_printable(urlunparse(("http",
                                                            netloc,
                                                            http.uri, None,
                                                            None, None)))
            # Body of request/response HTTP, considered the payload of request HTTP. according of RFC 2616
            self.http_package["body"] = convert_to_printable(http.body)

        except Exception:
            return False

        return self.http_package
