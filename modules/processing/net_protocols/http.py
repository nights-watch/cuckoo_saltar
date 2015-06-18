__author__ = 'targaryen'

from lib.cuckoo.common.utils import convert_to_printable
from urlparse import urlunparse

try:
    import dpkt

    IS_DPKT = True
except ImportError:
    IS_DPKT = False

class Http:

    #TODO create singleton
    def __init__(self):
        # List containing all HTTP requests.
        self.http_requests = {}

    def check_http(self, tcpdata):
        """Checks for HTTP traffic.
        @param tcpdata: TCP data flow.
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

    def add_http(self, tcpdata, dport):
        """Adds an HTTP flow.
        @param tcpdata: TCP data flow.
        @param dport: destination port.
        """
        if tcpdata in self.http_requests:
            self.http_requests[tcpdata]["count"] += 1
            return True

        try:
            http = dpkt.http.Request()
            http.unpack(tcpdata)
        except dpkt.dpkt.UnpackError:
            pass

        try:
            entry = {"count": 1}

            if "host" in http.headers:
                entry["host"] = convert_to_printable(http.headers["host"])
            else:
                entry["host"] = ""

            entry["port"] = dport

            # Manually deal with cases when destination port is not the default one,
            # and it is  not included in host header.
            netloc = entry["host"]
            if dport != 80 and ":" not in netloc:
                netloc += ":" + str(entry["port"])

            entry["data"] = convert_to_printable(tcpdata)
            entry["uri"] = convert_to_printable(urlunparse(("http",
                                                            netloc,
                                                            http.uri, None,
                                                            None, None)))
            entry["body"] = convert_to_printable(http.body)
            entry["path"] = convert_to_printable(http.uri)

            if "user-agent" in http.headers:
                entry["user-agent"] = \
                    convert_to_printable(http.headers["user-agent"])

            entry["version"] = convert_to_printable(http.version)
            entry["method"] = convert_to_printable(http.method)

            self.http_requests[tcpdata] = entry
        except Exception:
            return False

        return True




