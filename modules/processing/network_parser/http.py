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

    @staticmethod
    def dissect(data):
        return {}




