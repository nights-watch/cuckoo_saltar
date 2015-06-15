__author__ = 'targaryen'


class Udp:

    def __init__(self):
        # List containing all UDP packets.
        self.udp_connections = []
        self.udp_connections_seen = set()


    def udp_dissect(self, conn, data, dns):
        """Runs all UDP dissectors.
        @param conn: connection.
        @param data: payload data.
        """
        # Select DNS and MDNS traffic.
        # According of RFC 1035:
        #
        # The DNS assumes that messages will be transmitted as datagrams or in a
        # byte stream carried by a virtual circuit.  While virtual circuits can be
        # used for any DNS activity, datagrams are preferred for queries due to
        # their lower overhead and better performance.  Zone refresh activities
        # must use virtual circuits because of the need for reliable transfer.

        # The Internet supports name server access using TCP [RFC-793] on server
        # port 53 (decimal) as well as datagram access using UDP [RFC-768] on UDP
        # port 53 (decimal).,
        if conn["dport"] == 53 or conn["sport"] == 53 or conn["dport"] == 5353 or conn["sport"] == 5353:
            if dns.check_dns(data):
                return dns.add_dns(data)

