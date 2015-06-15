__author__ = 'targaryen'


class Smtp:

    #TODO create singleton
    def __init__(self):
        # List containing all SMTP requests.
        self.smtp_requests = []
        self.smtp_flow = {}

    def reassemble_smtp(self, conn, data):
        """Reassemble a SMTP flow.
        @param conn: connection dict.
        @param data: raw data.
        """
        if conn["dst"] in self.smtp_flow:
            self.smtp_flow[conn["dst"]] += data
        else:
            self.smtp_flow[conn["dst"]] = data

    def process_smtp(self):
        """Process SMTP flow."""
        #RFC 2821
        for  data in self.smtp_flow.iteritems():
            # Detect new SMTP flow.
            if data.startswith("EHLO") or data.startswith("HELO"):
                self.smtp_requests.append({"raw": data})