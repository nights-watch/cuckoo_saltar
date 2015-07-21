__author__ = 'targaryen'
import virustotal
from lib.cuckoo.common.abstracts import Processing

class VirusTotal(Processing):

    def run(self):

        self.key = "virustotal"
        vt_key = self.options.get("key", None)

        v = virustotal.VirusTotal(vt_key)

        report = v.scan(self.file_path)
        result={}
        result["scans"]={}

        report.join()
        for antivirus, malware in report:

            if malware is not None:
                result["scans"][antivirus[0]] = malware

        print result
        return result