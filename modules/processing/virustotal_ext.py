__author__ = 'targaryen'
import virustotal
import operator
from lib.cuckoo.common.abstracts import Processing
from name_generator.name_generator import Guesser

CHARS = ['/', ':','-', '!', '_']

class VirusTotal(Processing):

    def do_simple_filter(self, target):
        tags = {}
        total = 0
        for key in target:
            value = target[key].lower()
            tmp = value

            for char in CHARS:
                tmp = tmp.replace(char, '.')

            words = tmp.split('.')

            for word in words:
                total += 1
                if word in tags:
                    tags[word] += 1
                else:
                    tags[word] = 1

        sorted_tags = [ (x[0], float(x[1]) / total) for x in (sorted(tags.items(), key=operator.itemgetter(1)))]
        out = {}
        out['tags'] = [x[0] for x in sorted_tags[-5:] ]
        out['tags_weight'] = [x[1] for x in sorted_tags[-5:] ]
        return out

    def do_advanced_filter(self, target):
        return Guesser().guess_everything(target)

    def run(self):

        self.key = "virustotal"
        vt_key = self.options.get("key", None)

        v = virustotal.VirusTotal(vt_key)

        report = v.scan(self.file_path)

        result={}
        scans={}

        report.join()
        for antivirus, malware in report:

            if malware is not None:
                scans[antivirus[0]] = malware

        result['scans'] = scans
        classification_option = self.options.get('classification', 'none')
        
        # verify which classification algorithm to use
        simple_classification = False
        advanced_classification = False
        
        if classification_option in ['all', 'simple']:
            simple_classification = True
        if classification_option in ['all', 'advanced']:
            advanced_classification = True
        
        # apply classification
        if simple_classification:
            result['simple_classification'] = self.do_simple_filter(scans)
        if advanced_classification:
            result['advanced_classification'] = self.do_advanced_filter(scans)

        return result
