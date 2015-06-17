# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os
import json
import codecs

from lib.cuckoo.common.abstracts import Report
from lib.cuckoo.common.exceptions import CuckooReportError

class JsonDump(Report):
    """Saves analysis results in JSON format."""

    def run(self, results):
        """Writes report.
        @param results: Cuckoo results dict.
        @raise CuckooReportError: if fails to write report.
        """
        indent = self.options.get("indent", 4)
        encoding = self.options.get("encoding", "utf-8")

        try:
            
            del results['behavior']
            del results['procmemory']
            for tag in results['dropped']:
                del tag['sha1']
                del tag['crc32']
                del tag['sha256']
                del tag['path']
                del tag['ssdeep']
                del tag['sha512']
                del tag['md5']
                del tag['size']
                
            
                    
            path = os.path.join(self.reports_path, "report.json")
            with codecs.open(path, "w", "utf-8") as report:
                json.dump(results, report, sort_keys=False,
                          indent=int(indent), encoding=encoding)
                       
        except (UnicodeError, TypeError, IOError) as e:
            raise CuckooReportError("Failed to generate JSON report: %s" % e)
