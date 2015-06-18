#!/bin/bash
# ------------------------------------------------------------------
# [Author] Gustavo Correia
#  Description:
#               Cleans the analisys folder to delete unused files and folders.
# ------------------------------------------------------------------

cd ../storage
rm -r binaries/
cd analyses/
find . -type d -exec sh -c '(cd {} && rm -r files/ logs/ shots/ analysis.log binary reports/report.html)' ';'


