#!/bin/bash
# ------------------------------------------------------------------
# [Author] Gustavo Correia
# [Co-author] Igor Guimarães Dias <igonline15@gmail.com>
# Description:
#               Cleans the analyses folder to delete unused files and folders.
# ------------------------------------------------------------------

CUCKOO_PATH="/opt/cuckoo_saltar"
CUCKOO_ANALYSES="$CUCKOO_PATH/storage/analyses"

rm -r $CUCKOO_PATH/storage/binaries/

for dir in $CUCKOO_ANALYSES
do
    echo "Removing unused files and folders..."
    rm -rf files/ logs/ shots/ analysis.log binary reports/report.html
    echo "...done"
done

#find $CUCKOO_PATH/storage/analyses/ -type d -exec sh \
# -c '(cd {} && rm -r files/ logs/ shots/ analysis.log binary reports/report.html)' ';'


