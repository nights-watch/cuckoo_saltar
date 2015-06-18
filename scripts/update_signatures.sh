#!/bin/bash
# ------------------------------------------------------------------
# [Author] Hialo Muniz, Vinicius Franco
#  Description:
#
#
# Dependency:
#     Writing permissions in /opt. Commands:
#          sudo chown $USER:root -R /opt/
#          sudo chmod 755 -R /opt/
# ------------------------------------------------------------------

TIME=$(date +"%T")

CUCKOO_PATH=/opt/cuckoo_saltar
GITCUCKOO="gitCuckooCommunity"
GITYARA="gitYaraCommunity"

GITCUCKOO_ADDR="https://github.com/cuckoobox/community.git"
GITYARA_ADDR="https://github.com/citizenlab/malware-signatures.git"

##############################################################

function syncCuckooSignatures(){
	CUCKOO_SIG_DIR=/opt/signatures/$GITCUCKOO
	CUCKOO_GIT_DIR=$CUCKOO_SIG_DIR/community

	if [ ! -d $CUCKOO_SIG_DIR ]; then
		echo -e $TIME " Cuckoo signatures directory doesn't exist. Creating..."
		mkdir $CUCKOO_SIG_DIR -pm 775

		echo -e $TIME " Cloning remote repository..."
		git clone $GITCUCKOO_ADDR $CUCKOO_SIG_DIR/community
	fi

	cd $CUCKOO_GIT_DIR

	echo -e $TIME " Updating possible new cuckoo signatures..."
	git pull

	cp -rf $CUCKOO_GIT_DIR/modules/signatures/* /opt/cuckoo_saltar/modules/signatures/
}

##############################################################

function syncYaraSignatures(){
	YARA_SIG_DIR=/opt/signatures/$GITYARA

	if [ ! -d $YARA_SIG_DIR ]; then
		echo -e $TIME " YARA signatures directory doesn't exist. Creating..."
		mkdir $YARA_SIG_DIR -pm 775

		echo -e $TIME " Cloning remote repository..."
		git clone $GITYARA_ADDR $YARA_SIG_DIR
	fi

	cd $YARA_SIG_DIR

	echo -e $TIME " Updating possible new YARA signatures..."
	git pull

	cp -rf $YARA_SIG_DIR/yara-rules/malware-families $CUCKOO_PATH/data/yara/

	echo -e "include \"/opt/cuckoo_saltar/data/yara/binaries/shellcodes.yar\"" > /opt/cuckoo_saltar/data/yara/index_binaries.yar
	echo -e "include \"/opt/cuckoo_saltar/data/yara/binaries/embedded.yar\"" >> /opt/cuckoo_saltar/data/yara/index_binaries.yar
	echo -e "include \"/opt/cuckoo_saltar/data/yara/binaries/vmdetect.yar\"" >> /opt/cuckoo_saltar/data/yara/index_binaries.yar
	echo -e "include \"/opt/cuckoo_saltar/data/yara/malware-families/\"" >> /opt/cuckoo_saltar/data/yara/index_binaries.yar

}

syncCuckooSignatures
syncYaraSignatures
