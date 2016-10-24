MD_PREPROCESSOR := ./preprocess.sh

include lib/main.mk

lib/main.mk:
ifneq (,$(shell git submodule status lib 2>/dev/null))
	git submodule sync
	git submodule update --init
else
	git clone -q --depth 10 -b master https://github.com/martinthomson/i-d-template.git lib
endif

$(addsuffix .mdtmp,$(drafts)): preprocess.sh processlog.py

NSSDIR ?= ../nss
GTESTS := $(NSSDIR)/../dist/$(shell make -s -C $(NSSDIR) platform)/bin/ssl_gtests
$(addsuffix .mdtmp,$(drafts)): $(GTESTS)

$(GTESTS): $(NSSDIR)
	BUILD_OPT= USE_64=1 $(NSSDIR)/build.sh
