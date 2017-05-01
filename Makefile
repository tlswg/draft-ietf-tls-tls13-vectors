MD_PREPROCESSOR = NSS_DIR=$(NSS_DIR) ./preprocess.sh

include lib/main.mk

lib/main.mk:
ifneq (,$(shell git submodule status lib 2>/dev/null))
	git submodule sync
	git submodule update --init
else
	git clone -q --depth 10 -b master https://github.com/martinthomson/i-d-template.git lib
endif

$(addsuffix .xml,$(drafts)): preprocess.sh processlog.py

NSS_DIR ?= $(wildcard ../nss)
ifeq (,$(NSS_DIR))
  NSS_DIR := nss
endif
NSPR_DIR := $(NSS_DIR)/../nspr
GTESTS := $(NSS_DIR)/../dist/$(shell cat $(NSS_DIR)/../dist/latest)/bin/ssl_gtests
$(addsuffix .mdtmp,$(drafts)): $(GTESTS)

$(GTESTS): $(NSS_DIR) $(NSPR_DIR)
	$(NSS_DIR)/build.sh $(NSS_OPTIONS)

$(NSS_DIR):
	hg clone https://hg.mozilla.org/projects/nss $(realpath $@)

$(NSPR_DIR):
	hg clone https://hg.mozilla.org/projects/nspr $(realpath $@)
