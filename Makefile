NSS_DIR ?= $(wildcard ../nss)
ifeq (,$(NSS_DIR))
  NSS_DIR := nss
endif
NSPR_DIR := $(NSS_DIR)/../nspr
MD_PREPROCESSOR = NSS_DIR=$(NSS_DIR) ./preprocess.sh

LIBDIR := lib
include $(LIBDIR)/main.mk

$(LIBDIR)/main.mk:
ifneq (,$(shell git submodule status $(LIBDIR) 2>/dev/null))
	git submodule sync
	git submodule update $(CLONE_ARGS) --init
else
	git clone -q --depth 10 $(CLONE_ARGS) \
	    -b master https://github.com/martinthomson/i-d-template $(LIBDIR)
endif

$(addsuffix .xml,$(drafts)): preprocess.sh processlog.py

ifneq (,$(wildcard $(NSS_DIR)/../dist/latest))
  NSS_LATEST := $(shell cat $(NSS_DIR)/../dist/latest)
else
  NSS_LATEST := Debug
endif
GTESTS := $(NSS_DIR)/../dist/$(NSS_LATEST)/bin/ssl_gtests
$(addsuffix .xml,$(drafts)): $(GTESTS)

$(GTESTS): $(NSS_DIR) $(NSPR_DIR)
	$(NSS_DIR)/build.sh $(NSS_OPTIONS)

$(NSS_DIR):
ifneq (,$(NSS_BUNDLE))
	hg clone -b NSS_TLS13_DRAFT19_BRANCH $(NSS_BUNDLE) $(realpath $@) && hg -R $(realpath $@) pull -u https://hg.mozilla.org/projects/nss
else
	hg clone -b NSS_TLS13_DRAFT19_BRANCH https://hg.mozilla.org/projects/nss $(realpath $@)
endif

$(NSPR_DIR):
ifneq (,$(NSPR_BUNDLE))
	hg clone $(NSPR_BUNDLE) $(realpath $@) && hg -R $(realpath $@) pull -u https://hg.mozilla.org/projects/nspr
else
	hg clone https://hg.mozilla.org/projects/nspr $(realpath $@)
endif
