# Makefile fragment of the cloudauth filter, included by the HAProxy Makefile
# when the directory of this file is listed in EXTRA_MAKE :
#
#   make TARGET=linux-glibc USE_OPENSSL=1 EXTRA_MAKE=/path/to/haproxy-cloudauth
#
# The providers are all built by default. Each one may be left out by setting
# its variable to 0 :
#
#   CLOUDAUTH_AZURE  : Azure Blob Storage provider
#   CLOUDAUTH_GOOGLE : Google Cloud Storage provider
#   CLOUDAUTH_S3     : Amazon S3 and S3 compatible storages provider

# Absolute path of the directory holding this file, resolved when it is
# included, so that the paths below do not depend on the directory make was
# started from.
CLOUDAUTH_DIR := $(patsubst %/,%,$(dir $(abspath $(lastword $(MAKEFILE_LIST)))))

CLOUDAUTH_AZURE  ?= 1
CLOUDAUTH_GOOGLE ?= 1
CLOUDAUTH_S3     ?= 1

# The cleaning targets must work whatever the build options.
CLOUDAUTH_CLEANING = $(filter clean cloudauth-clean,$(MAKECMDGOALS))

ifeq ($(CLOUDAUTH_CLEANING),)
ifeq ($(USE_OPENSSL:0=),)
$(error the cloudauth filter requires an OpenSSL-compatible library, please also set USE_OPENSSL=1)
endif
endif

OPTIONS_OBJS += \
	$(CLOUDAUTH_DIR)/src/flt_cloudauth.o     \
	$(CLOUDAUTH_DIR)/src/cloudauth.o         \
	$(CLOUDAUTH_DIR)/src/cloudauth_common.o  \
	$(CLOUDAUTH_DIR)/src/cloudauth_fetch.o   \
	$(CLOUDAUTH_DIR)/src/cloudauth_metrics.o \
	$(CLOUDAUTH_DIR)/src/cloudauth_sigv4.o   \
	$(CLOUDAUTH_DIR)/src/cloudauth_trace.o

ifneq ($(CLOUDAUTH_AZURE:0=),)
OPTIONS_OBJS += $(CLOUDAUTH_DIR)/src/cloudauth_azure.o
endif

ifneq ($(CLOUDAUTH_GOOGLE:0=),)
OPTIONS_OBJS += $(CLOUDAUTH_DIR)/src/cloudauth_google.o
endif

ifneq ($(CLOUDAUTH_S3:0=),)
OPTIONS_OBJS += $(CLOUDAUTH_DIR)/src/cloudauth_s3.o
endif

# The HAProxy Makefile rebuilds an object when one of the HAProxy headers
# changes (include/*/*.h of HAProxy), but not when a header of the filter
# changes. The headers of the filter are therefore added as prerequisites of
# the objects of the filter. A rule without a recipe only adds prerequisites.
$(filter $(CLOUDAUTH_DIR)/%,$(OPTIONS_OBJS)): $(wildcard $(CLOUDAUTH_DIR)/include/cloudauth/*.h)

# The addon is not part of the "use_opts" list of HAProxy, so its flags are
# not collected automatically. This fragment is included before COPTS is
# assembled.
OPTIONS_CFLAGS += -I$(CLOUDAUTH_DIR)/include

# Report the providers in the "OPTIONS" line of "haproxy -vv", like the build
# options of HAProxy. BUILD_OPTIONS is set before this fragment is included,
# and only used after.
BUILD_OPTIONS += CLOUDAUTH_AZURE=$(CLOUDAUTH_AZURE) CLOUDAUTH_GOOGLE=$(CLOUDAUTH_GOOGLE) CLOUDAUTH_S3=$(CLOUDAUTH_S3)

# Extend the "clean" target of HAProxy. A rule without a recipe only adds
# prerequisites. This fragment is included before the first target of HAProxy
# ("all"), so the default goal is reset after the rules below to let "all"
# remain the default one.
clean: cloudauth-clean

.PHONY: cloudauth-clean
cloudauth-clean:
	$(Q)rm -f $(CLOUDAUTH_DIR)/src/*.[oas]

.DEFAULT_GOAL :=
