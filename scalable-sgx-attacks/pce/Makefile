LIBSGXSTEP_DIR       = ../sgx-step
LIBSGXSTEP           = $(LIBSGXSTEP_DIR)/libsgxstep
-include $(LIBSGXSTEP)/Makefile.config

ifeq ($(SGX_SDK),)
    SGX_SDK          = /opt/intel/sgxsdk
endif
export SGX_SDK

#libcommon.a
LIBCOMMON= ../../badram/common-code/
#lib kmod_read_alias.a
LIBKRA = ../../badram/alias-reversing/modules/read_alias/

SUBDIRS              = $(LIBSGXSTEP) Enclave attacker-enclave-alias/Enclave attacker-enclave-read/Enclave

CC                   = gcc
AS                   = gcc
LD                   = gcc

ifeq ($(M32), 1)
	CFLAGS   = -m32 -DM32=$(M32)
	LDFLAGS  = -m32
else
	LIB_SUFX = 64
endif

CFLAGS              += -fPIC -fno-stack-protector -fno-builtin -fno-jump-tables \
                       -fno-common -Wno-attributes -g -D_GNU_SOURCE -O0
SDK_SRCDIR           = $(LIBSGXSTEP_DIR)/sdk/intel-sdk/linux-sgx/
INTERNAL_INC         = -I$(SDK_SRCDIR)/common/inc/internal \
                       -I$(SDK_SRCDIR)/psw/ae/inc/internal \
                       -I$(SDK_SRCDIR)/external/epid-sdk \
                       -I$(SDK_SRCDIR)/external/dcap_source
INCLUDE              = -I$(SGX_SDK)/include/ -I$(LIBSGXSTEP_DIR) $(INTERNAL_INC) -I$(LIBKRA)/include -I$(LIBCOMMON)/include
LDFLAGS             += -lsgx-step -lsgx_urts -lencl_proxy -laae_encl_proxy -lare_encl_proxy -lcommon -lkmodreadalias\
                       -lsgx_uae_service -pthread $(SUBDIRS:%=-L %) -L$(SGX_SDK)/lib$(LIB_SUFX)/ \
                       -L$(SDK_SRCDIR)/psw/urts/linux -lelf -L$(LIBKRA) -L$(LIBCOMMON)/build/libs 

OBJECTS              = pce_u.o main.o
OBJECTS2             = generate_report.o
OUTPUT               = app
OUTPUT2              = generate_report

BUILDDIRS            = $(SUBDIRS:%=build-%)
CLEANDIRS            = $(SUBDIRS:%=clean-%)

MAKEFLAGS           += --silent

all: $(OUTPUT) $(OUTPUT2)
	
run: clean all
	sudo ./$(OUTPUT2)
	sudo ./$(OUTPUT)

$(OUTPUT): $(BUILDDIRS) $(OBJECTS)
	echo "$(INDENT)[LD]" $(OBJECTS) $(LIBS) -o $(OUTPUT) 
	$(LD) $(OBJECTS) $(LDFLAGS) -o $(OUTPUT) 

$(OUTPUT2): $(BUILDDIRS) $(OBJECTS2)
	echo "$(INDENT)[LD]" $(OBJECTS2) $(LIBS) -o $(OUTPUT2) 
	$(LD) $(OBJECTS2) $(LDFLAGS) -o $(OUTPUT2) 

%.o : %.c
	echo "$(INDENT)[CC] " $<
	$(CC) $(CFLAGS) $(INCLUDE) -c $<

%_u.c: %.edl
	sgx_edger8r --untrusted $< --search-path $(SGX_SDK)/include/

%.o : %.S
	echo "$(INDENT)[AS] " $<
	$(AS) $(INCLUDE) -c $< -o $@

clean: $(CLEANDIRS)
	echo "$(INDENT)[RM]" $(OBJECTS) $(OUTPUT)
	rm -f $(OBJECTS) $(OUTPUT) $(OBJECTS2) $(OUTPUT2)

$(BUILDDIRS):
	echo "$(INDENT)[===] $(@:build-%=%) [===]"
	$(MAKE) -C $(@:build-%=%) INDENT+="$(INDENT_STEP)" M32=$(M32) curr-dir=$(curr-dir)/$(@:build-%=%)

$(CLEANDIRS):
	echo "$(INDENT)[===] $(@:clean-%=%) [===]"
	$(MAKE) clean -C $(@:clean-%=%) INDENT+="$(INDENT_STEP)" curr-dir=$(curr-dir)/$(@:build-%=%)
