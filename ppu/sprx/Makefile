ifeq ($(strip $(DEVKITPRO)),)
$(error "Please set DEVKITPRO in your environment. export DEVKITPRO=<path to>devkitPro")
endif

ifeq ($(strip $(DEVKITPS3)),)
$(error "Please set DEVKITPS3 in your environment. export DEVKITPS3=<path>")
endif

all:
	@$(MAKE) -C libio --no-print-directory
	@$(MAKE) -C liblv2 --no-print-directory
	@$(MAKE) -C liblv2dbg --no-print-directory
	@$(MAKE) -C libnet --no-print-directory
	@$(MAKE) -C libgem --no-print-directory
	@$(MAKE) -C libaudio --no-print-directory
	@$(MAKE) -C libpngdec --no-print-directory
	@$(MAKE) -C libjpgdec --no-print-directory
	@$(MAKE) -C libgcm_sys --no-print-directory
	@$(MAKE) -C libsysfs --no-print-directory
	@$(MAKE) -C libsysutil --no-print-directory
	@$(MAKE) -C libsysmodule --no-print-directory
	
install:
	@$(MAKE) -C libio install --no-print-directory
	@$(MAKE) -C liblv2 install --no-print-directory
	@$(MAKE) -C liblv2dbg install --no-print-directory
	@$(MAKE) -C libnet install --no-print-directory
	@$(MAKE) -C libgem install --no-print-directory
	@$(MAKE) -C libaudio install --no-print-directory
	@$(MAKE) -C libpngdec install --no-print-directory
	@$(MAKE) -C libjpgdec install --no-print-directory
	@$(MAKE) -C libgcm_sys install --no-print-directory
	@$(MAKE) -C libsysfs install --no-print-directory
	@$(MAKE) -C libsysutil install --no-print-directory
	@$(MAKE) -C libsysmodule install --no-print-directory
	
clean:
	@$(MAKE) -C libio clean --no-print-directory
	@$(MAKE) -C liblv2 clean --no-print-directory
	@$(MAKE) -C liblv2dbg clean --no-print-directory
	@$(MAKE) -C libnet clean --no-print-directory
	@$(MAKE) -C libgem clean --no-print-directory
	@$(MAKE) -C libaudio clean --no-print-directory
	@$(MAKE) -C libpngdec clean --no-print-directory
	@$(MAKE) -C libjpgdec clean --no-print-directory
	@$(MAKE) -C libgcm_sys clean --no-print-directory
	@$(MAKE) -C libsysfs clean --no-print-directory
	@$(MAKE) -C libsysutil clean --no-print-directory
	@$(MAKE) -C libsysmodule clean --no-print-directory
	
.PHONY: all clean install