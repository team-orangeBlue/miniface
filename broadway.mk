ifeq ($(strip $(WIIDEV)),)
$(error "Set WIIDEV in your environment.")
endif

PREFIX = $(WIIDEV)/bin/powerpc-none-elf-

CFLAGS = -mcpu=750 -mpaired -m32 -mhard-float -mno-eabi -mno-sdata
CFLAGS += -ffreestanding -ffunction-sections
CFLAGS += -Wall -Wextra -O0 -pipe
CFLAGS += -Wno-error=unused-but-set-variable
ASFLAGS =
LDFLAGS = -mcpu=750 -m32 -n -z muldefs -nostartfiles -nodefaultlibs -Wl,-gc-sections

