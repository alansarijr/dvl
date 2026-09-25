# Shared build rules for DVL Cortex-M3 bare-metal fixtures.
# Included by each fixtures/baremetal/<NN_name>/Makefile via:
#   include ../common/Makefile.inc

# NOTE: deliberately NOT using $(abspath ...) here -- if the project is
# checked out under a path containing a space (as this one is:
# ".../Cyperpunk Dynamic/..."), an absolute COMMON_DIR breaks Make's
# prerequisite word-splitting. A relative path never touches that space
# because it's resolved from each fixture's own directory (make -C ...).
COMMON_DIR := $(dir $(lastword $(MAKEFILE_LIST)))


CC       := arm-none-eabi-gcc
OBJDUMP  := arm-none-eabi-objdump
READELF  := arm-none-eabi-readelf
SIZE     := arm-none-eabi-size

CFLAGS := -mcpu=cortex-m3 -mthumb -O0 -g3 -gdwarf-4 \
          -ffreestanding -fno-builtin -fno-common \
          -Wall -Wextra -I$(COMMON_DIR)

LDFLAGS := -nostdlib -T $(COMMON_DIR)/linker.ld \
           -Wl,-Map=$(basename $@).map -Wl,--build-id=none

%.elf: %.c $(COMMON_DIR)/startup.s $(COMMON_DIR)/linker.ld $(COMMON_DIR)/mmio.h
	$(CC) $(CFLAGS) $(LDFLAGS) $(COMMON_DIR)/startup.s $< -o $@

%.lst: %.elf
	$(OBJDUMP) -d -S $< > $@

.PHONY: clean-common
clean-common:
	rm -f *.elf *.o *.map *.lst
