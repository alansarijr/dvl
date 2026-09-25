# Fixture 01's binaries with all debug info removed (symbols kept), as
# most shipped firmware is. Code is byte-identical to 01's, so findings
# are located through 01's line table.
include ../common/Makefile.inc

STRIP := arm-none-eabi-strip
SRC_DIR := ../01_stack_overflow

all: bad.elf good.elf

bad.elf good.elf: %.elf: $(SRC_DIR)/%.elf
	$(STRIP) --strip-debug -o $@ $<

clean: clean-common
