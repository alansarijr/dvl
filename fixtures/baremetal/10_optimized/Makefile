# Fixture 04's sources built with optimization, so locals are described by
# DWARF location lists instead of single frame-base expressions.
include ../common/Makefile.inc

SRC_DIR := ../04_mmio_gated
OPT_CFLAGS = $(filter-out -O0,$(CFLAGS))

all: bad-O2.elf good-O2.elf bad-Os.elf good-Os.elf

%-O2.elf: $(SRC_DIR)/%.c $(COMMON_DIR)/startup.s $(COMMON_DIR)/linker.ld $(COMMON_DIR)/mmio.h
	$(CC) $(OPT_CFLAGS) -O2 $(LDFLAGS) $(COMMON_DIR)/startup.s $< -o $@

%-Os.elf: $(SRC_DIR)/%.c $(COMMON_DIR)/startup.s $(COMMON_DIR)/linker.ld $(COMMON_DIR)/mmio.h
	$(CC) $(OPT_CFLAGS) -Os $(LDFLAGS) $(COMMON_DIR)/startup.s $< -o $@

clean: clean-common
