include ../common/Makefile.inc

all: bad.elf dead_branch.elf

dead_branch.elf: dead_branch.c dead_branch_fn.s $(COMMON_DIR)/startup.s $(COMMON_DIR)/linker.ld $(COMMON_DIR)/mmio.h
	$(CC) $(CFLAGS) $(LDFLAGS) $(COMMON_DIR)/startup.s dead_branch_fn.s $< -o $@

clean: clean-common
