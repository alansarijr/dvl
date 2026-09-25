# Build/clean all Cortex-M3 bare-metal DVL test fixtures.
DIRS := 01_stack_overflow 02_alloc_const 03_unreachable 04_mmio_gated 05_irq_only 06_oob_read 07_magic_gate

.PHONY: all clean $(DIRS)

all: $(DIRS)

$(DIRS):
	$(MAKE) -C $@ all

clean:
	@for d in $(DIRS); do $(MAKE) -C $$d clean; done
