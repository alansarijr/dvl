# Fixtures 01 and 04 rebuilt for an STM32F1-like board: flash at
# 0x08000000, 128K RAM, and the UART at USART1's address (0x40013800) with
# STM32F1 status bits (RXNE = bit 5, TXE = bit 7). The target profile only
# names an SVD file; memory map and vector table are derived from the ELF.
include ../common/Makefile.inc

STM32_CFLAGS = $(CFLAGS) -DUART0_BASE=0x40013800UL '-DUART_SR_RXNE=(1U << 5)' '-DUART_SR_TXE=(1U << 7)'
STM32_LDFLAGS = -nostdlib -T linker_stm32.ld -Wl,-Map=$(basename $@).map -Wl,--build-id=none
DEPS = $(COMMON_DIR)/startup.s linker_stm32.ld $(COMMON_DIR)/mmio.h

all: overflow.elf bad.elf good.elf

overflow.elf: ../01_stack_overflow/bad.c $(DEPS)
	$(CC) $(STM32_CFLAGS) $(STM32_LDFLAGS) $(COMMON_DIR)/startup.s $< -o $@

bad.elf good.elf: %.elf: ../04_mmio_gated/%.c $(DEPS)
	$(CC) $(STM32_CFLAGS) $(STM32_LDFLAGS) $(COMMON_DIR)/startup.s $< -o $@

clean: clean-common
