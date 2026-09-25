/*
 * Generic Cortex-M3 bare-metal linker script for DVL test fixtures.
 *
 * Memory map (documented, matches targets/dvl-fixtures.toml used by the tool):
 *   FLASH : 0x00000000 - 0x0003FFFF  (256K)  -- code, .isr_vector, .rodata
 *   RAM   : 0x20000000 - 0x2000FFFF  (64K)   -- .data, .bss, stack (grows down)
 *
 * Peripherals (not part of this linker script, MMIO is hooked by the emulator):
 *   UART0 : 0x40001000  { SR @ 0x00, DR @ 0x04 }
 *   SIM   : 0x40002000  { EXIT @ 0x00, PRINT @ 0x04 }
 */

MEMORY
{
  FLASH (rx)  : ORIGIN = 0x00000000, LENGTH = 256K
  RAM   (rwx) : ORIGIN = 0x20000000, LENGTH = 64K
}

_estack = ORIGIN(RAM) + LENGTH(RAM);

SECTIONS
{
  .isr_vector :
  {
    KEEP(*(.isr_vector))
  } > FLASH

  .text :
  {
    *(.text*)
    *(.rodata*)
  } > FLASH

  _sidata = LOADADDR(.data);

  .data :
  {
    _sdata = .;
    *(.data*)
    _edata = .;
  } > RAM AT > FLASH

  .bss :
  {
    _sbss = .;
    *(.bss*)
    *(COMMON)
    _ebss = .;
  } > RAM

  /DISCARD/ :
  {
    *(.comment)
    *(.ARM.attributes)
  }
}
