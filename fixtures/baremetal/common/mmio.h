/*
 * Shared MMIO layout for DVL Cortex-M3 test fixtures.
 * No libc / no CMSIS -- fully self-contained (-nostdlib -ffreestanding).
 *
 * UART0 @ 0x40001000
 *   SR (0x00): bit0 TXE (transmit data register empty, read-only from sw pov)
 *              bit1 RXNE (receive data register not empty)
 *   DR (0x04): write -> transmit byte (captured by emulator hook)
 *              read  -> receive byte (fed by emulator from an input queue)
 *
 * SIM  @ 0x40002000  (test-harness convenience registers, not real hardware)
 *   EXIT  (0x00): writing here tells the emulator "clean end of test, stop"
 *   PRINT (0x04): writing a byte here is captured as debug output
 */
#ifndef DVL_MMIO_H
#define DVL_MMIO_H

#include <stdint.h>

/* Overridable so fixture 12 can place the UART where an STM32 has it. */
#ifndef UART0_BASE
#define UART0_BASE 0x40001000UL
#endif

typedef struct {
    volatile uint32_t SR;
    volatile uint32_t DR;
} UART_TypeDef;

#define UART0 ((UART_TypeDef *)UART0_BASE)

#ifndef UART_SR_TXE
#define UART_SR_TXE  (1U << 0)
#endif
#ifndef UART_SR_RXNE
#define UART_SR_RXNE (1U << 1)
#endif

#define SIM_BASE 0x40002000UL

typedef struct {
    volatile uint32_t EXIT;
    volatile uint32_t PRINT;
} SIM_TypeDef;

#define SIM ((SIM_TypeDef *)SIM_BASE)

static inline void sim_exit(uint32_t code)
{
    SIM->EXIT = code;
    for (;;) { /* emulator stops on the write above; this is a safety net */ }
}

static inline void uart_putc(char c)
{
    while (!(UART0->SR & UART_SR_TXE)) {
        /* busy-poll: the emulator's MMIO poll-breaker must flip TXE,
         * or this hangs forever in a naive emulator. */
    }
    UART0->DR = (uint32_t)(unsigned char)c;
}

static inline char uart_getc(void)
{
    while (!(UART0->SR & UART_SR_RXNE)) {
        /* busy-poll on RXNE: same poll-breaker requirement as uart_putc,
         * but gating a *read* path (fixture 04). */
    }
    return (char)(UART0->DR & 0xFF);
}

/* Minimal freestanding memcpy so fixtures never need libc. */
static inline void mem_copy(void *dst, const void *src, unsigned int n)
{
    unsigned char *d = (unsigned char *)dst;
    const unsigned char *s = (const unsigned char *)src;
    for (unsigned int i = 0; i < n; i++) {
        d[i] = s[i];
    }
}

#endif /* DVL_MMIO_H */
