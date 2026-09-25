/*
 * CWE-121/787 behind an MMIO poll loop -- the #1 hard problem called out
 * in the prompt: "bare-metal code often blocks on register polls that
 * will hang a naive emulator."
 *
 * handle_command() reads bytes from UART0 one at a time via uart_getc(),
 * which busy-polls UART0->SR & RXNE. Each received byte is appended to
 * `cmd[8]` with NO bound check on the write index -- if more than 8 bytes
 * arrive before a newline, this overflows.
 *
 * Two failure modes this fixture is designed to catch:
 *   1. If the emulator does not stub/advance RXNE, uart_getc() spins
 *      forever -> naive emulation reports "hang" or "unreachable", which
 *      is a FALSE "unreachable" (the bug is very much reachable with the
 *      right input).
 *   2. If the emulator advances RXNE but never actually varies the bytes
 *      fed through DR, the overflow never triggers even though the code
 *      path is reached -> also a wrong verdict.
 *
 * Expected verdict: TRUE POSITIVE, but ONLY reachable/provable if the
 * MMIO layer (a) breaks the poll loop and (b) feeds >8 bytes before '\n'.
 */
#include "mmio.h"

__attribute__((noinline))
void handle_command(void)
{
    char cmd[8];
    unsigned int i = 0;
    char c;

    do {
        c = uart_getc();     /* blocks on RXNE poll until MMIO layer sets it */
        cmd[i] = c;           /* BUG: no check that i < sizeof(cmd) */
        i++;
    } while (c != '\n' && i < 64);

    uart_putc(cmd[0]);
}

int main(void)
{
    handle_command();
    sim_exit(0);
    return 0;
}
