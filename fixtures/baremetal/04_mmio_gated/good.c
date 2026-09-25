/*
 * Safe twin of bad.c: identical MMIO poll-loop structure (same hard
 * problem for the emulator to solve), but the write index is bounded.
 *
 * Expected verdict: FALSE POSITIVE. Reaching this function requires the
 * exact same MMIO poll-breaking as the bad twin, but no OOB write ever
 * occurs no matter how many bytes are fed before newline.
 */
#include "mmio.h"

__attribute__((noinline))
void handle_command_safe(void)
{
    char cmd[8];
    unsigned int i = 0;
    char c;

    do {
        c = uart_getc();
        if (i < sizeof(cmd)) {
            cmd[i] = c;
            i++;
        }
    } while (c != '\n' && i < 64);

    uart_putc(cmd[0]);
}

int main(void)
{
    handle_command_safe();
    sim_exit(0);
    return 0;
}
