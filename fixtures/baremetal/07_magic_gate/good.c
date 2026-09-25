/*
 * Safe twin of bad.c: identical magic-byte gate (same path-solving hard
 * problem to reach at all), but the write index is bounded.
 *
 * Expected verdict: FALSE POSITIVE. Reaching the copy loop still
 * requires solving for gate == 0xA5, but no OOB write ever occurs no
 * matter how many bytes are fed before newline.
 */
#include "mmio.h"

__attribute__((noinline))
void handle_command_gated_safe(void)
{
    char gate = uart_getc();
    char cmd[8];
    unsigned int i = 0;
    char c;

    if (gate != (char)0xA5) {
        return;
    }

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
    handle_command_gated_safe();
    sim_exit(0);
    return 0;
}
