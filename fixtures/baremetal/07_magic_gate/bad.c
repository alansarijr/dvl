/*
 * CWE-121 gated behind a magic UART byte -- the hard problem the
 * generic concrete path-driving strategy (a fixed 'A'-filled payload)
 * cannot solve on its own: no amount of 'A' (0x41) bytes ever satisfies
 * `gate == 0xA5`, so a driver that doesn't search the input space will
 * never even reach the vulnerable loop, let alone trigger it.
 *
 * handle_command_gated() reads one "magic" byte first; only if it's
 * exactly 0xA5 does it fall into the same unchecked-index UART copy
 * loop as fixture 04's bad.c.
 *
 * Expected verdict: TRUE POSITIVE, but ONLY reachable/provable via a
 * driver that can solve for gate == 0xA5 specifically (angr path-solve
 * fallback, dvl.oracle_pathsolve) rather than a generic fixed payload.
 */
#include "mmio.h"

__attribute__((noinline))
void handle_command_gated(void)
{
    char gate = uart_getc();
    char cmd[8];
    unsigned int i = 0;
    char c;

    if (gate != (char)0xA5) {
        return;   /* wrong magic byte -- cmd is never touched */
    }

    do {
        c = uart_getc();
        cmd[i] = c;   /* BUG: no check that i < sizeof(cmd) */
        i++;
    } while (c != '\n' && i < 64);

    uart_putc(cmd[0]);
}

int main(void)
{
    handle_command_gated();
    sim_exit(0);
    return 0;
}
