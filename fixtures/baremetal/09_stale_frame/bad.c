/*
 * Buggy twin of 09_stale_frame/good.c: fill_status() itself writes past
 * `buf`, and main() still reuses the stack afterwards.
 *
 * Expected verdict: TRUE POSITIVE, from fill_status's own writes while its
 * frame is live.
 */
#include "mmio.h"

__attribute__((noinline))
void fill_status(void)
{
    char buf[8];
    for (int i = 0; i < 24; i++) {
        buf[i] = 'a';   /* BUG: loop bound exceeds sizeof(buf) */
    }
    uart_putc(buf[0]);
}

int main(void)
{
    volatile char state[32];

    fill_status();
    for (int i = 0; i < 32; i++) {
        state[i] = (char)i;
    }

    sim_exit(state[5]);
    return 0;
}
