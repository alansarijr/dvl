/*
 * Safe function whose stack slot is later reused. After fill_status()
 * returns, main() writes its own 32-byte local, which lies just above
 * fill_status()'s old frame. Those writes come from main, after
 * fill_status's frame is gone, so they say nothing about `buf`.
 *
 * Expected verdict: FALSE POSITIVE. An oracle that keeps using the frame
 * base of a function after it returns reports main's writes as a 52-byte
 * overflow of `buf`.
 */
#include "mmio.h"

__attribute__((noinline))
void fill_status(void)
{
    char buf[8];
    for (int i = 0; i < 8; i++) {
        buf[i] = 'a';
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
