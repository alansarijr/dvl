/*
 * Safe twin of bad.c: same call shape, but the copy length is clamped to
 * the destination buffer size before mem_copy() runs. No OOB write occurs.
 *
 * Expected verdict: FALSE POSITIVE (if a SAST tool flags this function at
 * all, dynamic verification must clear it -- the bounds oracle sees every
 * write land inside [buf, buf+16)).
 */
#include "mmio.h"

__attribute__((noinline))
void safe_copy(const char *input, unsigned int len)
{
    char buf[16];
    unsigned int n = (len < sizeof(buf) - 1) ? len : sizeof(buf) - 1;
    mem_copy(buf, input, n);
    buf[n] = 0;
    uart_putc(buf[0]);
}

int main(void)
{
    const char attacker_input[64] =
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

    safe_copy(attacker_input, 64);  /* clamped to 15 bytes + NUL, no overflow */

    sim_exit(0);
    return 0;
}
