/*
 * CWE-121 / CWE-787: Stack-based buffer overflow via unchecked copy.
 *
 * vulnerable_copy() copies `len` bytes into a fixed 16-byte stack buffer
 * with no bound check. main() calls it with 64 bytes of attacker-shaped
 * input, overflowing `buf` by 48 bytes and clobbering whatever the
 * compiler placed above it on the stack.
 *
 * Expected verdict: TRUE POSITIVE (see expected.json)
 */
#include "mmio.h"

__attribute__((noinline))
void vulnerable_copy(const char *input, unsigned int len)
{
    char buf[16];
    mem_copy(buf, input, len);   /* BUG: no check that len <= sizeof(buf) */
    uart_putc(buf[0]);
}

int main(void)
{
    const char attacker_input[64] =
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

    vulnerable_copy(attacker_input, 64);  /* 48 bytes past the end of buf */

    sim_exit(0);
    return 0;
}
