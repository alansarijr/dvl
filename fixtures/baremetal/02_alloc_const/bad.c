/*
 * CWE-789 twin of good.c: a constant stack allocation above cwe_checker's
 * default 7500-byte threshold (16 KiB, a quarter of the fixture board's
 * 64 KiB RAM) in one frame.
 *
 * Expected verdict: TRUE POSITIVE (medium) -- the allocation the finding
 * describes is really there.
 */
#include "mmio.h"

__attribute__((noinline))
void huge_constant_frame(void)
{
    char buf[16384];   /* compiler emits: sub sp, sp, #16384 (constant) */

    for (unsigned int i = 0; i < 10; i++) {
        buf[i] = (char)('A' + i);
    }
    uart_putc(buf[0]);
}

int main(void)
{
    huge_constant_frame();
    sim_exit(0);
    return 0;
}
