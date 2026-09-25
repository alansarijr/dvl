/*
 * CWE-789 FP-bait: mirrors the real finding seen in row_413_bad.arm.elf,
 * where cwe_checker flags a large `sub sp, sp, #<imm>` as "Memory
 * Allocation with Excessive Size Value".
 *
 * large_but_constant_frame() allocates a 4096-byte stack buffer -- large
 * enough to trip a naive size threshold -- but the size is a compile-time
 * constant, not attacker-controlled, and only the first 10 bytes are ever
 * touched. There is no user-controlled allocation size and no overflow.
 *
 * Expected verdict: FALSE POSITIVE. The allocation-size oracle must show
 * the frame size is an immediate baked into the instruction (no taint
 * reaches it), independent of any emulated input.
 */
#include "mmio.h"

__attribute__((noinline))
void large_but_constant_frame(void)
{
    char buf[4096];   /* compiler emits: sub sp, sp, #4096 (constant) */

    for (unsigned int i = 0; i < 10; i++) {
        buf[i] = (char)('A' + i);
    }
    uart_putc(buf[0]);
}

int main(void)
{
    large_but_constant_frame();
    sim_exit(0);
    return 0;
}
