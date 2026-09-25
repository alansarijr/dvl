/*
 * CWE-121 auto-FP via reachability triage.
 *
 * dead_vulnerable_function() contains a real, massive stack overflow --
 * but it is never called from main(), never referenced by any vector
 * table entry (reset, exceptions, or IRQs), and never called by any
 * other reachable function. It is kept in the binary with
 * __attribute__((used)) purely so the code exists for the SAST tool to
 * find; the point of this fixture is to prove that our OWN static
 * reachability analysis (rooted at the reset vector + every IVT entry)
 * refutes the finding WITHOUT needing to emulate at all.
 *
 * Expected verdict: FALSE POSITIVE (via static reachability filter,
 * emulation should not even be necessary).
 */
#include "mmio.h"

__attribute__((used, noinline))
void dead_vulnerable_function(const char *input)
{
    char buf[8];
    mem_copy(buf, input, 64);   /* huge overflow, but nobody ever calls this */
    uart_putc(buf[0]);
}

int main(void)
{
    uart_putc('O');
    uart_putc('K');
    sim_exit(0);
    return 0;
}
