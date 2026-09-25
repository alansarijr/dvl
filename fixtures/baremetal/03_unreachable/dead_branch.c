/*
 * main() calls service_loop() (dead_branch_fn.s), so service_loop is
 * reachable at the call-graph level. Its overflowing store sits behind an
 * unconditional branch and no path inside the function reaches it.
 *
 * Written in assembly because compilers delete such code even at -O0; it
 * does show up in hand-written assembly and patched firmware.
 *
 * Expected verdict: FALSE POSITIVE (dead code inside a live function).
 */
#include "mmio.h"

void service_loop(void);

int main(void)
{
    service_loop();
    sim_exit(0);
    return 0;
}
