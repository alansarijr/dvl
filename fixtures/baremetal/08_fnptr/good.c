/*
 * Safe twin of 08_fnptr/bad.c: same function-pointer dispatch, but the
 * copy length is clamped first.
 *
 * Expected verdict: FALSE POSITIVE, established by emulation (the handler
 * is reachable, it just never writes out of bounds), not by a wrong
 * "unreachable" answer.
 */
#include "mmio.h"

typedef void (*handler_fn)(const char *input, unsigned int len);

__attribute__((noinline))
void safe_handler(const char *input, unsigned int len)
{
    char buf[16];
    unsigned int n = len < sizeof(buf) ? len : sizeof(buf) - 1;
    mem_copy(buf, input, n);
    uart_putc(buf[0]);
}

handler_fn volatile handlers[1] = { safe_handler };

int main(void)
{
    const char attacker_input[64] =
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

    handlers[0](attacker_input, 64);

    sim_exit(0);
    return 0;
}
