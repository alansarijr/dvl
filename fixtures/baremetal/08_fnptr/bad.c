/*
 * CWE-121 in a function that is only ever called through a function
 * pointer. There is no direct `bl vulnerable_handler` anywhere; its
 * address sits in a data table that main() dispatches through, which is
 * how command tables, callbacks and RTOS task entries look in practice.
 *
 * Expected verdict: TRUE POSITIVE. A direct-call-only call graph wrongly
 * reports this function as unreachable.
 */
#include "mmio.h"

typedef void (*handler_fn)(const char *input, unsigned int len);

__attribute__((noinline))
void vulnerable_handler(const char *input, unsigned int len)
{
    char buf[16];
    mem_copy(buf, input, len);   /* BUG: no check that len <= sizeof(buf) */
    uart_putc(buf[0]);
}

handler_fn volatile handlers[1] = { vulnerable_handler };

int main(void)
{
    const char attacker_input[64] =
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

    handlers[0](attacker_input, 64);

    sim_exit(0);
    return 0;
}
