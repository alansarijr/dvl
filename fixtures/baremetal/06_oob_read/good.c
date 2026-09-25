/*
 * Safe twin of bad.c: bounds-checked index before the read.
 *
 * Expected verdict: FALSE POSITIVE. print_nth_safe() never dereferences
 * arr[n] unless n is within [0, len).
 */
#include "mmio.h"

__attribute__((noinline))
void print_nth_safe(const char *arr, int n, int len)
{
    if (n < 0 || n >= len) {
        return;   /* out-of-range index: refuse to read */
    }
    char c = arr[n];
    uart_putc(c);
}

int main(void)
{
    const char data[8] = "ABCDEFG";

    print_nth_safe(data, 40, 8);   /* out of range -> returns before any read */

    sim_exit(0);
    return 0;
}
