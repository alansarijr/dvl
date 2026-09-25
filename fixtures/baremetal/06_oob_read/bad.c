/*
 * CWE-125: Out-of-bounds read. print_nth() indexes into an 8-byte array
 * with an unchecked index and transmits whatever byte it finds -- reading
 * arbitrary memory 32 bytes past the end of `data`.
 *
 * Expected verdict: TRUE POSITIVE.
 */
#include "mmio.h"

__attribute__((noinline))
void print_nth(const char *arr, int n)
{
    char c = arr[n];   /* BUG: no check that 0 <= n < length of arr */
    uart_putc(c);
}

int main(void)
{
    const char data[8] = "ABCDEFG";

    print_nth(data, 40);   /* reads 32 bytes past the end of data */

    sim_exit(0);
    return 0;
}
