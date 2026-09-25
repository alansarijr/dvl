/*
 * CWE-121/787 reachable ONLY via an interrupt handler -- the prompt's
 * 2nd named hard problem: reachability analysis must root its CFG at
 * "the reset vector AND check whether the flagged address is reachable
 * ... from any entry point (interrupt handlers included)".
 *
 * main() never calls anything related to irq_buf; it just waits for
 * interrupts (wfi). The only path to the overflow is through
 * UART0_IRQHandler, which is entry [16] of the vector table (IRQ0).
 *
 * A reachability analysis rooted only at main()/Reset_Handler would
 * wrongly classify this as unreachable (FP). A reachability analysis
 * that also roots at every vector-table slot correctly finds it
 * reachable via IRQ0. This fixture's dynamic verification does not rely
 * on simulating a full NVIC/interrupt controller -- per the prompt's
 * step 4 ("symbolic execution to solve for register/memory state at the
 * finding's entry point, and directly seed emulation there"), the
 * emulator seeds execution directly at UART0_IRQHandler's entry with a
 * representative machine state and drives the loop with injected UART
 * bytes, exactly like fixture 04's MMIO handling.
 *
 * Expected verdict: TRUE POSITIVE.
 */
#include "mmio.h"

#define IRQ_BUF_LEN 8
static char irq_buf[IRQ_BUF_LEN];
static unsigned int irq_buf_idx = 0;

/* Overrides the weak default in startup.s -- this becomes vector[16]. */
void UART0_IRQHandler(void)
{
    char c = (char)(UART0->DR & 0xFF);
    irq_buf[irq_buf_idx] = c;   /* BUG: no check that irq_buf_idx < IRQ_BUF_LEN */
    irq_buf_idx++;

    if (c == '\n') {
        irq_buf_idx = 0;
    }
}

int main(void)
{
    /* Real hardware would enable the UART0 IRQ in the NVIC here. In this
     * fixture, main() itself never touches irq_buf -- everything relevant
     * happens only inside the ISR above. */
    for (;;) {
        __asm volatile ("wfi");
    }
}
