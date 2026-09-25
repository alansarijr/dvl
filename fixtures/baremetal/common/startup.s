/*
 * Generic Cortex-M3 startup code for DVL test fixtures.
 *
 * Vector table layout (standard ARMv7-M):
 *   [0]  initial SP (_estack)
 *   [1]  Reset_Handler
 *   [2]  NMI_Handler
 *   [3]  HardFault_Handler
 *   [4]  MemManage_Handler
 *   [5]  BusFault_Handler
 *   [6]  UsageFault_Handler
 *   [7-10]  Reserved (0)
 *   [11] SVC_Handler
 *   [12] DebugMon_Handler
 *   [13] Reserved (0)
 *   [14] PendSV_Handler
 *   [15] SysTick_Handler
 *   [16] IRQ0  = UART0_IRQHandler
 *   [17..23] IRQ1..IRQ7 = Default_Handler (dummy, unused)
 *
 * Every one of these entries is a legitimate CFG root for reachability
 * analysis -- a finding reachable only via IRQ7, for example, is NOT
 * unreachable just because main() never calls it.
 */

.syntax unified
.cpu cortex-m3
.thumb

.section .isr_vector, "a", %progbits
.global __isr_vector
__isr_vector:
    .word _estack
    .word Reset_Handler
    .word NMI_Handler
    .word HardFault_Handler
    .word MemManage_Handler
    .word BusFault_Handler
    .word UsageFault_Handler
    .word 0
    .word 0
    .word 0
    .word 0
    .word SVC_Handler
    .word DebugMon_Handler
    .word 0
    .word PendSV_Handler
    .word SysTick_Handler
    .word UART0_IRQHandler   /* IRQ0 */
    .word IRQ1_Handler
    .word IRQ2_Handler
    .word IRQ3_Handler
    .word IRQ4_Handler
    .word IRQ5_Handler
    .word IRQ6_Handler
    .word IRQ7_Handler

.section .text.Reset_Handler
.thumb_func
.global Reset_Handler
Reset_Handler:
    /* copy .data from FLASH (_sidata) to RAM (_sdata .. _edata) */
    ldr r0, =_sidata
    ldr r1, =_sdata
    ldr r2, =_edata
copy_loop:
    cmp r1, r2
    bcs copy_done
    ldr r3, [r0]
    adds r0, r0, #4
    str r3, [r1]
    adds r1, r1, #4
    b copy_loop
copy_done:

    /* zero .bss (_sbss .. _ebss) */
    ldr r1, =_sbss
    ldr r2, =_ebss
    movs r3, #0
zero_loop:
    cmp r1, r2
    bcs zero_done
    str r3, [r1]
    adds r1, r1, #4
    b zero_loop
zero_done:

    bl main
hang:
    b hang
.size Reset_Handler, .-Reset_Handler

/* Default handler: tight infinite loop. Easy for the emulator to detect
 * (PC stuck at a fixed address) and report as an unhandled-exception fault
 * rather than silently hanging. */
.section .text.Default_Handler
.thumb_func
Default_Handler:
    b Default_Handler
.size Default_Handler, .-Default_Handler

.weak NMI_Handler
.thumb_set NMI_Handler, Default_Handler

.weak HardFault_Handler
.thumb_set HardFault_Handler, Default_Handler

.weak MemManage_Handler
.thumb_set MemManage_Handler, Default_Handler

.weak BusFault_Handler
.thumb_set BusFault_Handler, Default_Handler

.weak UsageFault_Handler
.thumb_set UsageFault_Handler, Default_Handler

.weak SVC_Handler
.thumb_set SVC_Handler, Default_Handler

.weak DebugMon_Handler
.thumb_set DebugMon_Handler, Default_Handler

.weak PendSV_Handler
.thumb_set PendSV_Handler, Default_Handler

.weak SysTick_Handler
.thumb_set SysTick_Handler, Default_Handler

.weak UART0_IRQHandler
.thumb_set UART0_IRQHandler, Default_Handler

.weak IRQ1_Handler
.thumb_set IRQ1_Handler, Default_Handler
.weak IRQ2_Handler
.thumb_set IRQ2_Handler, Default_Handler
.weak IRQ3_Handler
.thumb_set IRQ3_Handler, Default_Handler
.weak IRQ4_Handler
.thumb_set IRQ4_Handler, Default_Handler
.weak IRQ5_Handler
.thumb_set IRQ5_Handler, Default_Handler
.weak IRQ6_Handler
.thumb_set IRQ6_Handler, Default_Handler
.weak IRQ7_Handler
.thumb_set IRQ7_Handler, Default_Handler

.end
