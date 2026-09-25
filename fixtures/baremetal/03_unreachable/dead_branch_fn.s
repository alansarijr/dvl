/* See dead_branch.c. */
.syntax unified
.cpu cortex-m3
.thumb

.text
.global service_loop
.thumb_func
.type service_loop, %function
service_loop:
    push {r7, lr}
    sub sp, #8
    b done
    /* Dead: writes 8 bytes past the 8-byte frame, over the saved r7/lr. */
    movs r1, #0x41
    str r1, [sp, #8]
    str r1, [sp, #12]
done:
    add sp, #8
    pop {r7, pc}
.size service_loop, .-service_loop
