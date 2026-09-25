/*
 * "Smart Sensor Gateway" firmware -- a single, cohesive bare-metal
 * application combining several real product features, each shaped
 * like something you'd actually find in IoT/embedded firmware, rather
 * than an isolated unit-test fixture. Meant as a realistic sample to
 * run the full DVL pipeline against end-to-end.
 *
 * Built for the same Cortex-M3 bare-metal target as fixtures/baremetal
 * (reuses their common/startup.s, common/linker.ld, common/mmio.h) so

 * the DVL emulation harness recognizes it as a supported target and
 * performs full dynamic verification, not just static Tier-C refutation.
 *
 * Features (each independently reachable from main(), like a real
 * firmware's init sequence would call each subsystem's setup/service
 * routine):
 *   1. process_uart_command()  -- UART command-line parser.   REAL BUG (CWE-121)
 *   2. parse_header()          -- length-prefixed header parser. SAFE (FP bait, CWE-121)
 *   3. get_calibration()       -- calibration-table lookup.    REAL BUG (CWE-125)
 *   4. init_diagnostics_buffer()-- large-but-constant scratch buffer. SAFE (FP bait, CWE-789)
 *   5. UART0_IRQHandler()      -- interrupt-driven event logger. REAL BUG (CWE-121), IRQ-ONLY
 *   6. process_auth_command()  -- sync-byte-gated auth command.  REAL BUG (CWE-121),
 *      only reachable by satisfying `sync == 0xA5` first -- the generic
 *      concrete driver alone can't solve that gate, so this finding
 *      needs the angr symbolic path-solve fallback (dvl.oracle_pathsolve)
 *      to resolve, not just the plain Unicorn harness.
 */
#include "mmio.h"

/* ---- 1. UART command parser: REAL BUG (CWE-121/787) ---------------- */
/* Reads a '\n'-terminated command into a fixed 16-byte buffer with NO
 * bound check on the write index -- a classic embedded command-line
 * overflow triggered by whatever bytes arrive over UART before a
 * newline. */
__attribute__((noinline))
void process_uart_command(void)
{
    char cmd_buf[16];
    unsigned int i = 0;
    char c;

    do {
        c = uart_getc();
        cmd_buf[i] = c;         /* BUG: no check that i < sizeof(cmd_buf) */
        i++;
    } while (c != '\n' && i < 255);

    uart_putc(cmd_buf[0]);
}

/* ---- 2. Header parser: SAFE (FP bait for CWE-121) ------------------- */
/* Superficially similar shape to process_uart_command (also copies
 * variable-length attacker-influenced input into a fixed buffer) but
 * properly clamps the copy length first. */
__attribute__((noinline))
void parse_header(const char *raw, unsigned int raw_len)
{
    char header[32];
    unsigned int n = (raw_len < sizeof(header) - 1) ? raw_len : sizeof(header) - 1;
    mem_copy(header, raw, n);
    header[n] = 0;
    uart_putc(header[0]);
}

/* ---- 3. Calibration lookup: REAL BUG (CWE-125) ---------------------- */
static const int calibration_table[8] = {
    100, 102, 98, 101, 99, 103, 97, 100
};

__attribute__((noinline))
int get_calibration(int channel)
{
    return calibration_table[channel];  /* BUG: no check 0 <= channel < 8 */
}

/* ---- 4. Diagnostics buffer: SAFE (FP bait for CWE-789) -------------- */
/* Large (2048-byte) stack buffer -- large enough to trip a naive
 * SAST size threshold -- but the size is a compile-time constant, not
 * attacker-controlled, and only the first 64 bytes are ever touched. */
__attribute__((noinline))
void init_diagnostics_buffer(void)
{
    char diag[2048];
    for (unsigned int i = 0; i < 64; i++) {
        diag[i] = 0;
    }
    uart_putc(diag[0]);
}

/* ---- 5. Event logger ISR: REAL BUG (CWE-121), IRQ-ONLY -------------- */
/* Overrides the weak default UART0_IRQHandler in startup.s. Logs one
 * received byte per interrupt into a fixed ring buffer with NO bound
 * check on the index. Unreachable from main()'s call graph -- only
 * reachable via the vector table (IRQ0) -- a real product feature
 * (interrupt-driven event logging) shaped exactly like fixture 05's
 * hard problem. */
#define EVENT_LOG_LEN 8
static char event_log[EVENT_LOG_LEN];
static unsigned int event_log_idx = 0;

void UART0_IRQHandler(void)
{
    char c = (char)(UART0->DR & 0xFF);
    event_log[event_log_idx] = c;   /* BUG: no check that idx < EVENT_LOG_LEN */
    event_log_idx++;

    if (c == '\n') {
        event_log_idx = 0;
    }
}

/* ---- 6. Auth command handler: REAL BUG (CWE-121), sync-byte-gated --- */
/* Only real embedded protocols often prefix a command with a fixed sync
 * byte before trusting the rest of the frame. Reads that byte first --
 * only if it's exactly 0xA5 does it fall into an unchecked-index copy
 * loop -- the same shape as fixtures/baremetal/07_magic_gate/bad.c, but
 * here as a plausible real firmware feature rather than a unit fixture.
 * No amount of a generic fixed-pattern payload satisfies sync == 0xA5,
 * so proving this one reachable needs the angr path-solve fallback. */
__attribute__((noinline))
void process_auth_command(void)
{
    char sync = uart_getc();
    char auth_buf[12];
    unsigned int i = 0;
    char c;

    if (sync != (char)0xA5) {
        return;
    }

    do {
        c = uart_getc();
        auth_buf[i] = c;   /* BUG: no check that i < sizeof(auth_buf) */
        i++;
    } while (c != '\n' && i < 64);

    uart_putc(auth_buf[0]);
}

int main(void)
{
    const char sample_header[41] =
        "HDR:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";


    process_uart_command();
    parse_header(sample_header, 40);
    init_diagnostics_buffer();
    (void)get_calibration(40);   /* out-of-range channel index -> real OOB read */
    process_auth_command();

    sim_exit(0);
    return 0;
}
