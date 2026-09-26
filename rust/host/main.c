/* SPDX-License-Identifier: Apache-2.0 */
/* POSIX signal entrypoints only; protocol and virtual-card policy are Rust. */
#include <signal.h>
static volatile sig_atomic_t stopped;
static void stop(int signal) { stopped = signal; }
int ck_host_stopping(void) { return stopped; }
int ck_host_udp_main(void);
int main(void) {
  signal(SIGTERM, stop);
  signal(SIGINT, stop);
  int status = ck_host_udp_main();
  return status ? status : stopped ? 128 + stopped : 0;
}
