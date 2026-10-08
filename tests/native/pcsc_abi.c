/* SPDX-License-Identifier: Apache-2.0 */
/* Link the Rust IFD exports using the installed platform declarations. */
#include <ifdhandler.h>
#include <reader.h>
#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#ifdef __APPLE__
_Static_assert(sizeof(DWORD) == sizeof(uint32_t), "Apple DWORD is uint32_t");
#else
_Static_assert(sizeof(DWORD) == sizeof(unsigned long), "PCSC DWORD is unsigned long");
#endif
_Static_assert(sizeof(RESPONSECODE) == sizeof(long), "IFD RESPONSECODE is long");
_Static_assert(sizeof(SCARD_IO_HEADER) == 2 * sizeof(DWORD), "PCI holds two DWORDs");
_Static_assert(offsetof(SCARD_IO_HEADER, Length) == sizeof(DWORD), "PCI field offset");
static RESPONSECODE (*polling)(DWORD, int);
static void *poll_thread(void *argument) {
  DWORD lun = *(DWORD *)argument;
  polling(lun, 10000);
  return NULL;
}
int main(void) {
  /* An unopened reader exercises signatures without persistent side effects. */
  const DWORD lun = 0x10000;
  DWORD length = 8;
  unsigned char output[8] = {0};
  SCARD_IO_HEADER send = {.Protocol = SCARD_PROTOCOL_T1, .Length = sizeof(send)};
  SCARD_IO_HEADER receive = {0};
  assert(IFDHCloseChannel(lun) == IFD_NO_SUCH_DEVICE);
  assert(IFDHICCPresence(lun) == IFD_ICC_NOT_PRESENT);
  assert(IFDHGetCapabilities(lun, TAG_IFD_ATR, &length, output) == IFD_NO_SUCH_DEVICE);
  assert(length == 0);
  assert(IFDHGetCapabilities(lun, TAG_IFD_ATR, NULL, output) == IFD_COMMUNICATION_ERROR);
  assert(IFDHSetCapabilities(lun, TAG_IFD_ATR, 0, output) == IFD_ERROR_TAG);
  assert(IFDHSetProtocolParameters(lun, SCARD_PROTOCOL_T1, 0, 0, 0, 0) == IFD_NO_SUCH_DEVICE);
  assert(IFDHPowerICC(lun, IFD_POWER_UP, output, &length) == IFD_NO_SUCH_DEVICE);
  assert(IFDHTransmitToICC(lun, send, output, 1, output, &length, &receive) == IFD_NO_SUCH_DEVICE);
  assert(receive.Protocol == SCARD_PROTOCOL_T1 && receive.Length == sizeof(receive));
  length = 8;
  assert(IFDHControl(lun, 0, NULL, 0, output, sizeof(output), &length) == IFD_ERROR_NOT_SUPPORTED);
  assert(length == 0);
  /* The prescribed killable callback must survive POSIX forced unwinding. */
  char directory[] = "/tmp/canokey-pcsc-abi-XXXXXX";
  assert(mkdtemp(directory));
  char image[sizeof(directory) + 8];
  assert(snprintf(image, sizeof(image), "%s/image", directory) > 0);
  assert(setenv("CANOKEY_VIRT_LFS_ROOT", image, 1) == 0);
  assert(setenv("CANOKEY_VIRT_RESET_STORAGE", "1", 1) == 0);
  assert(IFDHCreateChannel(lun, 0) == IFD_SUCCESS);
  length = sizeof(polling);
  assert(IFDHGetCapabilities(lun, TAG_IFD_POLLING_THREAD_WITH_TIMEOUT,
                            &length, (PUCHAR)&polling) == IFD_SUCCESS);
  assert(length == sizeof(polling));
  assert(polling(lun, -1) == IFD_COMMUNICATION_ERROR);
  assert(polling(lun, 0) == IFD_RESPONSE_TIMEOUT);
  pthread_t thread;
  assert(pthread_create(&thread, NULL, poll_thread, (void *)&lun) == 0);
  assert(pthread_cancel(thread) == 0);
  void *result = NULL;
  assert(pthread_join(thread, &result) == 0 && result == PTHREAD_CANCELED);
  assert(IFDHCloseChannel(lun) == IFD_SUCCESS);
  assert(unlink(image) == 0);
  assert(rmdir(directory) == 0);
  return 0;
}
