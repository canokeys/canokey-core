#include <apdu.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>

static void copy_data(uint8_t *buf, char **cmd, int lc) {
  for (int i = 0; i < lc; ++i)
    *buf++ = strtoul(*cmd, cmd, 16);
}

void apdu_fill_with_command(CAPDU *capdu, char *cmd) {
  int txLen = (strlen(cmd) + 1) / 3;
  CLA = strtoul(cmd, &cmd, 16);
  INS = strtoul(cmd, &cmd, 16);
  P1 = strtoul(cmd, &cmd, 16);
  P2 = strtoul(cmd, &cmd, 16);
  LC = 0;
  LE = 0;

  if (txLen == 4) // Case 1
    return;
  LC = strtoul(cmd, &cmd, 16);
  if (txLen == 5) { // Case 2S
    LE = LC;
    LC = 0;
  } else if (LC > 0 && txLen == 5 + LC) { // Case 3S
    copy_data(DATA, &cmd, LC);
  } else if (LC > 0 && txLen == 6 + LC) { // Case 4S
    copy_data(DATA, &cmd, LC);
    LE = strtoul(cmd, &cmd, 16);
    if (LE == 0)
      LE = 0x100;
  } else if (txLen == 7) { // Case 2E
    assert(LC == 0);
    LE = strtoul(cmd, &cmd, 16);
    LE = (LE << 8u) + strtoul(cmd, &cmd, 16);
  } else {
    assert(LC == 0);
    LC = strtoul(cmd, &cmd, 16);
    LC = (LC << 8u) + strtoul(cmd, &cmd, 16);
    assert(LC > 0);
    copy_data(DATA, &cmd, LC);
    if (txLen == 7 + LC) { // Case 3E
      return;
    } else if (txLen == 9 + LC) { // Case 4E
      LE = strtoul(cmd, &cmd, 16);
      LE = (LE << 8u) + strtoul(cmd, &cmd, 16);
      if (LE == 0)
        LE = 0x10000;
    } else {
      assert(0);
    }
  }
}
