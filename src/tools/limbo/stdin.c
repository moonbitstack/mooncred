// The suite arrives on standard input, so that no path has to travel through
// the command line and no encoding of it has to be got right on three systems.

#include "moonbit.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

MOONBIT_FFI_EXPORT
moonbit_bytes_t mooncred_limbo_stdin(void) {
  size_t capacity = 1u << 22;
  size_t length = 0;
  unsigned char *buffer = (unsigned char *)malloc(capacity);
  if (buffer == NULL) {
    return moonbit_make_bytes(0, 0);
  }
  for (;;) {
    if (length == capacity) {
      capacity *= 2;
      unsigned char *grown = (unsigned char *)realloc(buffer, capacity);
      if (grown == NULL) {
        free(buffer);
        return moonbit_make_bytes(0, 0);
      }
      buffer = grown;
    }
    size_t got = fread(buffer + length, 1, capacity - length, stdin);
    if (got == 0) {
      break;
    }
    length += got;
  }
  moonbit_bytes_t out = moonbit_make_bytes((int32_t)length, 0);
  memcpy(out, buffer, length);
  free(buffer);
  return out;
}
