#ifndef _UTILITIES_H_
#define _UTILITIES_H_

#include <stdint.h>
#include "sha256.h"

void printfh(const uint8_t *str, int len);

void getAbsolutePath(const char * filename, char * argv0, char *path, size_t pathlen);

unsigned long exponentInteger(const unsigned long base, unsigned n);

uint32_t littleToBigEndian(uint32_t val);

#endif