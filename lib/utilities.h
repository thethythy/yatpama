#ifndef _UTILITIES_H_
#define _UTILITIES_H_

#include <stdint.h>
#include "sha256.h"

void printfh(const uint8_t *str, int len);

int compare(const BYTE tab1[], int len1, const BYTE tab2[], int len2);

void getAbsolutePath(const char * filename, char * argv0, char *path, size_t pathlen);

#endif