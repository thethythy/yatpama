#ifndef _UTILITIES_H_
#define _UTILITIES_H_

#include <stdint.h>
#include "sha256.h"

void printfh(uint8_t *str, int len);
int getsl(char *str, int limit);

int compare(BYTE tab1[], int len1, BYTE tab2[], int len2);
void concat(BYTE tab1[], BYTE tab2[]);

void getAbsolutePath(const char * filename, char * argv0, char *path, size_t pathlen);

#endif