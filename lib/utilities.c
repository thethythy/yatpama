#include <stdio.h>
#include "utilities.h"

/*
 *  Print a string of hexadecimal values
 */
void printfh(uint8_t *str, int len) {
    for (int i = 0; i < len; ++i)
        printf("%.2x", str[i]);
    printf("\n");
}

/*
 * Get a string of characters with a maximum size equal to limit value.
 * Return the number of characters read
 */
int getsl(char *str, int limit) {
    char c;
    int i;
    for (i = 0; i < limit - 1 && (c = getchar()) != EOF && c != '\n'; i++) str[i] = c;
    str[i] = '\0';
    return i;
}

/*
 * Compare deux tableaux de BYTE
 * Renvoie 1 si ils sont identiques sinon -1
 */
int compare(BYTE tab1[], int len1, BYTE tab2[], int len2) {
    if (len1 != len2) return -1;
    for (int i = 0; i < len1; i++) if (tab1[i] != tab2[i]) return -1;
    return 1;
}

/*
 * Concaténation de deux tableaux de BYTE
 * Le dernier élément des tableaux doit être '\0'
 * tab1 est concaténer avec tab2 (tab2 mis en fin de tab1)
 * tab1 doit être assez grand pour contenir tab2
 */
void concat(BYTE tab1[], BYTE tab2[]) {
    int i, j;
    for(i = 0; tab1[i] != '\0'; i++);
    for(j = 0; tab2[j] != '\0'; j++, i++) tab1[i] = tab2[j];
    tab1[i] = '\0';
}