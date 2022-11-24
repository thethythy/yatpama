#include <stdio.h>

/*
 * Interface principale
 * Le programme attend que l'utilisateur utilise une commande connue
 */ 
char prompt() {
    char cmd;
    int again;

    do {
        printf("\n---------------------------------------------------------------------------");
        printf("\n                yatpama : Yet Another Tiny Password Manager                ");
        printf("\n---------------------------------------------------------------------------");
        printf("\n k pwd | p print | s search | a add | d del | e export | i import | q quit ");
        printf("\n---------------------------------------------------------------------------");
        printf("\nChoose a command: ");
        cmd = getchar();
        again = cmd != 'k' && cmd != 'p' && cmd != 'a' && cmd != 'q' &&
                cmd != 's' && cmd != 'd' && cmd != 'e' && cmd != 'i'; 
    } while (again);

    getchar(); // Enlever la touche 'Enter' du buffer du clavier

    return cmd;
}
