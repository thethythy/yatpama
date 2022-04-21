#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <sys/param.h>

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

/*
 * Obtenir le chemin complet du fichier donné en 1er paramètre
 *
 * Il faut tester les 3 cas suivants : on commence par regarder la forme de argv[0]
 * (1) S'il commence par '/' c'est un chemin absolu : on assume que c'est trouvé
 * (2) S'il contient un '/' mais pas au début, c'est un chemin relatif : on utilise getcwd
 * (3) S'il ne contient aucun '/', il faut chercher dans le PATH
 */
void getAbsolutePath(const char * filename, char * argv0, char *abspath, size_t pathlen) {
    // 1er cas : chemin absolu
    if (argv0[0] == '/') {
        strncpy(abspath, argv0, pathlen);
        abspath[pathlen-1] = '\0';
    }

    // 2ème cas : chemin relatif
    else if (strchr(argv0, '/')) {
        char current_path[MAXPATHLEN];
        if (getcwd(current_path, MAXPATHLEN)) {
            snprintf(abspath, pathlen, "%s/%s", current_path, argv0);
        }
    }

    // 3ème cas : dans le PATH
    else {
        // On récupère une référence sur le PATH
        char * PATH_ENV = getenv("PATH");

        // Copie de la variable d'environnement obligatoire car on la modifie
        char path[strlen(PATH_ENV)+1];
        strcpy(path, PATH_ENV);
        
        // On parcours le PATH chemin par chemin
        char * pos_debut = path;
        char * pos_fin = path;
        
        do {
            
            // Trouver la fin du premier chemin puis remplacer ':' par '\0'
            pos_fin = index(pos_debut, ':');
            if (pos_fin) *pos_fin = '\0';
            
            // Créer le chemin absolu en concaténer le chemin et le nom du fichier
            snprintf(abspath, pathlen, "%s/%s", pos_debut, filename);

            // Tester si le fichier existe et est accessible
            if (access(abspath, F_OK) == 0) {
                break; // Trouvé --> on arrête la boucle
            } else {
                *abspath = '\0'; // On continu après avoir "reset" le chemin testé
            }
            
            pos_debut = pos_fin + 1;

        } while(pos_fin);
        
    }
}