#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <sys/param.h>

#include "utilities.h"

/*
 * Print a string of hexadecimal values
 */
void printfh(uint8_t *str, int len) {
    for (int i = 0; i < len; ++i)
        printf("%.2x", str[i]);
    printf("\n");
}

/*
 * Compare two tables of BYTE
 * Return 1 if they are equal otherwise -1
 */
int compare(BYTE tab1[], int len1, BYTE tab2[], int len2) {
    if (len1 != len2) return -1;
    for (int i = 0; i < len1; i++) if (tab1[i] != tab2[i]) return -1;
    return 1;
}

/*
 * Get the full path of the file given in 1st parameter
 *
 * It is necessary to test the following 3 cases: we start by looking at the form of argv[0]
 * (1) If it starts with '/' it is an absolute path: we assume that it is found
 * (2) If it contains a '/' but not at the beginning, it is a relative path: we use getcwd
 * (3) If it contains no '/', search in the PATH
 */
void getAbsolutePath(const char * filename, char * argv0, char *abspath, size_t pathlen) {
    // 1er cass : absolute path
    if (argv0[0] == '/') {
        strncpy(abspath, argv0, pathlen);
        abspath[pathlen-1] = '\0';
    }

    // 2nd case : relative path
    else if (strchr(argv0, '/')) {
        char current_path[MAXPATHLEN];
        if (getcwd(current_path, MAXPATHLEN)) {
            snprintf(abspath, pathlen, "%s/%s", current_path, argv0);
        }
    }

    // 3rd case : in the PATH
    else {
        // We retrieve a reference on the PATH
        char * PATH_ENV = getenv("PATH");

        // Copy of environment variable required because it is modified
        char path[strlen(PATH_ENV)+1];
        strcpy(path, PATH_ENV);
        
        // We walk the PATH path by way
        char * pos_debut = path;
        char * pos_fin = path;
        
        do {
            
            // Find the end of the first path and replace ':' with '0'
            pos_fin = index(pos_debut, ':');
            if (pos_fin) *pos_fin = '\0';
            
            // Create the absolute path by concatenating the path and file name
            snprintf(abspath, pathlen, "%s/%s", pos_debut, filename);

            // Test whether the file exists and is accessible
            if (access(abspath, F_OK) == 0) {
                break; // Found --> we stop the loop
            } else {
                *abspath = '\0'; // We continue after "reset" the tested path
            }
            
            pos_debut = pos_fin + 1;

        } while(pos_fin);
        
    }
}