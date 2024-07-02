#include <curses.h>
#include <stdio.h>
#include <string.h>
#include <sys/param.h>
#include <time.h>
#include <unistd.h>

#include "yatpama_shared.h"
#include "../lib/sha256.h"
#include "../lib/utilities.h"

#define KEY_DEL 127     // DEL key
#define KEY_SPACE 32    // Space key

typedef struct UI_Windows {
    WINDOW * title_win;     // The title window at the top of the terminal
    WINDOW * commands_win;  // The command window after the title
    WINDOW * prompt_win;    // The prompt window just after the command window
    WINDOW * view_win;      // The main window for displaying entries
    WINDOW * alert_win;     // The alert window for displaying error messages and alerts
} UI_Windows ;

/*
 * Display an alert or a useful information
 * Parameter 1: the window where displaying
 * Parameter 2: the message to display
 */
void displayAnAlertMessage(WINDOW * win, char * message) {
    wmove(win, 1, 0);
    wclrtoeol(win); // Clear line 
    wprintw(win, "%s", message);
    wrefresh(win);
}

/*
 * Display an entry
 * Parameter 1: the window for displaying the entry
 * Parameter 2: the number of the entry
 * Parameter 3: the field information of the entry
 * Parameter 4: the field secret of the entry
 */
void displayAnEntry(WINDOW * win, int nbInfo, char * information, char * secret) {
    int row, col, y, x;
    getmaxyx(win, row, col);    // Get the number of rows and columns
    getyx(win, y, x);           // Get the current position

    if (y >= row - 1 - 3) {
        wprintw(win, "Enter any key before displaying next entries");
        wgetch(win);
        wrefresh(win);
    }

    wprintw(win, "Entry n°%i:", nbInfo);
    wprintw(win, "\n Information: ");
    wprintw(win, "\t%s", information);
    wprintw(win, "\n Secret: ");
    wprintw(win, "\t%s\n", secret);
    wrefresh(win);
}

/*
 * Clear the window displaying entries
 * Parameter 1: the window for displaying the entry 
 */
void clear_view_window(WINDOW * win) {
    wclear(win);
    wrefresh(win);
}

/*
 * Draw the title window
 * Parameter 1: the title window pointer
 */
void display_title_window(WINDOW * win) {
    int row, col;
    getmaxyx(win, row, col);   // Get the number of rows and columns

    wmove(win, 0, (col - 36) / 2);
    wprintw(win, "          ___   __");
    wmove(win, 1, (col - 36) / 2);       
    wprintw(win, "\\ /  /\\    |   |__|  /\\   |\\/|   /\\");
    wmove(win, 2, (col - 36) / 2);
    wprintw(win, " |  /  \\   |   |    /  \\  |  |  /  \\");

    char mesg[] = "Yet Another Tiny Password Manager";
    mvwprintw(win, row - 1, (col - (int)strlen(mesg)) / 2, "%s", mesg);
    
    wrefresh(win);
}

/*
 * Draw the command-list window
 * Parameter 1: the command-list window pointer
 */
void display_command_window(WINDOW * win) {
    int row, col;
    getmaxyx(win, row, col);   // Get the number of rows and columns
    char mesg[] = "[p]wd [l]ist [s]earch [a]dd [d]el e[x]port [i]mport [q]uit";
    mvwprintw(win, row - 2, (col - (int)strlen(mesg)) / 2, "%s", mesg);
    box(win, 0, 0);
    wrefresh(win);
}

/* 
 * Display the prompt window
 * Parameter 1: the prompt window pointer
 */
void display_prompt_window(WINDOW * win) {
    int row, col;
    getmaxyx(win, row, col);                    // get the number of rows and columns
    mvwhline(win, row - 1, 0, ACS_HLINE, col);  // draw a horizontal line at the top
    wrefresh(win);
}

/* 
 * Display the alert window
 * Parameter 1: the alert window pointer
 */
void display_alert_window(WINDOW * win) {
    int row, col;
    getmaxyx(win, row, col);                // get the number of rows and columns
    mvwhline(win, 0, 0, ACS_HLINE, col);    // draw a horizontal line at the bottom
    wrefresh(win);
}

/*
 * Get a string of characters
 * Parameter 1: the window used to get the string
 * Parameter 2: the prompt message
 * Parameter 3: the string
 * Parameter 4: the max length of the string
 * Parameter 5: a flag to indicate a secret (0) or a public (> 0) string
 */
void getAString(WINDOW * win, char * prompt, char * mesg, int size_max, int flag) {
    memset(mesg, 0, size_max);
    wmove(win, 0, 0);                   // Go to the beginning
    wclrtoeol(win);                     // Clear line
    wprintw(win, "%s", prompt);         // Display the prompt

    if (flag > 0) {
        wgetnstr(win, mesg, size_max);  // Get a public string
    }
    else {                              // Get a secret string

        int ch, x, xinit, y, again, len = 0;
        int isCharExtented = 0; // Extended char encoding flag
        getyx(win, y, x); // Get cursor initial position
        xinit = x;

        struct timespec delay;
        delay.tv_sec = 0;
        delay.tv_nsec = 250000000; // Period before masking the previous char

        do {
            noecho();
            ch = wgetch(win); // Get a character without echoing
            echo();

            // Is it backspace or del key ?
            if (ch == KEY_DEL || ch == KEY_BACKSPACE) {

                if (x > xinit ) {
                    // Erase an extended char encoding ?
                    if ((uint8_t)*(mesg - 2) >= 128u) {
                        mesg = mesg - 2; len = len - 2; // Yes : "erase" two char
                    } else { 
                        mesg--; len--;                  // No : "erase" one char
                    }

                    *mesg = '\0';                       // New end of string

                    mvwaddch(win, y, --x, KEY_SPACE);   // Mask the previous key by a space
                    wmove(win, y, x);                   // New cursor position
                    wrefresh(win);
                }
            } 
            else {

                again = (char)ch != '\n' && len < size_max - 1;

                // Add the key in the message string
                if (again) {
                    *mesg++ = (char)ch;
                    len++;
                }

                // Display char in the window then after a short period mask it
                // We also have to handle extended encoding

                if (ch < 128 && !isCharExtented) {
                    mvwaddch(win, y, x, ch);
                    wrefresh(win);
                    nanosleep(&delay, NULL);
                    mvwaddch(win, y, x++, '*');
                } else if (ch >= 128 && !isCharExtented) {
                    isCharExtented = 1;
                } 
                else if (isCharExtented) {
                    isCharExtented = 0;
                    mvwaddstr(win, y, x++, mesg - 2);
                    wrefresh(win);
                    nanosleep(&delay, NULL);
                    mvwaddch(win, y, x++, '*');
                }

            }

        } while (again);

        *mesg = '\0';
    }
}

/*
 * Lock the terminal and wait the user password to unlock it 
 * Paramater 1: record of the window pointers
 * Parameter 2: the password hash
 */
void lock_hmi(UI_Windows * wins, BYTE * pass_hash) {
    char msecret[PWD_MAX_SIZE]; // The password
    BYTE hash[32]; // The hash to control

    do {

        // Clear the screen and wait for a keystroke
        erase(); refresh(); curs_set(0);
        mvprintw((int)(LINES / 2), (int)(COLS / 2 - 17), "Hit a key to unlock the screen");
        timeout(-1);
        getch();
        erase(); refresh(); curs_set(1);

        // Get the password then control it
        getAString(wins->prompt_win, "Master password: ", msecret, PWD_MAX_SIZE, 0);
        sha256((BYTE *)msecret, strlen(msecret), hash);

    } while (1 != compare(hash, 32, pass_hash, 32));

    // Re-draw the HMI
    display_title_window(wins->title_win);
    display_command_window(wins->commands_win);
    display_prompt_window(wins->prompt_win);
    display_alert_window(wins->alert_win);
}

/*
 * Wait that the user chooses a valid command
 * After a timeout, lock the terminal
 * Paramater 1: record of the window pointers
 * Parameter 2: flag that indicates if user is connected
 * Parameter 3: the password hash
 */ 
char getAValidCommand(UI_Windows * wins, int isConnected, BYTE * pass_hash) {
    char cmd;
    int again = 1, key, timer;

    timer = TIMEOUT_LOCK * 1000; // Timer in ms before locking the terminal

    do {
        wmove(wins->prompt_win, 0, 0);
        wclrtoeol(wins->prompt_win); // Clear line 

        mvwprintw(wins->prompt_win, 0, 0, "Choose a command: "); // Display a prompt
        wrefresh(wins->prompt_win);

        wtimeout(wins->prompt_win, 1000);   // Set blocking read for 1 second
        key = wgetch(wins->prompt_win);     // Wait 1 second a character
        wtimeout(wins->prompt_win, -1);     // Blocking read for next getch

        // Ready to lock the terminal (user must be connected) ?
        if (key == ERR && isConnected) {
            timer = timer - 1000; // One second elapsed
            if (timer == 0) {
                lock_hmi(wins, pass_hash); // Lock because timer == zero
                timer = TIMEOUT_LOCK * 1000; // Reset timer
            }
        } else {
            cmd = (char)key;
            again = cmd != 'p' && cmd != 'l' && cmd != 'a' && cmd != 'q' &&
                    cmd != 's' && cmd != 'd' && cmd != 'x' && cmd != 'i';
        }

    } while (again);

    return cmd;
}

#define T_W_H   5
#define C_W_H   3
#define P_W_H   2
#define A_W_H   2

/*
 * Start and paramaterize the curses mode then draw user interface
 * Parameter 1: record of the window pointers
 * Return value: 0 if OK -1 if KO
 */
int start_paramaterize_curses(UI_Windows * wins) {
    initscr();  // Start the curses mode

    // Verify the terminal size
    if (COLS < 67 || LINES < 17) {
        endwin(); // Stop the curses mode now !
        fprintf(stderr, "The terminal size (%dx%d) is too small to start Yatpama!...\n", COLS, LINES);
        return -1;
    }

    cbreak();   // Control characters ; No keyboard buffering
    echo();     // Echoing input characters
    keypad(stdscr, TRUE);   // Function keys available (F1, ..., UP, ...)

    // Create and draw the title window
    wins->title_win = newwin(T_W_H, COLS, 0, 0);
    display_title_window(wins->title_win);

    // Create and draw the command list window
    wins->commands_win = newwin(C_W_H, COLS, T_W_H, 0);
    display_command_window(wins->commands_win);

    // Create the prompt window
    wins->prompt_win = newwin(P_W_H, COLS, T_W_H + C_W_H, 0);
    display_prompt_window(wins->prompt_win);

    // Create the window of the list of entries
    int view_win_height = LINES - T_W_H - C_W_H - P_W_H - A_W_H;
    wins->view_win = newwin(view_win_height, COLS, T_W_H + C_W_H + P_W_H, 0);
    scrollok(wins->view_win, TRUE);
    idlok(wins->view_win, TRUE);

    // Create the window for displaying alert messages
    wins->alert_win = newwin(A_W_H, COLS, T_W_H + C_W_H + P_W_H + view_win_height, 0);
    display_alert_window(wins->alert_win);

    return 0;
}

/* 
 * Stop the curses mode
 * Parameter 1: record of the window pointers
 */
void stop_curses(UI_Windows * wins) {
    // Free UI windows
    delwin(wins->title_win);
    delwin(wins->commands_win);
    delwin(wins->prompt_win);
    delwin(wins->view_win);
    delwin(wins->alert_win);

    endwin();   // Stop the curses mode
}

/*
 * Main interaction loop
 * Parameter 1: a shared data record
 * Parameter 2: a record of pointers on windows
 * Parameter 3: a flag to indicate if the user is connected
 * Parameter 4: the user password hash
 */
void interaction_loop(T_Shared * pt_sh, UI_Windows * wins, int isConnected, BYTE * pass_hash) {
    char command; // The current command

    command = getAValidCommand(wins, isConnected, pass_hash); // Wait an order

    switch (command) {

        // Enter the password and generate the key
        case 'p':
            displayAnAlertMessage(wins->alert_win, "Enter a password");
            char msecret[PWD_MAX_SIZE]; // The password
            
            // Get the user password
            getAString(wins->prompt_win, "Master password: ", msecret, PWD_MAX_SIZE, 0);
            add_shared_cmd_1arg(pt_sh, CORE_CMD_KEY, msecret); // Request to create the key

            sha256((BYTE *)msecret, strlen(msecret), pass_hash); // Generate a fingerprint of the password            
            memset(msecret, 0, PWD_MAX_SIZE);

            break;

        // Displaying entries
        case 'l':
            clear_view_window(wins->view_win);
            displayAnAlertMessage(wins->alert_win, "Print list of entries");
            add_shared_cmd_0arg(pt_sh, CORE_CMD_PRINT); // Request for the list
            break;

        // Filtering entries
        case 's':
            clear_view_window(wins->view_win);
            displayAnAlertMessage(wins->alert_win, "Search entries following a pattern");
            char pattern[MAX_SIZE]; // The filtering pattern
            getAString(wins->prompt_win, "Pattern: ", pattern, MAX_SIZE, 1);
            add_shared_cmd_1arg(pt_sh, CORE_CMD_SEARCH, pattern); // Request for search
            break;

        // Add a new entry
        case 'a':
            clear_view_window(wins->view_win);
            displayAnAlertMessage(wins->alert_win, "Add a new secret information");

            char information[MAX_SIZE];
            getAString(wins->prompt_win, "Information: ", information, MAX_SIZE, 1);
            
            char secret[MAX_SIZE];
            getAString(wins->prompt_win, "Secret: ", secret, MAX_SIZE, 1);
            
            add_shared_cmd_2arg(pt_sh, CORE_CMD_ADD, information, secret); // Request to add an entry

            memset(information, 0, MAX_SIZE);
            memset(secret, 0, MAX_SIZE);

            break;

        // Normal shutdown
        case 'q':
            add_shared_cmd_0arg(pt_sh, HMI_CMD_EXIT); // End of user interface
            break;
        
        // Removing an entry
        case 'd':
            clear_view_window(wins->view_win);
            displayAnAlertMessage(wins->alert_win, "Delete an entry");
            char cNbEntry[ENTRY_NB_MAX_NB + 1]; // Number entry as a string of characters
            getAString(wins->prompt_win, "Give entry number: ", cNbEntry, ENTRY_NB_MAX_NB + 1, 1); // Get the entry number to remove
            add_shared_cmd_1arg(pt_sh, CORE_CMD_DEL_P1, cNbEntry); // Request to get the entry concerned
            break;

        // Exportation of entries
        case 'x':
            clear_view_window(wins->view_win);
            displayAnAlertMessage(wins->alert_win, "Export entries");
            char file_export[MAXPATHLEN];
            getAString(wins->prompt_win, "Give the name of the file to export to: ", file_export, MAXPATHLEN, 1);
            add_shared_cmd_1arg(pt_sh, CORE_CMD_EXP, file_export); // Request to execute an exportation
            break;

        // Importation of entries
        case 'i':
            clear_view_window(wins->view_win);
            displayAnAlertMessage(wins->alert_win, "Import entries");
            char file_import[MAXPATHLEN];
            getAString(wins->prompt_win, "Give the name of the file to import from: ", file_import, MAXPATHLEN, 1);
            add_shared_cmd_1arg(pt_sh, CORE_CMD_IMP, file_import); // Request to execute an importation
            break;

        default:
            break;
    }
}

/*
 * HMI command management thread
 * Parameter 1: a data useful for the thread (a structure T_Shared)
 */
void * thread_hmi(void * t_arg) {
    T_Shared * pt_sh = t_arg; // The argument is a structure T_Shared
    UI_Windows wins; // Curses windows of the user interface

    char message[ALERT_MAX_SIZE];   // To store alert and error messages
    char answer[2];                // Store a response y/n
    char next_command[CMD_NB_MAX_NB]; // Store the next command (as a string)
    char question[PROMPT_MAX_SIZE]; // Store the prompt

    char nbInfo[ENTRY_NB_MAX_NB];   // Entries number as a string
    char information[MAX_SIZE];     // Information field of the entry
    char secret[MAX_SIZE];          // Secret field of the entry

    // Start and paramaterize the cursus mode then draw user interface
    if (start_paramaterize_curses(& wins) == -1) {
        add_shared_cmd_hpriority(pt_sh, CORE_CMD_EXIT); // Priority request to stop CORE thread
        return NULL;
    }

    BYTE pass_hash[32];     // The password hash (sha256)
    int isConnected = 0;    // Flag to know if user is connected or not

    int loop_again = 1;
    while(loop_again == 1) {
    
        int hmi_cmd = 0;

        // Read a command
        hmi_cmd = get_shared_cmd(pt_sh);
    
        switch (hmi_cmd) {

            // Wait a new command
            case HMI_CMD_LOOP_INTER:
                delete_shared_cmd(pt_sh, 0); // Delete the command
                interaction_loop(pt_sh, & wins, isConnected, pass_hash); // Interact with the user
                break;

            // Display an entry
            case HMI_CMD_SHOW_ENTRY:
                get_shared_cmd_1arg(pt_sh, nbInfo, ENTRY_NB_MAX_NB);    // Get the entry number
                get_shared_cmd_2arg(pt_sh, information, MAX_SIZE);      // Get the informatin field
                get_shared_cmd_3arg(pt_sh, secret, MAX_SIZE);           // Get the secret field
                displayAnEntry(wins.view_win, atoi(nbInfo), information, secret); // Display the entry
                delete_shared_cmd(pt_sh, 3);                            // Remove the command
                break;

            // Clear the window displaying entries
            case HMI_CMD_CLEAR_WINDOW:
                clear_view_window(wins.view_win);           // Clear all the window
                delete_shared_cmd(pt_sh, 0);                // Remove the command
                break;

            // Ask confirmation y/n
            case HMI_CMD_ASK_YN:
                get_shared_cmd_1arg(pt_sh, next_command, CMD_NB_MAX_NB);    // Get the next command
                get_shared_cmd_2arg(pt_sh, question, PROMPT_MAX_SIZE);      // Get the question
                getAString(wins.prompt_win, question, answer, 2, 1);        // Get the answer
                delete_shared_cmd(pt_sh, 2);                                // Remove the command
                add_shared_cmd_1arg(pt_sh, atoi(next_command), answer);     // Send the answer and the next command
                break;

            // Inform the user is connected or not
            case HMI_CMD_CONNECTED:
                delete_shared_cmd(pt_sh, 0);    // Remove the command
                isConnected = 1;                // User is now connected
                break;

            // Display an alert message
            case HMI_CMD_ALERT:
                get_shared_cmd_1arg(pt_sh, message, ALERT_MAX_SIZE);        // Get the message
                displayAnAlertMessage(wins.alert_win, message);             // Display the alert message
                delete_shared_cmd(pt_sh, 1);                                // Remove the command
                break;
        
            // Interface shutdown (normal)
            case HMI_CMD_EXIT:
                delete_shared_cmd(pt_sh, 0);                // Remove the command
                add_shared_cmd_0arg(pt_sh, CORE_CMD_EXIT);  // Request to stop CORE thread
                stop_curses(& wins);                        // End of the curses mode
                loop_again = 0;                             // End of the HMI thread
                break;

            // Stopping the application on error
            case HMI_CMD_ERROR:
                stop_curses(& wins);                                    // End of the curses mode
                get_shared_cmd_1arg(pt_sh, message, ALERT_MAX_SIZE);    // Get the message
                fprintf(stderr, "%s", message);                         // Display the error message
                delete_shared_cmd(pt_sh, 1);                            // Remove the command
                add_shared_cmd_hpriority(pt_sh, CORE_CMD_EXIT);         // Priority request to stop CORE thread
                loop_again = 0;                                         // End of the HMI thread
                break;

            default:
                break;
        }

    }

    return NULL;
}