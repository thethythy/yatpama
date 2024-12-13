#include <curses.h>
#include <stdio.h>
#include <string.h>
#include <sys/param.h>
#include <time.h>
#include <unistd.h>

#include "yatpama_shared.h"
#include "../lib/sha256.h"
#include "../lib/utilities.h"

static T_Shared * pt_sh;    // Global variable on the shared record 

#define KEY_DEL 127     // DEL key
#define KEY_SPACE 32    // Space key

typedef struct UI_Windows {
    WINDOW * title_win;     // The title window at the top of the terminal
    WINDOW * commands_win;  // The command window after the title
    WINDOW * prompt_win;    // The prompt window just after the command window
    WINDOW * view_win;      // The main window for displaying entries
    WINDOW * alert_win;     // The alert window for displaying error messages and alerts
} UI_Windows ;

#define T_W_H   3           // Title window height
#define C_W_H   3           // Command window height
#define P_W_H   2           // Prompt window height
#define A_W_H   2           // Alert window height

#define MIN_LENGTH 67       // Minimum length
#define MIN_HEIGHT 17       // Minimum height

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
    int col = getmaxx(win);   // Get the number of rows and columns

    wattron(win, A_BOLD);
    wmove(win, 0, (col - 52) / 2);
    wprintw(win, "                ___    __");
    wmove(win, 1, (col - 52) / 2);       
    wprintw(win, "\\ /   /\\         |    |__|  /\\        |\\/|    /\\");
    wmove(win, 2, (col - 52) / 2);
    wprintw(win, " |et /  \\nother  |iny |    /  \\ssword |  |an /  \\ger");
    wattroff(win, A_BOLD);
   
    wrefresh(win);
}

/*
 * Draw the command-list window
 * Parameter 1: the command-list window pointer
 */
void display_command_window(WINDOW * win) {
    int row, col;
    getmaxyx(win, row, col);   // Get the number of rows and columns
    char mesg[] = " [a]dd [d]el [e]dit [i]mport [l]ist [p]wd [q]uit [s]earch e[x]port ";
    
    wattron(win, A_REVERSE);
    mvwprintw(win, row - 2, (col - strlen(mesg)) / 2, "%s", mesg);
    wattroff(win, A_REVERSE);

    wrefresh(win);
}

/* 
 * Display the prompt window
 * Parameter 1: the prompt window pointer
 */
void display_prompt_window(WINDOW * win) {
    int row, col;
    getmaxyx(win, row, col);                    // get the number of rows and columns
    mvwhline(win, row - 1, 0, ACS_S3, col);  // draw a horizontal line at the top
    wrefresh(win);
}

/* 
 * Display the alert window
 * Parameter 1: the alert window pointer
 */
void display_alert_window(WINDOW * win) {
    int col = getmaxx(win);             // get the number of rows and columns
    mvwhline(win, 0, 0, ACS_S9, col);   // draw a horizontal line at the bottom
    wrefresh(win);
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
 * Resize the human-machine interface 
 * Parameter 1: record of the window pointers
 * Return value: 0 if OK -1 if KO
 */
int resize_hmi(UI_Windows * wins) {
    // Verify the terminal size
    if (COLS < MIN_LENGTH || LINES < MIN_HEIGHT) {
        char message[ALERT_MAX_SIZE];
        sprintf(message, "The new terminal size (%dx%d) is too small for Yatpama (%dx%d)!...\n", COLS, LINES, MIN_LENGTH, MIN_HEIGHT);
        add_shared_cmd_1arg(pt_sh, HMI_CMD_ERROR, message);
        return -1; 
    }

    // Clear, resize then re-draw the title window
    werase(wins->title_win);
    wresize(wins->title_win, T_W_H, COLS);
    display_title_window(wins->title_win);

    // Clear, resize then re-draw the command list window
    werase(wins->commands_win);
    wresize(wins->commands_win, C_W_H, COLS);
    display_command_window(wins->commands_win);

    // Resize then re-draw the prompt window
    wresize(wins->prompt_win, P_W_H, COLS);
    display_prompt_window(wins->prompt_win);

    // Resize then clear the window of the list of entries
    int view_win_height = LINES - T_W_H - C_W_H - P_W_H - A_W_H;
    wresize(wins->view_win, view_win_height, COLS);
    clear_view_window(wins->view_win);

    // Resize then re-draw the window for displaying alert messages
    wresize(wins->alert_win, A_W_H, COLS);
    mvwin(wins->alert_win, T_W_H + C_W_H + P_W_H + view_win_height, 0);
    display_alert_window(wins->alert_win);

    return 0;
}

/*
 * Start and paramaterize the curses mode then draw user interface
 * Parameter 1: record of the window pointers
 * Return value: 0 if OK -1 if KO
 */
int start_paramaterize_curses(UI_Windows * wins) {
    initscr();  // Start the curses mode

    // Verify the terminal size
    if (COLS < MIN_LENGTH || LINES < MIN_HEIGHT) {
        endwin(); // Stop the curses mode now !
        fprintf(stderr, "The current terminal size (%dx%d) is too small to start Yatpama (%dx%d)!...\n", COLS, LINES, MIN_LENGTH, MIN_HEIGHT);
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
 * Get a string of characters
 * Parameter 1: the window used to get the string
 * Parameter 2: the prompt message
 * Parameter 3: the string
 * Parameter 4: the max length of the string
 * Parameter 5: a flag to indicate a secret (0) or a public (> 0) string
 * Return value: 0 if OK; -1 if KO
 */
int getAString(UI_Windows * wins, char * prompt, char * mesg, int size_max, int flag) {
    WINDOW * win = wins->prompt_win;
    
    memset(mesg, 0, size_max);
    wmove(win, 0, 0);                   // Go to the beginning
    wclrtoeol(win);                     // Clear line
    wprintw(win, "%s", prompt);         // Display the prompt

    int ch, x, xinit, y, again = 0, len = 0;
    int isCharExtented = 0; // Extended char encoding flag
    getyx(win, y, x); // Get cursor initial position
    xinit = x;

    struct timespec delay;
    delay.tv_sec = 0;
    delay.tv_nsec = 250000000; // Period before masking the previous char

    do {
        if (flag == 0) noecho();
        do {
            wtimeout(win, 1000);  // Set blocking read for 1 second
            ch = wgetch(win);     // Wait 1 second a character

            // The terminal size has changed ?
            if (ch == KEY_RESIZE) {
                if (resize_hmi(wins) == -1) return -1;
                wmove(win, y, x); wrefresh(win); // Replace the cursor at its position
                ch = ERR;
            }
        } while (ch == ERR);
        wtimeout(win, -1);        // Return to normal behaviour for getch
        if (flag == 0) echo();

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
                wclrtoeol(win);
                wrefresh(win);
            }
        }

        // A normal key (to mask after a delay if it's a secret string)
        else {

            again = (char)ch != '\n' && len < size_max - 1;

            // Add the key in the message string
            if (again) {
                *mesg++ = (char)ch;
                len++;
            }

            if (flag == 0) {
                // You're editing a secret string
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
            } else {
                x++;
            }

        }

    } while (again);

    *mesg = '\0';

    return 0;
}

/**
 * Display a flag to indicate is user is signed in or out
 * Parameter 1: the window where displaying
 * Parameter 2: a flag to indicate if user is signed in
 */
void displayIsSignedIn(WINDOW * win, int isSignedIn) {
    wmove(win, 1, 0);
    waddstr(win, "<");
    if (!isSignedIn) {
        wattron(win, A_BLINK);
        waddch(win, ACS_NEQUAL);
        wattroff(win, A_BLINK);
    } else {
        waddch(win, ACS_DIAMOND);
    }
    waddstr(win, ">");
    waddch(win, ACS_VLINE);
    wrefresh(win);
}

/*
 * Display an alert or a useful information
 * Parameter 1: the window where displaying
 * Parameter 2: the message to display
 * Parameter 3: a flag to indicate if user is signed in
 */
void displayAnAlertMessage(WINDOW * win, char * message, int isSignedIn) {
    displayIsSignedIn(win, isSignedIn);

    wmove(win, 1, 4);
    wclrtoeol(win); // Clear line
    wattron(win, A_DIM | A_ITALIC);
    wprintw(win, "%s", message);
    wrefresh(win);
    wattroff(win, A_DIM | A_ITALIC);
}

/*
 * Display an entry
 * Parameter 1: the window for displaying the entry
 * Parameter 2: the number of the entry
 * Parameter 3: the field information of the entry
 * Parameter 4: the field secret of the entry
 * Parameter 5: the user is signed in or out
 * Return value: 0 if OK -1 if KO
 */
int displayAnEntry(UI_Windows * wins, int nbInfo, char * information, char * secret, int isSignedIn) {
    int row, col, y, x;
    WINDOW * win = wins->view_win;

    getmaxyx(win, row, col);    // Get the number of rows and columns
    getyx(win, y, x);           // Get the current position

    if (y > row - 4) {
        int ch;
        displayAnAlertMessage(wins->alert_win, "Enter any key before displaying next entries", isSignedIn);
        do {
            wtimeout(win, 1000);  // Set blocking read for 1 second
            ch = wgetch(win);     // Wait 1 second a character

            // The terminal size has changed ?
            if (ch == KEY_RESIZE) {
                if (resize_hmi(wins) == -1) return -1;
                wmove(wins->alert_win, 1, 45); wrefresh(wins->alert_win); // Replace the cursor at its position
                ch = ERR;
            }
        } while (ch == ERR);
        wtimeout(win, -1);        // Return to normal behaviour for getch
        displayAnAlertMessage(wins->alert_win, "", isSignedIn); // Erase current alert message
    }

    wprintw(win, "Entry n°%i:", nbInfo);
    wprintw(win, "\n Information: ");
    wprintw(win, "\t%s", information);
    wprintw(win, "\n Secret: ");
    wprintw(win, "\t%s\n", secret);
    wrefresh(win);

    return 0;
}

/*
 * Edit an entry
 * Parameter 1: the window used to get the strings
 * Parameter 2: the next command for the core thread
*/
void editAnEntry(UI_Windows * wins, int next_core_command) {
    char information[MAX_SIZE];
    int error = getAString(wins, "Information: ", information, MAX_SIZE, 1);
    
    if (error == 0) {
        char secret[MAX_SIZE];
        error = getAString(wins, "Secret: ", secret, MAX_SIZE, 1);
    
        if (error == 0) {
            // Send a request to the core thread
            add_shared_cmd_2arg(pt_sh, next_core_command, information, secret);
        }

        memset(secret, 0, MAX_SIZE);
    }
    memset(information, 0, MAX_SIZE);
}

/*
 * Lock the terminal and wait the user password to unlock it 
 * Paramater 1: record of the window pointers
 * Parameter 2: the password hash
 * Return value: 0 if OK -1 if KO
 */
int lock_hmi(UI_Windows * wins, BYTE * pass_hash) {
    char msecret[PWD_MAX_SIZE]; // The password
    BYTE hash[32]; // The hash to control

    do {

        // Clear the screen and wait for a keystroke
        erase(); refresh(); curs_set(0);
        timeout(1000);
        int key, code = 0;
        do {
            mvprintw((int)(LINES / 2), (int)(COLS / 2 - MIN_HEIGHT), "Hit a key to unlock the screen");
            key = getch();
            if (key == KEY_RESIZE) { // Remember the size has changed
                erase(); refresh();
                code = key;
                key = ERR;
            }
        } while (key == ERR);
        timeout(-1);
        erase(); refresh(); curs_set(1);

        // Re-draw the HMI because the size has changed?
        if (code == KEY_RESIZE) {
           if (resize_hmi(wins) == -1) return -1;
        } 
            
        // Get the password then control it
        code = getAString(wins, "Master password: ", msecret, PWD_MAX_SIZE, 0);
        if (code == 0)
            sha256((BYTE *)msecret, strlen(msecret), hash);
        else
            return -1;

    } while (1 != compare(hash, 32, pass_hash, 32));

    return resize_hmi(wins);
}

/*
 * Wait that the user chooses a valid command
 * After a timeout, lock the terminal
 * Paramater 1: record of the window pointers
 * Parameter 2: flag that indicates if user is signed in
 * Parameter 3: the password hash
 */ 
char getAValidCommand(UI_Windows * wins, int isSignedIn, BYTE * pass_hash) {
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

        // Ready to lock the terminal (user must be signed in) ?
        if (key == ERR && isSignedIn) {
            timer = timer - 1000; // One second elapsed
            if (timer == 0) {
                // Lock because timer == zero
                if (lock_hmi(wins, pass_hash) == -1) return 'k';
                timer = TIMEOUT_LOCK * 1000; // Reset timer
            }
        } else
            // The size screen has changed ?
            if (key == KEY_RESIZE) {
                if (resize_hmi(wins) == -1) return 'k';
        } else {
            cmd = (char)key;
            again = cmd != 'a' && cmd != 'd' && cmd != 'e' && cmd != 'i' && 
                    cmd != 'l' && cmd != 'p' && cmd != 'q' && cmd != 's' && 
                    cmd != 'x' ;
        }

    } while (again);

    return cmd;
}

/*
 * Main interaction loop
 * Parameter 1: a shared data record
 * Parameter 2: a record of pointers on windows
 * Parameter 3: a flag to indicate if the user is signed in
 * Parameter 4: the user password hash
 */
void interaction_loop(T_Shared * pt_sh, UI_Windows * wins, int isSignedIn, BYTE * pass_hash) {
    char command; // The current command
    char cNbEntry[ENTRY_NB_MAX_NB + 1]; // Number entry as a string of characters
    int error;

    command = getAValidCommand(wins, isSignedIn, pass_hash); // Wait an order

    switch (command) {

        // Add a new entry
        case 'a':
            clear_view_window(wins->view_win);
            displayAnAlertMessage(wins->alert_win, "Add a new secret information", isSignedIn);
            editAnEntry(wins, CORE_CMD_ADD);
            break;

        // Removing an entry
        case 'd':
            clear_view_window(wins->view_win);
            displayAnAlertMessage(wins->alert_win, "Delete an entry", isSignedIn);
            error = getAString(wins, "Give entry number: ", cNbEntry, ENTRY_NB_MAX_NB + 1, 1); // Get the entry number to remove
            if (error == 0) add_shared_cmd_1arg(pt_sh, CORE_CMD_DEL_P1, cNbEntry); // Request to get the entry concerned
            break;

        // Editing an entry
        case 'e':
            clear_view_window(wins->view_win);
            displayAnAlertMessage(wins->alert_win, "Edit an entry", isSignedIn);
            error = getAString(wins, "Give entry number: ", cNbEntry, ENTRY_NB_MAX_NB + 1, 1); // Get the entry number to edit
            if (error == 0) add_shared_cmd_1arg(pt_sh, CORE_CMD_EDT_P1, cNbEntry); // Request to get the entry concerned
            break;

        // Importation of entries
        case 'i':
            clear_view_window(wins->view_win);
            displayAnAlertMessage(wins->alert_win, "Import entries", isSignedIn);
            char file_import[MAXPATHLEN];
            error = getAString(wins, "Give the name of the file to import from: ", file_import, MAXPATHLEN, 1);
            if (error == 0) add_shared_cmd_1arg(pt_sh, CORE_CMD_IMP, file_import); // Request to execute an importation
            break;

        // Displaying entries
        case 'l':
            clear_view_window(wins->view_win);
            displayAnAlertMessage(wins->alert_win, "Print list of entries", isSignedIn);
            add_shared_cmd_0arg(pt_sh, CORE_CMD_PRINT); // Request for the list
            break;

        // Enter the password and generate the key
        case 'p':
            displayAnAlertMessage(wins->alert_win, "Enter a password", isSignedIn);
            char msecret[PWD_MAX_SIZE]; // The password
            
            // Get the user password
            error = getAString(wins, "Master password: ", msecret, PWD_MAX_SIZE, 0);
            if (error == 0) {
                add_shared_cmd_1arg(pt_sh, CORE_CMD_KEY, msecret); // Request to create the key
                sha256((BYTE *)msecret, strlen(msecret), pass_hash); // Generate a fingerprint of the password            
                memset(msecret, 0, PWD_MAX_SIZE);
            }
            break;

        // Normal shutdown
        case 'q':
            add_shared_cmd_0arg(pt_sh, HMI_CMD_EXIT); // End of user interface
            break;
        
        // Filtering entries
        case 's':
            clear_view_window(wins->view_win);
            displayAnAlertMessage(wins->alert_win, "Search entries following a pattern", isSignedIn);
            char pattern[MAX_SIZE]; // The filtering pattern
            error = getAString(wins, "Pattern: ", pattern, MAX_SIZE, 1);
            if (error == 0) add_shared_cmd_1arg(pt_sh, CORE_CMD_SEARCH, pattern); // Request for search
            break;

        // Exportation of entries
        case 'x':
            clear_view_window(wins->view_win);
            displayAnAlertMessage(wins->alert_win, "Export entries", isSignedIn);
            char file_export[MAXPATHLEN];
            error = getAString(wins, "Give the name of the file to export to: ", file_export, MAXPATHLEN, 1);
            if (error == 0) add_shared_cmd_1arg(pt_sh, CORE_CMD_EXP, file_export); // Request to execute an exportation
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
    pt_sh = t_arg; // The argument is a structure T_Shared
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
    displayIsSignedIn(wins.alert_win, 0);

    BYTE pass_hash[32];    // The password hash (sha256)
    int isSignedIn = 0;    // Flag to know if user is signed in or out

    int loop_again = 1;
    while(loop_again == 1) {
    
        int hmi_cmd = 0;
        int error;

        // Read a command
        hmi_cmd = get_shared_cmd(pt_sh);
    
        switch (hmi_cmd) {

            // Wait a new command
            case HMI_CMD_LOOP_INTER:
                delete_shared_cmd(pt_sh, 0); // Delete the command
                interaction_loop(pt_sh, & wins, isSignedIn, pass_hash); // Interact with the user
                break;

            // Display an entry
            case HMI_CMD_SHOW_ENTRY:
                get_shared_cmd_1arg(pt_sh, nbInfo, ENTRY_NB_MAX_NB);    // Get the entry number
                get_shared_cmd_2arg(pt_sh, information, MAX_SIZE);      // Get the informatin field
                get_shared_cmd_3arg(pt_sh, secret, MAX_SIZE);           // Get the secret field
                delete_shared_cmd(pt_sh, 3);                            // Remove the command
                displayAnEntry(&wins, atoi(nbInfo), information, secret, isSignedIn); // Display the entry
                break;

            // Clear the window displaying entries
            case HMI_CMD_CLEAR_WINDOW:
                clear_view_window(wins.view_win);   // Clear the window of the entries
                delete_shared_cmd(pt_sh, 0);        // Remove the command
                break;

            // Ask confirmation y/n
            case HMI_CMD_ASK_YN:
                get_shared_cmd_1arg(pt_sh, next_command, CMD_NB_MAX_NB);    // Get the next command
                get_shared_cmd_2arg(pt_sh, question, PROMPT_MAX_SIZE);      // Get the question
                delete_shared_cmd(pt_sh, 2);                                // Remove the command
                error = getAString(&wins, question, answer, 2, 1);          // Get the answer
                if (error == 0) add_shared_cmd_1arg(pt_sh, atoi(next_command), answer);     // Send the answer and the next command
                break;

            // Inform the user is signed in
            case HMI_CMD_SIGNEDIN:
                delete_shared_cmd(pt_sh, 0);    // Remove the command
                isSignedIn = 1;                // User is now signed in
                displayIsSignedIn(wins.alert_win, 1); // Display a flag
                break;

            // Display an alert message
            case HMI_CMD_ALERT:
                get_shared_cmd_1arg(pt_sh, message, ALERT_MAX_SIZE);        // Get the message
                displayAnAlertMessage(wins.alert_win, message, isSignedIn); // Display the alert message
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

            // Edit an existing entry
            case HMI_CMD_EDIT_ENTRY:
                delete_shared_cmd(pt_sh, 0);            // Remove the command
                editAnEntry(& wins, CORE_CMD_EDT_P2);   // Edit an entry then send it
                break;

            default:
                break;
        }

    }

    return NULL;
}