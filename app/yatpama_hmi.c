#include <curses.h>
#include <stdio.h>
#include <string.h>
#include <sys/param.h>

#include "yatpama_shared.h"
#include "../lib/utilities.h"

typedef struct UI_Windows {
    WINDOW * title_win;     // The title window at the top of the terminal
    WINDOW * commands_win;  // The command window after the title
    WINDOW * prompt_win;    // The prompt window just after the command window
    WINDOW * view_win;      // The main window for displaying entries
    WINDOW * alert_win;     // The alert window for displaying error messages and alerts
} UI_Windows ;

/*
 * Wait that the user chooses a valid command
 * Paramater 1: the prompt window
 */ 
char prompt(WINDOW * win) {
    char cmd;
    int again;

    do {
        wmove(win, 0, 0);
        wclrtoeol(win); // Clear line 

        mvwprintw(win, 0, 0, "Choose a command: "); // Display a prompt
        wrefresh(win);

        cmd = (char)wgetch(win);
        again = cmd != 'p' && cmd != 'l' && cmd != 'a' && cmd != 'q' &&
                cmd != 's' && cmd != 'd' && cmd != 'x' && cmd != 'i';

    } while (again);

    return cmd;
}

/*
 * Get a string of characters
 * Parameter 1: the window used to get the string
 * Parameter 2: the prompt message
 * Parameter 3: the string
 * Parameter 4: the max length of the string
 */
void getAPublicString(WINDOW * win, char * prompt, char * mesg, int size_max) {
    memset(mesg, 0, size_max);
    wmove(win, 0, 0);                   // Go to the beginning
    wclrtoeol(win);                     // Clear line
    wprintw(win, "%s", prompt);         // Display the prompt
    wgetnstr(win, mesg, size_max);    // Get the string
}

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
 * Main interaction loop
 * Parameter 1: a shared data record
 * Parameter 2: a record of pointers on windows
 */
void interaction_loop(T_Shared * pt_sh, UI_Windows * wins) {
    char command; // The current command

    command = prompt(wins->prompt_win); // Entering an order

    switch (command) {

        // Entering the password and generating the key
        case 'p':
            displayAnAlertMessage(wins->alert_win, "Enter password command");
            char msecret[PWD_MAX_SIZE]; // The password
            getAPublicString(wins->prompt_win, "Master password: ", msecret, PWD_MAX_SIZE);
            add_shared_cmd_1arg(pt_sh, CORE_CMD_KEY, msecret); // Request to create the key
            memset(msecret, 0, PWD_MAX_SIZE);
            break;

        // Displaying entries
        case 'l':
            clear_view_window(wins->view_win);
            displayAnAlertMessage(wins->alert_win, "Print list of entries");
            add_shared_cmd_0arg(pt_sh, CORE_CMD_PRINT); // Request for the list
            break;

        // Entries filtering
        case 's':
            clear_view_window(wins->view_win);
            displayAnAlertMessage(wins->alert_win, "Search entries following a pattern");
            char pattern[MAX_SIZE]; // The filtering pattern
            getAPublicString(wins->prompt_win, "Pattern: ", pattern, MAX_SIZE);
            add_shared_cmd_1arg(pt_sh, CORE_CMD_SEARCH, pattern); // Request for search
            break;

        // Adding a new entry
        case 'a':
            clear_view_window(wins->view_win);
            displayAnAlertMessage(wins->alert_win, "Add a new secret information");

            char information[MAX_SIZE];
            getAPublicString(wins->prompt_win, "Information: ", information, MAX_SIZE);
            
            char secret[MAX_SIZE];
            getAPublicString(wins->prompt_win, "Secret: ", secret, MAX_SIZE);
            
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
            getAPublicString(wins->prompt_win, "Give entry number: ", cNbEntry, ENTRY_NB_MAX_NB + 1); // Get the entry number to remove
            add_shared_cmd_1arg(pt_sh, CORE_CMD_DEL_P1, cNbEntry); // Request to get the entry concerned
            break;

        // Exportation of entries
        case 'x':
            clear_view_window(wins->view_win);
            displayAnAlertMessage(wins->alert_win, "Export entries");
            char file_export[MAXPATHLEN];
            getAPublicString(wins->prompt_win, "Give the name of the file to export to: ", file_export, MAXPATHLEN);
            add_shared_cmd_1arg(pt_sh, CORE_CMD_EXP, file_export); // Request to execute an exportation
            break;

        // Importation of entries
        case 'i':
            clear_view_window(wins->view_win);
            displayAnAlertMessage(wins->alert_win, "Import entries");
            char file_import[MAXPATHLEN];
            getAPublicString(wins->prompt_win, "Give the name of the file to import from: ", file_import, MAXPATHLEN);
            add_shared_cmd_1arg(pt_sh, CORE_CMD_IMP, file_import); // Request to execute an importation
            break;

        default:
            break;
    }
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
void display_alert_win(WINDOW * win) {
    int row, col;
    getmaxyx(win, row, col);                // get the number of rows and columns
    mvwhline(win, 0, 0, ACS_HLINE, col);    // draw a horizontal line at the bottom
    wrefresh(win);
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

    cbreak();   // Control characters ; Get a char or a string without CR or EOF
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
    display_alert_win(wins->alert_win);

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
 * HMI command management thread
 * Parameter 1: a data useful by the thread (a structure T_Shared)
 */
void * thread_hmi(void * t_arg) {
    T_Shared * pt_sh = t_arg; // The argument is a structure T_Shared
    UI_Windows wins; // Curses windows of the user interface

    char message[ALERT_MAX_SIZE];   // To store alert and error messages
    char reponse;                   // Store a response y/n
    char next_command[CMD_NB_MAX_NB]; // Store the next command (as a string)
    char question[PROMPT_MAX_SIZE]; // Store the prompt

    char nbInfo[ENTRY_NB_MAX_NB];   // Entry number as a string
    char information[MAX_SIZE];     // Information field of the entry
    char secret[MAX_SIZE];          // Secret field of the entry

    // Start and paramaterize the cursus mode then draw user interface
    if (start_paramaterize_curses(& wins) == -1) {
        add_shared_cmd_hpriority(pt_sh, CORE_CMD_EXIT); // Priority request to stop CORE thread
        return NULL;
    }

    int loop_again = 1;
    while(loop_again == 1) {
    
        int hmi_cmd = 0;

        // Reading a possible command
        hmi_cmd = get_shared_cmd(pt_sh);
    
        switch (hmi_cmd) {

            // Wait a new command
            case HMI_CMD_LOOP_INTER:
                delete_shared_cmd(pt_sh, 0);                // Delete the command
                interaction_loop(pt_sh, & wins);            // Interact with the user
                break;

            // Displaying an entry
            case HMI_CMD_SHOW_ENTRY:
                get_shared_cmd_1arg(pt_sh, nbInfo, ENTRY_NB_MAX_NB);    // Get the entry number
                get_shared_cmd_2arg(pt_sh, information, MAX_SIZE);      // Get the informatin field
                get_shared_cmd_3arg(pt_sh, secret, MAX_SIZE);           // Get the secret field
                displayAnEntry(wins.view_win, atoi(nbInfo), information, secret); // Display the entry
                delete_shared_cmd(pt_sh, 3);                            // Remove the command
                break;

            // Ask confirmation y/n
            case HMI_CMD_ASK_YN:
                get_shared_cmd_1arg(pt_sh, next_command, CMD_NB_MAX_NB);    // Get the next command
                get_shared_cmd_2arg(pt_sh, question, PROMPT_MAX_SIZE);      // Get the question
                getAPublicString(wins.prompt_win, question, &reponse, 2);   // Get the response
                delete_shared_cmd(pt_sh, 2);                                // Remove the command
                add_shared_cmd_1arg(pt_sh, atoi(next_command), &reponse);   // Sends the response and the next command
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