#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/time.h>

#include "../lib/utilities.h"

#include "yatpama_shared.h"
#include "yatpama_hmi.h"
#include "yatpama_core.h"

#define EXIT_ON_BRUTE_FORCE_ATTACK  1
#define EXIT_ON_SIGNAL_MASK_ERROR   2

/**
 * Exit on error: 
 * - show a message according an error code;
 * - update access time of the data file;
 * - exit the process
 */
void exit_on_error(int err_code) {
  switch (err_code) {
    case EXIT_ON_BRUTE_FORCE_ATTACK:
      fprintf(stderr, "Potential brute force attack detected! Wait %d seconds before retrying.\n", EXEC_INTERVAL_TIME);
      break;
  
    case EXIT_ON_SIGNAL_MASK_ERROR:
      fprintf(stderr, "Impossible to mask undesirable signals!\n");    
      break;

    default:
      break;
  }

  utimes(FILE_DATA_NAME, NULL); // Set access time
  exit(EXIT_FAILURE);
}

/**
 * Shield against brute force attack 
 * Compare the actual time and the access time of the data file
 * The difference must be inferior to EXEC_INTERVAL_TIME
 */
void brute_force_attack_shield() {

  // Get the access time of the data file
  struct stat file_stat;
  int error = stat(FILE_DATA_NAME, &file_stat);

  // Get the actual time and compare it with the last access
  if (error == 0) {
    struct timeval time;
      
    // The difference must be inferior to EXEC_INTERVAL_TIME (in seconds)
    if (gettimeofday(&time, NULL) == 0 && 
        (time.tv_sec - file_stat.st_atime) < EXEC_INTERVAL_TIME ) {
        exit_on_error(EXIT_ON_BRUTE_FORCE_ATTACK);
      }
  }

}

/**
 * Mask undesirable signals to control the application lifecycle
 */
void mask_signals() {
  sigset_t sig;       // Signals set
  sigemptyset(&sig);  // Empty the set

  // Add SIGINT SIGQUIT SIGTSTP SIGTERM signals
  sigaddset(&sig, SIGINT); 
  sigaddset(&sig, SIGQUIT);
  sigaddset(&sig, SIGTSTP);
  sigaddset(&sig, SIGTERM);
  
  // Mask signals for the current process and threads
  if (pthread_sigmask(SIG_BLOCK, &sig, NULL) != 0) {
    exit_on_error(EXIT_ON_SIGNAL_MASK_ERROR);
  }
}

int main(int argc, char * argv[]) {
  pthread_t t_core;
  pthread_t t_hmi;

  // Shared data structure between the two threads
  T_Shared sh = {
    .cmd_list = NULL,                       // List of commands
    .mut_list = PTHREAD_MUTEX_INITIALIZER,  // Semaphore to access to the list
    .synchro = PTHREAD_COND_INITIALIZER     // Sync to avoid looping on an empty list
  };

  // CORE thread-specific data structure
  T_Core core = {
    .t_sh = &sh,          // The shared structure of data
    .exec_name = argv[0]  // The name of the executable entered on the command line
  };

  // Brute force attack shield
  //#define __DEBUG__
  #ifndef __DEBUG__
  brute_force_attack_shield();
  #endif

  // Mask some signals
  mask_signals();

  // The first command: launch an interaction loop on the HMI side
  add_shared_cmd_0arg(&sh, HMI_CMD_LOOP_INTER);

  // Launching threads
  pthread_create(&t_core, NULL, thread_core, &core);
  pthread_create(&t_hmi, NULL, thread_hmi, &sh);

  // Waiting for threads to end
  pthread_join(t_hmi, NULL);
  pthread_join(t_core, NULL);

  del_DLList(& sh.cmd_list); // Delete the shared command list

  utimes(FILE_DATA_NAME, NULL); // Set access time (against brute force attack)

  return 0;
}
