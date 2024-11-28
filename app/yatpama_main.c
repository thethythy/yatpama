#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/time.h>

#include "../lib/utilities.h"

#include "yatpama_shared.h"
#include "yatpama_hmi.h"
#include "yatpama_core.h"

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
        utimes(FILE_DATA_NAME, NULL); // Set access time
        fprintf(stderr, "Potential brute force attack detected! Wait %d seconds before retrying.\n", EXEC_INTERVAL_TIME);
        exit(EXIT_FAILURE);
      }
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
  brute_force_attack_shield();

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
