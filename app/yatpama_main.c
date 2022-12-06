#include <string.h>

#include "yatpama_shared.h"
#include "yatpama_hmi.h"
#include "yatpama_core.h"

int main(int argc, char * argv[]) {
  pthread_t t_core;
  pthread_t t_hmi;

  // Structure de données partagée entre les deux threads
  T_Shared sh = {
    .cmd_list = NULL,                       // Liste des commandes
    .mut_list = PTHREAD_MUTEX_INITIALIZER,  // Sémaphore d'accès à la liste
    .synchro = PTHREAD_COND_INITIALIZER     // Synchro pour ne pas boucler sur une liste vide   
  };

  // Structure de données propre au thread CORE
  T_Core core = {
    .t_sh = &sh,          // La structure partagée
    .exec_name = argv[0]  // Le nom de l'exécutable saisie sur la ligne de commande
  };

  // La première commande : lancer une boucle d'interaction côté HMI
  add_shared_cmd_0arg(&sh, HMI_CMD_LOOP_INTER);

  // Lancement des threads
  pthread_create(&t_core, NULL, thread_core, &core);
  pthread_create(&t_hmi, NULL, thread_hmi, &sh);

  // Attente de la fin des threads
  pthread_join(t_hmi, NULL);
  pthread_join(t_core, NULL);

  del_DLList(& sh.cmd_list); // Suppresion de la liste des commandes

  return 0;
}
