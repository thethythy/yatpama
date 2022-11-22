#include <stdio.h>
#include <stdlib.h>

#include "dllist.h"

int isEmpty_DLList(DLList list) {
    return list == NULL ? 1 : 0;
}

DLList new_DLList() {
    DLList list;

    list = malloc(sizeof *list);
    if (list == NULL) {
        fprintf(stderr, "Impossible to allocate memory!\n");
        exit(1);
    }

    list->prec = list->next = NULL;
    list->pdata = NULL;

    return list;
}

void del_DLList(DLList * plist) {
    if (*plist != NULL) {
        DLList temp = (*plist)->next;
        if (temp != NULL) del_DLList(&temp);
        free((*plist)->pdata);
        free(*plist);
        *plist = NULL;
    }
}

DLList addAtLast_DLList(DLList list, void * pdata) {
    // If the list is empty
    if (list == NULL) {
        list = new_DLList();
        list->pdata = pdata;
    }
    else {
        // If the list contain only one node
        if (list->next == NULL) {
            DLList temp = new_DLList();
            temp->pdata = pdata;
            temp->prec = list;
            list->next = temp;
        } else {
            // The list has more than one node, go to the next node
            addAtLast_DLList(list->next, pdata);
        }
    }    

    return list;
}

DLList del_Element_DLList(DLList list, int pos) {
    if (list != NULL && pos > 0) {
        // If the list has only one element and we want to delete it
        if (pos == 1 && list->next == NULL) {
            del_DLList(&list);
        } else
            // If we want to delete the first node of a list of length > 1
            if (pos == 1 && list->next != NULL) {
                // Delete on place
                DLList temp = list->next;
                free(list->pdata);
                list->pdata = temp->pdata;
                list->next = temp->next;
                if (temp->next != NULL) temp->next->prec = list;
                free(temp);
            } else 
                // If we want delete a node at position > 1 of a list of length > 1
                if (pos > 1 && list->next != NULL) {
                    list->next = del_Element_DLList(list->next, pos-1);
                }
    }

    return list;
}

DLList next_DLList(DLList list) {
    return list == NULL ? NULL : list->next;
}

DLList prev_DLList(DLList list) {
    return list == NULL ? NULL : list->prec;
}

int size_DLList(DLList list) {
    if (list == NULL)
        return 0;
    else
        return 1 + size_DLList(list->next);
}
