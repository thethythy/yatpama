#include <stdio.h>

#include "../lib/dllist.h"
#include "../app/yatpama.h"

int main(void)
{
    int error = 0;
    DLList list = NULL;

    fprintf(stdout, "\nAll the following tests must be OK:\n\n");

    // ----------------------------------
    // Test isEmpty_DLList and new_DLList

    error = isEmpty_DLList(list) == 0;

    if (error) {
        fprintf(stdout, "Test 1 isEmpty_DLList: \t\tKO\n");
    } else {
        fprintf(stdout, "Test 1 isEmpty_DLList: \t\tOK\n");
    }

    list = new_DLList();
    error = isEmpty_DLList(list) == 1 || list->next != NULL || list->prec != NULL;

    if (error) {
        fprintf(stdout, "Test 2 new_DLList: \t\tKO\n");
    } else {
        fprintf(stdout, "Test 2 new_DLList: \t\tOK\n");
    }

    // ----------------------------------
    // Test del_DLList

    del_DLList(&list);
    error = isEmpty_DLList(list) == 0 || list != NULL;

    if (error) {
        fprintf(stdout, "Test 3 del_DLList: \t\tKO\n");
    } else {
        fprintf(stdout, "Test 3 del_DLList: \t\tOK\n");
    }

    // ----------------------------------
    // Test addAtLast_DLList

    Entry * pentry1 = malloc(sizeof *pentry1);
    Entry * pentry2 = malloc(sizeof *pentry2);
    Entry * pentry3 = malloc(sizeof *pentry3);

    // Add a first node
    list = addAtLast_DLList(list, pentry1);

    error = list->prec != NULL || list->next != NULL;

    if (error) {
        fprintf(stdout, "Test 4 addAtLast_DLList: \tKO\n");
    } else {
        fprintf(stdout, "Test 4 addAtLast_DLList: \tOK\n");
    }

    // Add a second node
    list = addAtLast_DLList(list, pentry2);
    
    error = list->prec != NULL || list->next == NULL || list->next->next != NULL || list->next->prec != list;

    if (error) {
        fprintf(stdout, "Test 5 addAtLast_DLList: \tKO\n");
    } else {
        fprintf(stdout, "Test 5 addAtLast_DLList: \tOK\n");
    }

    // Add a third node
    list = addAtLast_DLList(list, pentry3);
    
    error = list->prec != NULL || list->next == NULL || list->next->next == NULL || list->next->next->next != NULL || list->next->prec != list;

    if (error) {
        fprintf(stdout, "Test 6 addAtLast_DLList: \tKO\n");
    } else {
        fprintf(stdout, "Test 6 addAtLast_DLList: \tOK\n");
    }

    // ----------------------------------
    // Test size_DLList

    error = size_DLList(list) != 3;

    if (error) {
        fprintf(stdout, "Test 7 size_DLList: \t\tKO\n");
    } else {
        fprintf(stdout, "Test 7 size_DLList: \t\tOK\n");
    }    

    // ----------------------------------
    // Test del_DLList

    del_DLList(&list);
    error = isEmpty_DLList(list) == 0 || list != NULL;

    if (error) {
        fprintf(stdout, "Test 8 del_DLList: \t\tKO\n");
    } else {
        fprintf(stdout, "Test 8 del_DLList: \t\tOK\n");
    }

    // ----------------------------------
    // Test del_Element_DLList

    // Try to delete at a wrong position
    pentry1 = malloc(sizeof *pentry1);
    list = addAtLast_DLList(NULL, pentry1); // Add a first node
    list = del_Element_DLList(list, 10); // Try to delete this node

    error = list == NULL || list->next != NULL || list->pdata == NULL;

    if (error) {
        fprintf(stdout, "Test 9 del_Element_DLList: \tKO\n");
    } else {
        fprintf(stdout, "Test 9 del_Element_DLList: \tOK\n");
    }

    list = del_Element_DLList(list, 0); // Try to delete this node

    error = list == NULL || list->next != NULL || list->pdata == NULL;

    if (error) {
        fprintf(stdout, "Test 10 del_Element_DLList: \tKO\n");
    } else {
        fprintf(stdout, "Test 10 del_Element_DLList: \tOK\n");
    }

    list = del_Element_DLList(list, -1); // Try to delete this node

    error = list == NULL || list->next != NULL || list->pdata == NULL;

    if (error) {
        fprintf(stdout, "Test 11 del_Element_DLList: \tKO\n");
    } else {
        fprintf(stdout, "Test 11 del_Element_DLList: \tOK\n");
    }

    // Delete at position 1 in list of length 1

    list = del_Element_DLList(list, 1); // Delete this node

    error = list != NULL;

    if (error) {
        fprintf(stdout, "Test 12 del_Element_DLList: \tKO\n");
    } else {
        fprintf(stdout, "Test 12 del_Element_DLList: \tOK\n");
    }

    // Delete at position 2 in list of length 2
    pentry1 = malloc(sizeof *pentry1);
    pentry2 = malloc(sizeof *pentry2);

    list = addAtLast_DLList(NULL, pentry1);
    list = addAtLast_DLList(list, pentry2);

    list = del_Element_DLList(list, 2); // Delete this node

    error = list == NULL || list->pdata != pentry1 || list->prec != NULL || list->next != NULL;

    if (error) {
        fprintf(stdout, "Test 13 del_Element_DLList: \tKO\n");
    } else {
        fprintf(stdout, "Test 13 del_Element_DLList: \tOK\n");
    }

    // Delete at position 2 in list of length 3

    pentry2 = malloc(sizeof *pentry2);
    pentry3 = malloc(sizeof *pentry3);

    list = addAtLast_DLList(list, pentry2);
    list = addAtLast_DLList(list, pentry3);

    list = del_Element_DLList(list, 2); // Delete the node at position 2

    error = list == NULL || list->pdata != pentry1 || list->next->pdata != pentry3 || list->next->next != NULL;

    if (error) {
        fprintf(stdout, "Test 14 del_Element_DLList: \tKO\n");
    } else {
        fprintf(stdout, "Test 14 del_Element_DLList: \tOK\n");
    }

    // Delete at position 1 in list of length 2    

    list = del_Element_DLList(list, 1); // Delete the node at position 1

    error = list == NULL || list->pdata != pentry3 || list->next != NULL || list->prec != NULL;

    if (error) {
        fprintf(stdout, "Test 15 del_Element_DLList: \tKO\n");
    } else {
        fprintf(stdout, "Test 15 del_Element_DLList: \tOK\n");
    }

    del_DLList(&list);

    // ----------------------------------
    // Test next_DLList

    DLList temp;

    // Next node of an empty list

    temp = next_DLList(list);

    error = temp != NULL;

    if (error) {
        fprintf(stdout, "Test 16 next_DLList: \t\tKO\n");
    } else {
        fprintf(stdout, "Test 16 next_DLList: \t\tOK\n");
    }

    // Next node of a list of length 1

    list = addAtLast_DLList(NULL, NULL);
    temp = next_DLList(list);

    error = temp != NULL;

    if (error) {
        fprintf(stdout, "Test 17 next_DLList: \t\tKO\n");
    } else {
        fprintf(stdout, "Test 17 next_DLList: \t\tOK\n");
    }

    // Next node of a list of length 2

    list = addAtLast_DLList(list, NULL);

    temp = next_DLList(list);

    error = temp == NULL || temp != list->next;

    if (error) {
        fprintf(stdout, "Test 18 next_DLList: \t\tKO\n");
    } else {
        fprintf(stdout, "Test 18 next_DLList: \t\tOK\n");
    }

    // ----------------------------------
    // Test prev_DLList

    // Prev node of a list of length 2

    temp = prev_DLList(list);

    error = temp != NULL;

    if (error) {
        fprintf(stdout, "Test 19 prev_DLList: \t\tKO\n");
    } else {
        fprintf(stdout, "Test 19 prev_DLList: \t\tOK\n");
    }

    // Prev node of the second position in a list of length 2

    temp = prev_DLList(list->next);

    error = temp != list;

    if (error) {
        fprintf(stdout, "Test 20 prev_DLList: \t\tKO\n");
    } else {
        fprintf(stdout, "Test 20 prev_DLList: \t\tOK\n");
    }

    // Prev node of an empty list

    del_DLList(&list);

    temp = prev_DLList(list);

    error = temp != NULL;

    if (error) {
        fprintf(stdout, "Test 21 prev_DLList: \t\tKO\n");
    } else {
        fprintf(stdout, "Test 21 prev_DLList: \t\tOK\n");
    }

    // ----------------------------------
    // Test size_DLList

    error = size_DLList(list) != 0;

    if (error) {
        fprintf(stdout, "Test 22 size_DLList: \t\tKO\n");
    } else {
        fprintf(stdout, "Test 22 size_DLList: \t\tOK\n");
    } 

    return error;
}