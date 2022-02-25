#ifndef _DLLIST_H
#define _DLLIST_H

#include "../yatpama.h"

/*
 * A double-linked list
 *
 * Each element contain a pointer on a structure Entry, a pointer to the
 * predecessor Element and a pointer to the next Element.
 * 
 * If the pointer to the predecessor Element is NULL, the current Element is the head
 * If the pointer to the next Element is NULL, the current Element is the last node
 */

// A node of the list that contains a pointer on a structure Entry,
// a pointer on the predecessor node and a pointer on next node
typedef struct Element {
    struct Element * prec;
    struct Element * next;
    Entry * entry;
} Element;

// The double-linked list type
// An empty list is equal to NULL
typedef Element * DLList;

// Return 1 if the list is empty otherwise 0
int isEmpty_DLList(DLList list);

// Create a new list
// A this state, the three pointers are NULL 
DLList new_DLList();

// Delete an entire list; each pointed Entry is also deleted
void del_DLList(DLList *plist);

// Add a new node at the last position
// Return the modified list
DLList addAtLast_DLList(DLList list, Entry * pentry);

// Delete a node and the pointed Entry
// The second parameter is the position of the node (position 1 is the first node)
// Return the modified list
DLList del_Element_DLList(DLList list, int pos);

// Return the next node of the list
// Return NULL if the list is empty or if there is no next node
DLList next_DLList(DLList list);

// Return the previous node of the list
// Return NULL if the list is empty or if there is no previous node
DLList prev_DLList(DLList list);

// Get the size of the list
// Count the number of node
int size_DLList(DLList list);

#endif