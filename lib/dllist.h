#ifndef _DLLIST_H
#define _DLLIST_H

/*
 * A double-linked list
 *
 * Each Element contain a pointer on a data, a pointer to the
 * predecessor Element and a pointer to the next Element.
 * 
 * If the pointer to the predecessor Element is NULL, the current Element is the head
 * If the pointer to the next Element is NULL, the current Element is the last node
 */

// A node of the list that contains a pointer on a data,
// a pointer on the predecessor node and a pointer on next node
typedef struct Element {
    struct Element * prec;
    struct Element * next;
    void * pdata;
} Element;

// The double-linked list type
// An empty list is equal to NULL
typedef Element * DLList;

// Return 1 if the list is empty otherwise 0
int isEmpty_DLList(const Element * list);

// Create a new list
// A this state, the three pointers are NULL 
DLList new_DLList();

// Delete an entire list; each data is also deleted
void del_DLList(DLList *plist);

// Add a new node at the last position
// Return the modified list
DLList addAtLast_DLList(DLList list, void * pdata);

// Add a new node at the first position
// Return the modified list
DLList addAtFirst_DLList(DLList list, void * pdata);

// Delete a node and the inner data
// The second parameter is the position of the node (position 1 is the first node)
// Return the modified list
DLList del_Element_DLList(DLList list, int pos);

// Modify the inner data of a node
// The second parameter is the position of the node (position 1 is the first node)
// The last parameter is the new data (erase the old data)
DLList mod_Element_DLList(DLList list, int pos, void * pdata);

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