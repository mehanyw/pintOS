#ifndef VM_SWAP_H
#define VM_SWAP_H
/*
	Implementation of swap table, which will keep track of the swap space
	on the disk.
*/


#include <bitmap.h>

void swap_table_init(void);
int write_slot(void*);
void read_slot(size_t, void*);
void free_swap_slot(size_t);

#endif /* vm/swap.h */
