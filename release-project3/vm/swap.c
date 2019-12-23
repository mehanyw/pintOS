#include "vm/swap.h"
#include <bitmap.h>
#include "threads/synch.h"
#include "devices/block.h"
#include <stdio.h>

static struct bitmap* swap_table;
static struct lock swap_table_lock;
static struct block* swap_block;

static size_t search_open_slot();

void
swap_table_init(){
	swap_block = block_get_role(BLOCK_SWAP);
	swap_table = bitmap_create(block_size(swap_block)/8);
	lock_init(&swap_table_lock);
}

/* Searches for an open slot and writes a page to it, returns the slot index */
int
write_slot(void* page){
	size_t slot = search_open_slot();
	if(slot == BITMAP_ERROR) {                                  //Panic the kernel if no more swap space.
		//printf("OVERFLOW OF SWAP!");
		exit(-1);
	}
	size_t sector = slot * 8;
	int i=0;
	for(; i<8; i++)
		block_write(swap_block, sector+i, page+(i*512));
	return slot;
}

/* Reads a swap slot into a page & frees the slot in the swap table bitmap */
void
read_slot(size_t swap_slot, void* page){
	size_t sector = swap_slot * 8;
	int i=0;
	for(; i<8; i++)
		block_read(swap_block, sector+i, page+(i*512));
	free_swap_slot(swap_slot);
}

/* Returns the index of the first open slot in the swap table & sets to true */
static size_t
search_open_slot(){
	lock_acquire(&swap_table_lock);
	size_t retVal = bitmap_scan_and_flip(swap_table, 0, 1, false);
	lock_release(&swap_table_lock);
	return retVal != BITMAP_ERROR ? retVal : BITMAP_ERROR;
}

void
free_swap_slot(size_t swap_slot){
	lock_acquire(&swap_table_lock);
	bitmap_set(swap_table, swap_slot, false);
	lock_release(&swap_table_lock);
}
