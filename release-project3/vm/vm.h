#ifndef VM_VM_H
#define VM_VM_H
/*
	File for Supplemental Page Table Data Structure
	SPT will be a per-process data structure meaning
	it will be intilalized with the start up of every new process.
	The SPT will be a hash table which contains the data of each page
*/

#include <hash.h>
#include <debug.h>
#include "filesys/off_t.h"

struct spt_entry {

	void* 			frame;			/* Kernal VM which corresponds to frame */

	void* 			vaddr;			/* Virtual Address of Page */
	int 			vpn;			/* Virtual Page Number - Key in Hashmap*/

	bool 			valid;			/* Flag indicating valid address */
	bool 			present;		/* Flag indicating if page is resident in RAM */

	struct file* 	file;			/* File pointer if page bytes are in FS. DO I DO THIS OS MMAP??? */
	off_t 			file_offset;	/* File Offset */
	int32_t 		zeros;			/* Zeroes Present */
	bool 			writable;		/* IS THIS NEEDED OR CAN I USE THE EXCEPTION VARS */

	bool 			swap;
	int32_t 		swap_slot;		/* Flag if page is in swap */

	bool 			stack;

	struct hash_elem elem;			/* Hashmap element */
};

bool spt_init(struct hash* h);
unsigned spt_entry_hash(const struct hash_elem*, void* UNUSED);
bool spt_entry_comparator(const struct hash_elem*, const struct hash_elem*, void* UNUSED);
struct spt_entry* get_spt_entry(struct hash*,void*);

#endif /* vm/vm.h */
