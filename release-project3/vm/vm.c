/* File for Supplemental Page Table Data Structure
	SPT will be a per-process data structure meaning
	it will be intilalized with the start up of every new process.
	The SPT will be a hash table which contains the data of each page	

*/

#include "vm/vm.h"
#include "threads/vaddr.h"
#include "threads/thread.h"
#include <hash.h>
#include <debug.h>


/* Returns a hash of the SPT key: vaddr */
unsigned 
spt_entry_hash(const struct hash_elem* e, void* aux UNUSED){
	struct spt_entry* s = hash_entry(e,struct spt_entry,elem);
	return hash_int(s->vpn);
}

/* Note: Spt_enty comparator */
bool 
spt_entry_comparator(const struct hash_elem* a, const struct hash_elem* b, void* aux UNUSED){
	return hash_entry(a,struct spt_entry,elem)->vpn < hash_entry(b,struct spt_entry,elem)->vpn;
}

/* Intializes the SPT with the hash_init. hash_init calls malloc */ 
bool 
spt_init(struct hash* h){
	return hash_init(h,spt_entry_hash,spt_entry_comparator, NULL);
}

/* Returns a pointer to the SPT entry with corresponding address. Returns NULL if no element exists */
struct spt_entry* 
get_spt_entry(struct hash* spt, void* addr){
	struct spt_entry search;
	search.vpn = pg_no(addr);
	struct hash_elem* e = hash_find(spt, &search.elem);
	return e == NULL ? NULL: hash_entry(e, struct spt_entry, elem);
}





