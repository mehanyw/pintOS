
#include "vm/frame.h"
#include "vm/vm.h"
#include "vm/swap.h"
#include "userprog/pagedir.h"
#include <list.h>
#include "threads/vaddr.h"
#include "threads/palloc.h"
#include "threads/malloc.h"
#include "threads/synch.h"
#include "threads/thread.h"
#include <string.h>
#include <stdio.h>

/* Frame Table list and Lock */
static struct list frame_table;
static struct lock ft_lock;

/* The 'hand' in the clock algorithm */
static struct list_elem* k;

// When we are destroying a process, ->>> we have to free anything we malloced.

/* Know the SPTE. Pass it into the Frame allocator in order to be able to update it and know the upage.
   Which will be used for the pagedir_ access.
 */


static void* frame_evict(enum palloc_flags, struct spt_entry*);
static inline void increment_ft_iter (struct list_elem**);
static void print_list();

struct lock evict_lock;

/* Inits the list and grabs all the user-pool pages */
void frame_table_init(){
	list_init(&frame_table);
	lock_init(&ft_lock);
	lock_init(&evict_lock);
}

/* Returns a frame */
void*
frame_alloc(enum palloc_flags flags, struct spt_entry* new_spte){
	// if(lock_held_by_current_thread(&evict_lock))
	//      lock_release(&evict_lock);

	lock_acquire(&evict_lock);
	void* frame;

	//Eviction testing
	// if(list_size(&frame_table) >= 150){
	//  frame = frame_evict(flags, new_spte);
	//  lock_release(&evict_lock);
	//  return frame;
	// }

	if(flags & PAL_ZERO)
		frame = palloc_get_page(PAL_USER | PAL_ZERO);
	else
		frame = palloc_get_page(PAL_USER);

	if(frame != NULL) {
		/* Add ft_entry to frame table */
		struct ft_entry* e = malloc(sizeof(struct ft_entry));
		e->frame = frame;
		e->owner = thread_current();
		e->spte = new_spte;

		lock_acquire(&ft_lock);
		list_push_back(&frame_table,&e->elem);
		lock_release(&ft_lock);
		lock_release(&evict_lock);
		return frame;
	}
	frame = frame_evict(flags, new_spte);
	lock_release(&evict_lock);
	return frame;
}

/* Returns an evicted frame. Writes old data to swap slot, and updates old thread's SPT and PT*/
static void*
frame_evict(enum palloc_flags flags, struct spt_entry* new_spte) {

	if(k == NULL) {
		k = list_begin(&frame_table);
	}

	struct list_elem* iter = k;
	struct list_elem* end = k == list_begin(&frame_table) ? list_prev(list_end(&frame_table)) : list_prev(iter);

	//printf("EVICTION TIME:\n");
	//print_list();
	//printf("**************************************\n");
	while(iter != end) {
		struct ft_entry* f_entry = list_entry(iter, struct ft_entry, elem);
		struct spt_entry* s_entry = f_entry->spte;

		if(!pagedir_is_accessed(f_entry->owner->pagedir, s_entry->vaddr)) {

			/*if(!pagedir_is_dirty(f_entry->owner->pagedir, s_entry->vaddr) && !s_entry->stack && s_entry->file != NULL){
			        //No need to write to swap
			        pagedir_clear_page(f_entry->owner->pagedir, s_entry->vaddr);
			        s_entry->present = false;
			        f_entry->owner = thread_current();
			        f_entry->spte = new_spte;
			        increment_ft_iter(&k);
			        if(flags & PAL_ZERO)
			                memset(f_entry->frame, 0, PGSIZE);
			        return f_entry->frame;
			   }*/

			//Write data to swap
			int slot_index = write_slot(f_entry->frame);
			s_entry->present = false;
			s_entry->swap = true;
			s_entry->swap_slot = slot_index;
			s_entry->file = NULL;
			pagedir_clear_page(f_entry->owner->pagedir, s_entry->vaddr);
			f_entry->owner = thread_current();
			f_entry->spte = new_spte;
			increment_ft_iter(&k);
			if(flags & PAL_ZERO)
				memset(f_entry->frame, 0, PGSIZE);
			return f_entry->frame;
		}

		pagedir_set_accessed(f_entry->owner->pagedir, s_entry->vaddr, false);

		iter = list_next(iter);
		if(iter == list_end(&frame_table))
			iter = list_begin(&frame_table);
	}


	struct ft_entry* f_entry = list_entry(k, struct ft_entry, elem);
	struct spt_entry* s_entry = f_entry->spte;
	/*if(!pagedir_is_dirty(f_entry->owner->pagedir, s_entry->vaddr) && !s_entry->stack  && s_entry->file != NULL){
	        pagedir_clear_page(f_entry->owner->pagedir, s_entry->vaddr);
	        s_entry->present = false;
	        f_entry->owner = thread_current();
	        f_entry->spte = new_spte;
	        increment_ft_iter(&k);
	        if(flags & PAL_ZERO)
	                memset(f_entry->frame, 0, PGSIZE);
	        return f_entry->frame;
	   }*/

	//Write data to swap
	int slot_index = write_slot(f_entry->frame);
	s_entry->present = false;
	s_entry->swap = true;
	s_entry->swap_slot = slot_index;
	s_entry->file = NULL;
	pagedir_clear_page(f_entry->owner->pagedir, s_entry->vaddr);
	f_entry->owner = thread_current();
	f_entry->spte = new_spte;
	increment_ft_iter(&k);
	if(flags & PAL_ZERO)
		memset(f_entry->frame, 0, PGSIZE);
	return f_entry->frame;

}


void free_dying_thread_frames(struct thread* dying){
	//print_list();
	struct list_elem* iter = list_begin(&frame_table);
	for(; iter != list_end(&frame_table); iter = list_next(iter)) {
		struct ft_entry* f = list_entry(iter, struct ft_entry, elem);
		struct spt_entry* s = f->spte;
		if(f->owner == dying) {
			lock_acquire(&ft_lock);
			palloc_free_page(f->frame);
			pagedir_clear_page(f->owner->pagedir, s->vaddr);
			list_remove(iter);
			lock_release(&ft_lock);
			if(s->swap) {
				free_swap_slot(s->swap_slot);
			}
		}
	}

	//printf("AFTER\n");
	//	print_list();
}


static inline void
increment_ft_iter (struct list_elem** k){
	*k = list_next(*k);
	if(*k == NULL || *k == list_end(&frame_table))
		*k = list_next(list_begin(&frame_table));
}

static void
print_list(){
	struct list_elem* iter = list_head(&frame_table);
	for(; iter != list_end(&frame_table); iter = list_next(iter)) {
		struct ft_entry* f = list_entry(iter, struct ft_entry, elem);
		printf("ft_entry: %p \t thread: %p\n", f->frame, f->owner);
	}
}
