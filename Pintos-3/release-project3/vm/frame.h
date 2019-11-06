#ifndef VM_FRAME_H
#define VM_FRAME_H

#include <list.h>
#include "threads/palloc.h"
#include "threads/thread.h"

struct ft_entry {

	void* 				frame;			/* Address of the frame */
	struct thread* 		owner;			/* Reference to the owning thread of the frame */
	struct spt_entry* 	spte;			/* SPTE corresponding page */

	struct list_elem 	elem;
};


void frame_table_init(void);
void* frame_alloc(enum palloc_flags, struct spt_entry*);
void free_dying_thread_frames(struct thread*);


#endif /* vm/frame.h */
