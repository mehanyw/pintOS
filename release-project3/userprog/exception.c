#include "userprog/exception.h"
#include <inttypes.h>
#include <stdio.h>
#include "userprog/gdt.h"
#include "threads/interrupt.h"
#include "threads/thread.h"

/*For syscall exit*/
#include <lib/user/syscall.h> 
#include "threads/vaddr.h"

#include "vm/vm.h"
#include "vm/swap.h"
#include "vm/frame.h"
#include "threads/vaddr.h"

#include "threads/thread.h"
#include <stddef.h>
#include <string.h>
#include "threads/palloc.h"
#include "threads/malloc.h"
#include "process.h"
#include "filesys/filesys.h"
#include "filesys/file.h"

#define MIN_STACK_VADDR PHYS_BASE - 0x800000 

/* Number of page faults processed. */
static long long page_fault_cnt;

static void kill (struct intr_frame *);
static void page_fault (struct intr_frame *);

/* Registers handlers for interrupts that can be caused by user
   programs.

   In a real Unix-like OS, most of these interrupts would be
   passed along to the user process in the form of signals, as
   described in [SV-386] 3-24 and 3-25, but we don't implement
   signals.  Instead, we'll make them simply kill the user
   process.

   Page faults are an exception.  Here they are treated the same
   way as other exceptions, but this will need to change to
   implement virtual memory.

   Refer to [IA32-v3a] section 5.15 "Exception and Interrupt
   Reference" for a description of each of these exceptions. */
void
exception_init (void)
{
  /* These exceptions can be raised explicitly by a user program,
     e.g. via the INT, INT3, INTO, and BOUND instructions.  Thus,
     we set DPL==3, meaning that user programs are allowed to
     invoke them via these instructions. */
  intr_register_int (3, 3, INTR_ON, kill, "#BP Breakpoint Exception");
  intr_register_int (4, 3, INTR_ON, kill, "#OF Overflow Exception");
  intr_register_int (5, 3, INTR_ON, kill,
                     "#BR BOUND Range Exceeded Exception");

  /* These exceptions have DPL==0, preventing user processes from
     invoking them via the INT instruction.  They can still be
     caused indirectly, e.g. #DE can be caused by dividing by
     0.  */
  intr_register_int (0, 0, INTR_ON, kill, "#DE Divide Error");
  intr_register_int (1, 0, INTR_ON, kill, "#DB Debug Exception");
  intr_register_int (6, 0, INTR_ON, kill, "#UD Invalid Opcode Exception");
  intr_register_int (7, 0, INTR_ON, kill,
                     "#NM Device Not Available Exception");
  intr_register_int (11, 0, INTR_ON, kill, "#NP Segment Not Present");
  intr_register_int (12, 0, INTR_ON, kill, "#SS Stack Fault Exception");
  intr_register_int (13, 0, INTR_ON, kill, "#GP General Protection Exception");
  intr_register_int (16, 0, INTR_ON, kill, "#MF x87 FPU Floating-Point Error");
  intr_register_int (19, 0, INTR_ON, kill,
                     "#XF SIMD Floating-Point Exception");

  /* Most exceptions can be handled with interrupts turned on.
     We need to disable interrupts for page faults because the
     fault address is stored in CR2 and needs to be preserved. */
  intr_register_int (14, 0, INTR_OFF, page_fault, "#PF Page-Fault Exception");
}

/* Prints exception statistics. */
void
exception_print_stats (void)
{
  printf ("Exception: %lld page faults\n", page_fault_cnt);
}

/* Handler for an exception (probably) caused by a user process. */
static void
kill (struct intr_frame *f)
{
  /* This interrupt is one (probably) caused by a user process.
     For example, the process might have tried to access unmapped
     virtual memory (a page fault).  For now, we simply kill the
     user process.  Later, we'll want to handle page faults in
     the kernel.  Real Unix-like operating systems pass most
     exceptions back to the process via signals, but we don't
     implement them. */

  /* The interrupt frame's code segment value tells us where the
     exception originated. */
  switch (f->cs)
    {
    case SEL_UCSEG:
      /* User's code segment, so it's a user exception, as we
         expected.  Kill the user process.  */
      printf ("%s: dying due to interrupt %#04x (%s).\n",
              thread_name (), f->vec_no, intr_name (f->vec_no));
      intr_dump_frame (f);
      thread_exit ();

    case SEL_KCSEG:
      /* Kernel's code segment, which indicates a kernel bug.
         Kernel code shouldn't throw exceptions.  (Page faults
         may cause kernel exceptions--but they shouldn't arrive
         here.)  Panic the kernel to make the point.  */
      intr_dump_frame (f);
      PANIC ("Kernel bug - unexpected interrupt in kernel");

    default:
      /* Some other code segment?  Shouldn't happen.  Panic the
         kernel. */
      printf ("Interrupt %#04x (%s) in unknown segment %04x\n",
             f->vec_no, intr_name (f->vec_no), f->cs);
      thread_exit ();
    }
}

/* Page fault handler.  This is a skeleton that must be filled in
   to implement virtual memory.  Some solutions to project 2 may
   also require modifying this code.

   At entry, the address that faulted is in CR2 (Control Register
   2) and information about the fault, formatted as described in
   the PF_* macros in exception.h, is in F's error_code member.  The
   example code here shows how to parse that information.  You
   can find more information about both of these in the
   description of "Interrupt 14--Page Fault Exception (#PF)" in
   [IA32-v3a] section 5.15 "Exception and Interrupt Reference". */
static void
page_fault (struct intr_frame *f)
{
  bool not_present;  /* True: not-present page, false: writing r/o page. */
  bool write;        /* True: access was write, false: access was read. */
  bool user;         /* True: access by user, false: access by kernel. */
  void *fault_addr;  /* Fault address. */

  /* Obtain faulting address, the virtual address that was
     accessed to cause the fault.  It may point to code or to
     data.  It is not necessarily the address of the instruction
     that caused the fault (that's f->eip).
     See [IA32-v2a] "MOV--Move to/from Control Registers" and
     [IA32-v3a] 5.15 "Interrupt 14--Page Fault Exception
     (#PF)". */
  asm ("movl %%cr2, %0" : "=r" (fault_addr));


   /* Turn interrupts back on (they were only off so that we could
     be assured of reading CR2 before it changed). */
  intr_enable ();

    /* Count page faults. */
  page_fault_cnt++;

  /* Determine cause. */
  not_present = (f->error_code & PF_P) == 0;
  write = (f->error_code & PF_W) != 0;
  user = (f->error_code & PF_U) != 0;


   /* Exit If User program is trying to access NULL or kernel virtual address */
  if(fault_addr == NULL || is_kernel_vaddr(fault_addr) || !not_present){
    // printf("ACCESS TO NULL OR KERN!\n");
    exit(-1);
  }

  if(f->esp > 0xbfffffff){
    f->esp = thread_current()->esp;
  }

  // printf("STACK ESP: %p\n", thread_current()->esp);
  // printf("Fault addr: %p\n", fault_addr);
  // printf("f->esp: %p\n", f->esp);
  // printf("Page addr: %p\n", pg_round_down(thread_current()->esp));
  // printf("Diffenece: %p\n", pg_round_down(thread_current()->esp) - fault_addr);
  // printf("Diffenece in esp's: %p\n", thread_current()->esp - fault_addr);


  //intr_frame f is the state/context of the cpu->>> the registers
  //Need to check the MODE to tell if f->esp is the kernel sp, or users esp
  // If its the kernels then the thread->esp should be used

   /* Need to check for user access or OS syscall access */

  //stack-grow-sc is growing the stack by 16 pages!!
  // f->esp holds the kernel address in this case since the page_fault occurred during a system call which
  //is a part of the kernel program.



  //Check to make sure this is true
  if (fault_addr >= MIN_STACK_VADDR){
    if((f->esp - 32) > fault_addr){ //pushes all the cpu registers, (8, 4 byte registers)
       // printf("F->ESP-32 > FAULT\n");
      exit(-1);
    }

    struct spt_entry* e = get_spt_entry(&thread_current()->spt, fault_addr);

    if(e == NULL){
      //Add to SPT
      struct spt_entry* e = malloc(sizeof(struct spt_entry));
      
      e->vaddr = pg_round_down(fault_addr);
      e->vpn = pg_no(e->vaddr);

      e->valid = 1;
      e->present = 1;
      e->file = NULL;
      e->swap = false;
      e->stack = true;
      hash_insert(&thread_current()->spt,&e->elem);
      uint8_t* kpage = frame_alloc(PAL_USER, e); 
      install_page(pg_round_down(fault_addr), kpage, true);
      return;
    }
    else if(e->swap){
      //Check the Swap
      int slot = e->swap_slot;
      uint8_t* kpage = frame_alloc(PAL_USER, e);
      read_slot(slot, kpage);
      install_page(e->vaddr, kpage, true);
      return;
    }
   
    else{
      // printf("STACK PAGE NOT ON SWAP?\n");
      exit(-1);
    }
  }

  //Get the SPT entry of the page that faulted
  struct spt_entry* p = get_spt_entry(&thread_current()->spt, fault_addr);

  //There is no page to load in. 
  //TODO: Ask TA about this.
  if(p == NULL){
    // printf("P==NULL!\n");
    exit(-1); 
  }

  //At this point we know a page exists but it is not loaded.  

  if(p->file){
    size_t page_read_bytes = PGSIZE - p->zeros;
    file_reopen(p->file);
    file_seek(p->file, p->file_offset);

     /* Obtain a frame from the user pool. */

    uint8_t* kpage = frame_alloc(PAL_USER,p); 

    /* Fetches data from file to frame */
    if(file_read(p->file, kpage, page_read_bytes) != (int) page_read_bytes){ 
        palloc_free_page(kpage);
       // printf("EXIT IN Exception!\n");
        exit(-1);
    }

     /* Copy zero bits into frame */
    memset (kpage + page_read_bytes, 0, p->zeros);

    /* Add the page to the process's virtual address space. Adds mapping to vaddr corresponding PTE */
   if (!install_page (p->vaddr, kpage, p->writable)) {
       palloc_free_page (kpage);
       // printf("EXIT IN Exception!\n");  
       exit(-1);             
   } 
  } 

  else if(p->swap){
    //Obtain a frame
    uint8_t* kpage = frame_alloc(PAL_USER, p);

    //fetch and read swap slot into frame
    read_slot(p->swap_slot, kpage);

    if(!install_page(p->vaddr, kpage, p->writable)){
      palloc_free_page(kpage);
       // printf("EXIT IN SWAP page_fault!\n"); 
      exit(-1);
    }
  }

    //update the SPTE
    p->present = 1;     /* Page is now present in memory, update the SPT */ 
    return;             
}
