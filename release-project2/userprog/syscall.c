#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"

/* For system call prototypes */
#include <lib/user/syscall.h>

/* For OS shutdown capabilities */
#include "devices/shutdown.h"

/* For Vitrual Address capabilites */
#include "threads/vaddr.h"
#include "pagedir.h"

/* For sychronization needed for filesystem */
#include "threads/synch.h"

/* For access to the console */
#include <kernel/console.h>

/* For access to file operations */
#include "filesys/filesys.h"
#include "filesys/file.h"
static void syscall_handler (struct intr_frame *);
static int get_user (const uint8_t *uaddr);
static bool put_user (uint8_t *udst, uint8_t byte);
static void get_user_mem(void* user_add,void* kern_dest,unsigned size);

static struct lock fs_lock;          /* A global lock which will manage mutual exclusion of filesystem */


void
syscall_init (void)
{
	intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");

	/* Intialize the global fs lock */
	lock_init(&fs_lock);
}


static void
syscall_handler (struct intr_frame *f)
{
	if(f->esp == NULL || !is_user_vaddr(f->esp) || pagedir_get_page(thread_current()->pagedir,f->esp) == NULL) {
		exit(-1);
	}
	pid_t pid = 0;
	int arg = 0;
	int arg2 = 0;
	void* buf;


	switch(*((int*) f->esp)) {
	case SYS_HALT:
		halt();
		break;

	case SYS_EXIT:
		get_user_mem(f->esp+4,&arg,4);
		exit(arg);
		break;

	case SYS_EXEC:
		get_user_mem(f->esp+4, &buf, 4);
		f->eax = exec(buf);
		break;

	case SYS_WAIT:
		get_user_mem(f->esp+4, &pid,4);
		f->eax = wait(pid);
		break;

	case SYS_CREATE:
		get_user_mem(f->esp+4, &buf, 4);
		get_user_mem(f->esp+8, &arg, 4);
		f->eax = create(buf,arg);
		break;

	case SYS_REMOVE:
		get_user_mem(f->esp+4, &buf, 4);
		f->eax = remove(buf);
		break;

	case SYS_OPEN:
		get_user_mem(f->esp+4, &buf, 4);
		f->eax = open(buf);
		break;

	case SYS_FILESIZE:
		get_user_mem(f->esp+4, &arg, 4);
		f->eax = filesize(arg);
		break;

	case SYS_READ:
		get_user_mem(f->esp+4, &arg, 4);
		get_user_mem(f->esp+8, &buf, 4);
		get_user_mem(f->esp+12, &arg2, 4);
		f->eax = read(arg,buf,arg2);
		break;

	case SYS_WRITE:
		get_user_mem(f->esp+4, &arg, 4);
		get_user_mem(f->esp+8, &buf, 4);
		get_user_mem(f->esp+12, &arg2, 4);
		f->eax = write(arg, buf, arg2);
		break;

	case SYS_SEEK:
		get_user_mem(f->esp+4,&arg,4);
		get_user_mem(f->esp+8,&arg2,4);
		seek(arg,arg2);

		break;

	case SYS_TELL:
		get_user_mem(f->esp+4, &arg, 4);
		f->eax =tell(arg);
		break;

	case SYS_CLOSE:
		get_user_mem(f->esp+4,&arg,4);
		close(arg);
		break;

	}
}

/* Reads size number of bytes in order to read arguments for syscalls*/
static void
get_user_mem(void* user_add,void* kern_dest,unsigned size)
{
	int i=0;
	for(; i<size; i++) {
		if(user_add == NULL || !is_user_vaddr(user_add+i)) {
			exit(-1);
		}
		int b = get_user(user_add+i);
		memset(kern_dest+i,b,1);
	}

}





/* void halt (void)
        Terminates Pintos by calling shutdown_power_off() (declared in "threads/init.h").
        This should be seldom used, because you lose some information about possible
        deadlock situations, etc.  */

void
halt(void)
{
	shutdown_power_off();
}

/* void exit (int status)
        Terminates the current user program,
        returning status to the kernel. If the process's parent waits for it (see below),
        this is the status that will be returned. Conventionally, a status of 0 indicates
        success and nonzero values indicate errors. */

void exit(int status)
{

	struct thread* t = thread_current();       //Get the current thread
	/*Close all file descriptors*/
	int i=0;
	for(; i<FDTABLE_SIZE; i++) {
		if(t->fdtable[i]) {
			close(i);
		}
	}
	t->exit_status = status;                   //Set the thread exit status
	sema_up(&t->dying);                  // Tell the parent that the exit_status id ready to be read
	thread_exit();
}

/*pid_t exec (const char *cmd_line)
    Runs the executable whose name is given in cmd_line, passing any
    given arguments, and returns the new process's program id (pid). Must
    return pid -1, which otherwise should not be a valid pid, if the program
    cannot load or run for any reason. Thus, the parent process cannot return
    from the exec until it knows whether the child process successfully loaded
    its executable. You must use appropriate synchronization to ensure this. */

pid_t
exec (const char* cmd_line)
{
	if (cmd_line == NULL || !is_user_vaddr(cmd_line) || pagedir_get_page(thread_current()->pagedir,cmd_line) == NULL) {
		exit(-1);
	}
	pid_t child = process_execute(cmd_line);
	return child;
}

/* Waits for a child process pid and retrieves the child's exit status.

   If pid is still alive, waits until it terminates. Then, returns the status that pid passed to exit.
   If pid did not call exit(), but was terminated by the kernel (e.g. killed due to an exception), wait(pid)
   must return -1. It is perfectly legal for a parent process to wait for child processes that have already
   terminated by the time the parent calls wait, but the kernel must still allow the parent to retrieve its
   child's exit status, or learn that the child was terminated by the kernel.

   wait must fail and return -1 immediately if any of the following conditions is true:

    pid does not refer to a direct child of the calling process. pid is a direct child of the
    calling process if and only if the calling process received pid as a return value from a
    successful call to exec.

    Note that children are not inherited: if A spawns child B and B spawns child process C,
    then A cannot wait for C, even if B is dead. A call to wait(C) by process A must fail.
    Similarly, orphaned processes are not assigned to a new parent if their parent process exits before
    they do.

    The process that calls wait has already called wait on pid. That is, a process may wait for any
    given child at most once.

   Processes may spawn any number of children, wait for them in any order, and may even exit without
   having waited for some or all of their children. Your design should consider all the ways in which
   waits can occur. All of a process's resources, including its struct thread, must be freed whether its
   parent ever waits for it or not, and regardless of whether the child exits before or after its parent.

   You must ensure that Pintos does not terminate until the initial process exits. The supplied Pintos
   code tries to do this by calling process_wait() (in "userprog/process.c") from main() (in "threads/init.c").
   We suggest that you implement process_wait() according to the comment at the top of the function and then
   implement the wait system call in terms of process_wait().

   Implementing this system call requires considerably more work than any of the rest.  */

static struct thread*
get_child_thread_byId(pid_t child)
{
	struct thread* parent = thread_current();
	int i=0;
	for(; i<CHILDTABLE_SIZE; i++) {
		if(parent->childTable[i]) {
			if(parent->childTable[i]->tid == child) {
				return parent->childTable[i];
			}
		}
	}
	return NULL;
}

int
wait (pid_t pid)
{
	struct thread* parent = thread_current();
	//If child is still alive, it will be here
	struct thread* child = get_child_thread_byId(pid);
	if(child) {
		int exit_status = process_wait(child->tid);
		sema_up(&child->dead);
		remove_child_thread_byId(child->tid);
		return exit_status;
	}
	return -1;

}

/*bool create (const char *file, unsigned initial_size)
    Creates a new file called file initially initial_size bytes in size.
    Returns true if successful, false otherwise. Creating a new file does
    not open it: opening the new file is a separate operation which would
    require a open system call.*/

bool
create (const char* file, unsigned initial_size)
{
	//Check if null, kernel address space, or unmapped virtual memory;

	if(file == NULL || !is_user_vaddr(file) || pagedir_get_page(thread_current()->pagedir,file) == NULL) {
		exit(-1);
	}
	lock_acquire(&fs_lock);
	bool retVal = filesys_create(file,initial_size);
	lock_release(&fs_lock);
	return retVal;
}


/* bool remove (const char *file)
    Deletes the file called file. Returns true if successful, false otherwise.
    A file may be removed regardless of whether it is open or closed, and removing
    an open file does not close it. See Removing an Open File, for details. */

bool
remove (const char* file)
{
	if(file == NULL || !is_user_vaddr(file) || pagedir_get_page(thread_current()->pagedir,file) == NULL) {
		exit(-1);
	}
	lock_acquire(&fs_lock);
	bool retVal = filesys_remove(file);
	lock_release(&fs_lock);

	return retVal;
}


/* int open (const char *file)
    Opens the file called file. Returns a nonnegative integer handle called a "file descriptor" (fd),
    or -1 if the file could not be opened.

    File descriptors numbered 0 and 1 are reserved for the console: fd 0 (STDIN_FILENO) is
    standard input, fd 1 (STDOUT_FILENO) is standard output. The open system call will never
    return either of these file descriptors, which are valid as system call arguments only as
    explicitly described below.

    Each process has an independent set of file descriptors. File descriptors are not
    inherited by child processes.

    When a single file is opened more than once, whether by a single process or different processes,
    each open returns a new file descriptor. Different file descriptors for a single file are closed
    independently in separate calls to close and they do not share a file position.
 */

int
open (const char* file)
{
	if(file == NULL || !is_user_vaddr(file) || pagedir_get_page(thread_current()->pagedir,file) == NULL) {
		exit(-1);
	}

	lock_acquire(&fs_lock);
	struct file* fptr = filesys_open(file);
	lock_release(&fs_lock);
	if(fptr == NULL) {
		return -1;
	}

	/* ~~~ Need to add it the thread fdtable ~~~*/

	struct thread* t = thread_current();
	t->fdtable[t->nextFd] = fptr;           /* Place file pointer in fd table */
	int retVal = t->nextFd;                 /* Set the return int to the index of the fd table */
	t->nextFd++;                            /* Increment the nextFd field of the thread */

	return retVal;
}


/* int filesize (int fd)
    Returns the size, in bytes, of the file open as fd. */

int
filesize (int fd)
{
	/* read the whole contents of the file until EOF then report back number of bytes */
	uint32_t count = 0;
	lock_acquire(&fs_lock);
	struct thread* t = thread_current();
	struct file* fptr = t->fdtable[fd];
	if (fptr == NULL) {
		lock_release(&fs_lock);
		return -1;
	}

	lock_release(&fs_lock);
	return file_length(fptr);

}


/* int read (int fd, void *buffer, unsigned size)
    Reads size bytes from the file open as fd into buffer. Returns the
    number of bytes actually read (0 at end of file), or -1 if the file
    could not be read (due to a condition other than end of file). Fd 0
    reads from the keyboard using input_getc().  */

int
read (int fd, void* buffer, unsigned size)
{
	if(buffer == NULL || !is_user_vaddr(buffer) || pagedir_get_page(thread_current()->pagedir,buffer) == NULL) {
		exit(-1);
	}

	if(fd == STDIN_FILENO) {
		int count = 0;
		for(; count < size; count++) {
			uint8_t byte = input_getc();
			memset(buffer+count,byte,1);
		}
		return size;
	}
	//NOTE: fd could be too big, that could cause problems
	if(fd>FDTABLE_SIZE || fd < 0) {
		return -1;
	}
	struct file* fptr = thread_current()->fdtable[fd];
	if(fptr == NULL) {
		return -1;
	}
	off_t bytes_read = file_read(fptr,buffer,size);

	return bytes_read;
}

/*int write (int fd, const void *buffer, unsigned size)
    Writes size bytes from buffer to the open file fd.
    Returns the number of bytes actually written,
    which may be less than size if some bytes could not be written.

    Writing past end-of-file would normally extend the file,
    but file growth is not implemented by the basic file system.
    The expected behavior is to write as many bytes as possible up
    to end-of-file and return the actual number written, or 0 if no bytes
    could be written at all.

    Fd 1 writes to the console. Your code to write to the console should
    write all of buffer in one call to putbuf(), at least as long as size is
    not bigger than a few hundred bytes. (It is reasonable to break up larger buffers.)
    Otherwise, lines of text output by different processes may end up interleaved
    on the console, confusing both human readers and our grading scripts.
 */


int
write (int fd,const void* buffer, unsigned size)
{

	if(buffer == NULL || !is_user_vaddr(buffer) || pagedir_get_page(thread_current()->pagedir,buffer) == NULL) {
		exit(-1);
	}

	if(fd == STDOUT_FILENO) {
		putbuf(buffer,size);
		return size;
	}
	if(fd > FDTABLE_SIZE || fd < 0) { //TODO: Update fdtable to a dynamic list
		return -1;
	}

	//I will have to check if current FD is valid
	struct thread* t = thread_current();
	struct file* fptr = t->fdtable[fd];
	if(fptr) {
		lock_acquire(&fs_lock); //Is a lock needed for file write ?
		int retVal = file_write(fptr,buffer,size);
		lock_release(&fs_lock);
		return retVal;
	}

	return -1;
}



/* void seek (int fd, unsigned position)
    Changes the next byte to be read or written in open file fd to position, expressed
    in bytes from the beginning of the file. (Thus, a position of 0 is the file's start.)

    A seek past the current end of a file is not an error. A later read obtains 0 bytes,
    indicating end of file. A later write extends the file, filling any unwritten gap with
    zeros. (However, in Pintos files have a fixed length until project 4 is complete, so writes
    past end of file will return an error.) These semantics are implemented in the file system
    and do not require any special effort in system call implementation. */

void
seek (int fd, unsigned position)
{
	if(fd > FDTABLE_SIZE || fd < 0) {
		return;
	}
	struct file* fptr = thread_current()->fdtable[fd];
	if(fptr) {
		file_seek(fptr,position);
	}
}

/* unsigned tell (int fd)
    Returns the position of the next byte to be read or written in
    open file fd, expressed in bytes from the beginning of the file. */

unsigned
tell (int fd)
{
	if(fd > FDTABLE_SIZE || fd < 0) {
		return -1;
	}

	struct file* fptr = thread_current()->fdtable[fd];
	if(fptr) {
		unsigned retVal = file_tell(fptr);
		return retVal;
	}

	return -1;
}

/* void close (int fd)
    Closes file descriptor fd. Exiting or terminating a process implicitly closes all
    its open file descriptors, as if by calling this function for each one.  */

void
close (int fd)
{
	if(fd > FDTABLE_SIZE || fd < 0) {
		return;
	}
	struct file* fptr = thread_current()->fdtable[fd];
	if(fptr) {
		file_close(fptr);
		thread_current()->fdtable[fd] = NULL;
	}
}

/* Reads a byte at user virtual address UADDR.
   UADDR must be below PHYS_BASE.
   Returns the byte value if successful, -1 if a segfault
   occurred. */
static int
get_user (const uint8_t *uaddr)
{
	int result;
	asm ("movl $1f, %0; movzbl %1, %0; 1:"
	     : "=&a" (result) : "m" (*uaddr));
	return result;
}

/*   Writes BYTE to user address UDST.
     UDST must be below PHYS_BASE.
     Returns true if successful, false if a segfault occurred. */
static bool
put_user (uint8_t *udst, uint8_t byte)
{
	int error_code;
	asm ("movl $1f, %0; movb %b2, %1; 1:"
	     : "=&a" (error_code), "=m" (*udst) : "q" (byte));
	return error_code != -1;
}
