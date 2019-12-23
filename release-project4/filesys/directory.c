#include "filesys/directory.h"
#include <stdio.h>
#include <string.h>
#include <list.h>
#include "filesys/filesys.h"
#include "filesys/inode.h"
#include "threads/malloc.h"
#include "threads/thread.h"

/* A directory. */
struct dir
  {
    struct inode *inode;                /* Backing store. */
    off_t pos;                          /* Current position. */

    //Note, should these also be in the dir_entry ? 
    //Where should i set these, Also shouldnt i just use dir_add these
    //To have easier lookup using dir
    struct dir*  self;                   //"." self refernce 
    struct dir* parent_dir;             /* ".." parent dir refernce  */
  };

/* A single directory entry. */
struct dir_entry
  {
    block_sector_t inode_sector;        /* Sector number of header. */
    char name[NAME_MAX + 1];            /* Null terminated file name. */
    bool in_use;                        /* In use or free? */
  };

/* Creates a directory with space for ENTRY_CNT entries in the
   given SECTOR.  Returns true if successful, false on failure. */
bool
dir_create (block_sector_t sector, size_t entry_cnt)
{
  return inode_create (sector, entry_cnt * sizeof (struct dir_entry), 1);
}

/* Opens and returns the directory for the given INODE, of which
   it takes ownership.  Returns a null pointer on failure. */
struct dir *
dir_open (struct inode *inode)
{
  struct dir *dir = calloc (1, sizeof *dir);
  if (inode != NULL && dir != NULL)
    {
      dir->inode = inode;
      dir->pos = 0;
      return dir;
    }
  else
    {
      inode_close (inode);
      free (dir);
      return NULL;
    }
}

/* Opens the root directory and returns a directory for it.
   Return true if successful, false on failure. */
struct dir *
dir_open_root (void)
{
  return dir_open (inode_open (ROOT_DIR_SECTOR));
}

/* Opens and returns a new directory for the same inode as DIR.
   Returns a null pointer on failure. */
struct dir *
dir_reopen (struct dir *dir)
{
  return dir_open (inode_reopen (dir->inode));
}

/* Destroys DIR and frees associated resources. */
void
dir_close (struct dir *dir)
{
  if (dir != NULL)
    {
      //YIKES: I think i shouldve used sector when storing cwd, ther are problems here
      //When i close, doing this for now
      //inode_close (dir->inode);
      //free (dir); //TODO: WTF WHEN I TAKE THIS OUT IS_THREAD DOESNT ASSERT EVEN THO IT NEVER SHOULD ?
    }
}

/* Returns the inode encapsulated by DIR. */
struct inode *
dir_get_inode (struct dir *dir)
{
  return dir->inode;
}

/* Searches DIR for a file with the given NAME.
   If successful, returns true, sets *EP to the directory entry
   if EP is non-null, and sets *OFSP to the byte offset of the
   directory entry if OFSP is non-null.
   otherwise, returns false and ignores EP and OFSP. */
static bool
lookup (const struct dir *dir, const char *name,
        struct dir_entry *ep, off_t *ofsp)
{
  struct dir_entry e;
  size_t ofs;

  ASSERT (dir != NULL);
  ASSERT (name != NULL);

  for (ofs = 0; inode_read_at (dir->inode, &e, sizeof e, ofs) == sizeof e;
       ofs += sizeof e)
    if (e.in_use && !strcmp (name, e.name))
      {
        if (ep != NULL)
          *ep = e;
        if (ofsp != NULL)
          *ofsp = ofs;
        return true;
      }
  return false;
}

/* Searches DIR for a file with the given NAME
   and returns true if one exists, false otherwise.
   On success, sets *INODE to an inode for the file, otherwise to
   a null pointer.  The caller must close *INODE. */
bool
dir_lookup (const struct dir *dir, const char *name,
            struct inode **inode)
{
  struct dir_entry e;
  bool removed = isRemoved(dir_get_inode(dir));
  ASSERT (dir != NULL);
  ASSERT (name != NULL);
  
  if(removed == true){
    *inode = NULL;
    return false;
  }


  if (lookup (dir, name, &e, NULL))
    *inode = inode_open (e.inode_sector);
  else
    *inode = NULL;

  return *inode != NULL;
}

/* Adds a file named NAME to DIR, which must not already contain a
   file by that name.  The file's inode is in secto
   INODE_SECTOR.
   Returns true if successful, false on failure.
   Fails if NAME is invalid (i.e. too long) or a disk or memory
   error occurs. */
bool
dir_add (struct dir *dir, const char *name, block_sector_t inode_sector)
{
  struct dir_entry e;
  off_t ofs;
  bool success = false;

  ASSERT (dir != NULL);
  ASSERT (name != NULL);

  /* Check NAME for validity. */
  if (*name == '\0' || strlen (name) > NAME_MAX)
    return false;

  /* Check that NAME is not in use. */
  if (lookup (dir, name, NULL, NULL))
    goto done;

  /* Set OFS to offset of free slot.
     If there are no free slots, then it will be set to the
     current end-of-file.

     inode_read_at() will only return a short read at end of file.
     Otherwise, we'd need to verify that we didn't get a short
     read due to something intermittent such as low memory. */
  for (ofs = 0; inode_read_at (dir->inode, &e, sizeof e, ofs) == sizeof e;
       ofs += sizeof e)
    if (!e.in_use)
      break;

  /* Write slot. */
  e.in_use = true;
  strlcpy (e.name, name, sizeof e.name);
  e.inode_sector = inode_sector;
  success = inode_write_at (dir->inode, &e, sizeof e, ofs) == sizeof e;

 done:
  return success;
}

/* Removes any entry for NAME in DIR.
   Returns true if successful, false on failure,
   which occurs only if there is no file with the given NAME. */
bool
dir_remove (struct dir *dir, const char *name)
{
  struct dir_entry e;
  struct inode *inode = NULL;
  bool success = false;
  off_t ofs;

  ASSERT (dir != NULL);
  ASSERT (name != NULL);

  /* Find directory entry. */
  if (!lookup (dir, name, &e, &ofs))
    goto done;

  /* Open inode. */
  inode = inode_open (e.inode_sector);
  if (inode == NULL)
    goto done;

  /* Erase directory entry. */
  e.in_use = false;
  if (inode_write_at (dir->inode, &e, sizeof e, ofs) != sizeof e)
    goto done;

  /* Remove inode. */
  inode_remove (inode);
  success = true;

 done:
  inode_close (inode);
  return success;
}

/* Reads the next directory entry in DIR and stores the name in
   NAME.  Returns true if successful, false if the directory
   contains no more entries. */
bool
dir_readdir (struct dir *dir, char name[NAME_MAX + 1])
{
  struct dir_entry e;

  while (inode_read_at (dir->inode, &e, sizeof e, dir->pos) == sizeof e)
    {
      dir->pos += sizeof e;
      if (e.in_use && strcmp(e.name, ".") && strcmp(e.name, ".."))
        {
          strlcpy (name, e.name, NAME_MAX + 1);
          return true;
        }
    }
  return false;
}


struct dir* abs_path_traverse(const char* dir){
  /* Cpy string */
  char* path_str = (char*)malloc(strlen(dir));
  strlcpy(path_str, dir, 100); //Reasoing below

  /* Start at root dir */
  struct dir* d = dir_open_root();
  struct inode* i = dir_get_inode(d);


  /* Tokenize str, TODO: check case "//" */  
  char* save_ptr;
  char* token = strtok_r(path_str, "/", &save_ptr);

  for (; token; token = strtok_r (NULL, "/", &save_ptr)){
     if(!dir_lookup(d, token, &i)){
      //printf("Did not find %s in dir", token);
      free(path_str);
      return d;
      //return NULL;  //What if we have an invalid ?
     }
     dir_close(d);
     d = dir_open(i);
   }
   free(path_str);
   //thread_current()->cwd = d;
   return d; //TODO: Step through this
}


//TODO: Refactor to combine the two into wrappers for one func
struct dir* rel_path_traverse(const char* dir){
  
  /* Cpy string */
  char* path_str = (char*)malloc(strlen(dir));
  strlcpy(path_str, dir, 100); //TODO: strlen() is not working, thus magic number :/

  /* Start at current dir */
  struct dir* d = thread_current()->cwd;
  struct inode* i = dir_get_inode(d);
  
  /* Tokenize str, TODO: check case "//" */  
  char* save_ptr;
  char* token = strtok_r(path_str, "/", &save_ptr);

  for (; token; token = strtok_r (NULL, "/", &save_ptr)){
     if(!dir_lookup(d, token, &i)){
      //printf("Did not find %s in dir", token);
      free(path_str);
      return NULL;
     }
    // dir_close(d);
     d = dir_open(i);
   }
   free(path_str);
   //thread_current()->cwd = d;
   return d; //TODO: Step through this
}

void dir_unix_dot_init(struct dir* d, struct dir* parent){
  dir_add(d, ".", inode_get_inumber(dir_get_inode(d)));
  dir_add(d, "..", inode_get_inumber(dir_get_inode(parent)));
  return;
}

void dir_setPos(struct dir* d, int i){
  d->pos = i;
}

int dir_getPos(struct dir* d){
  return d->pos;
}
struct inode* getParentInode(struct dir* d){
  struct inode* i = NULL;
  if(dir_lookup(d, "..", &i))
    return i;
   return NULL;  
}