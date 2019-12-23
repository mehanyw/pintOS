#ifndef FILESYS_DIRECTORY_H
#define FILESYS_DIRECTORY_H

#include <stdbool.h>
#include <stddef.h>
#include "devices/block.h"

/* Maximum length of a file name component.
   This is the traditional UNIX maximum length.
   After directories are implemented, this maximum length may be
   retained, but much longer full path names must be allowed. */
#define NAME_MAX 32

struct inode;

/* Opening and closing directories. */
bool dir_create (block_sector_t sector, size_t entry_cnt);
struct dir *dir_open (struct inode *);
struct dir *dir_open_root (void);
struct dir *dir_reopen (struct dir *);
void dir_close (struct dir *);
struct inode *dir_get_inode (struct dir *);

/* Reading and writing. */
bool dir_lookup (const struct dir *, const char *name, struct inode **);
bool dir_add (struct dir *, const char *name, block_sector_t);
bool dir_remove (struct dir *, const char *name);
bool dir_readdir (struct dir *, char name[NAME_MAX + 1]);


/* Filesys stuff, Should i put it here? ~ Ammar */
struct dir* abs_path_traverse(const char*);
struct dir* rel_path_traverse(const char*);
void dir_unix_dot_init(struct dir*, struct dir*);
void dir_setPos(struct dir* d, int);
int dir_getPos(struct dir*);
bool isParent(struct dir*, struct dir*);
struct inode* getParentInode(struct dir*);
#endif /* filesys/directory.h */
