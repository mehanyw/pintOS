#include "filesys/inode.h"
#include <list.h>
#include <debug.h>
#include <round.h>
#include <string.h>
#include "filesys/filesys.h"
#include "filesys/free-map.h"
#include "threads/malloc.h"

#include "devices/block.h"

#include <stdio.h>

/* Identifies an inode. */
#define INODE_MAGIC 0x494e4f44

#define DIR_PTR_CNT 120
#define IND_PTR_CNT 128
#define DOB_PTR_CNT 128 * 128


/* On-disk inode.
   Must be exactly BLOCK_SECTOR_SIZE bytes long. */
struct inode_disk
{   
    block_sector_t dir_sect[DIR_PTR_CNT];/* Table of Direct Pointers */
    block_sector_t ind_sect;            /* Indirect Pointer */
    block_sector_t doub_sect;           /* Doubly Indirect Pointer */
    off_t length;                       /* Length Of File */ 
    unsigned magic;                     /* Magic number. */
    int32_t idx;
    size_t space;                       /* Possible Space of File */
    int32_t isDir;
    int32_t unused;
  };

static void init_disk_inode(struct inode_disk*);
static bool insert_inode_sector(struct inode_disk*, uint32_t, block_sector_t);
static void allocate_sectors(struct inode_disk*, size_t);


/* Returns the number of sectors to allocate for an inode SIZE
   bytes long. */
static inline size_t
bytes_to_sectors (off_t size)
{
  return DIV_ROUND_UP (size, BLOCK_SECTOR_SIZE);
}

/* In-memory inode. */
struct inode
  {
    struct list_elem elem;              /* Element in inode list. */
    block_sector_t sector;              /* Sector number of disk location. */
    int open_cnt;                       /* Number of openers. */
    bool removed;                       /* True if deleted, false otherwise. */
    int deny_write_cnt;                 /* 0: writes ok, >0: deny writes. */
    struct inode_disk data;             /* Inode content. */
  };

/* Returns the block device sector that contains byte offset POS
   within INODE.
   Returns -1 if INODE does not contain data for a byte at offset
   POS. */
static block_sector_t
byte_to_sector (const struct inode *inode, off_t pos)
{
  ASSERT (inode != NULL);
  if(pos > inode->data.length)
    return -1;

  uint32_t sector = pos / BLOCK_SECTOR_SIZE;
  //Direct Case      
  if(sector < DIR_PTR_CNT)
    return inode->data.dir_sect[sector];

  block_sector_t* buf = malloc(BLOCK_SECTOR_SIZE);
  
  //Indirect Case
  if(sector < DIR_PTR_CNT + IND_PTR_CNT){
    block_read(fs_device, inode->data.ind_sect, buf);
    block_sector_t ret = buf[sector - DIR_PTR_CNT];
    free(buf);
    return ret;
  }

  //Double Indirect Case
  if(sector < DIR_PTR_CNT + IND_PTR_CNT + DOB_PTR_CNT){
     block_read(fs_device, inode->data.doub_sect, buf);

     uint32_t dsect = sector - DIR_PTR_CNT - IND_PTR_CNT;
     uint32_t ind_ptr = dsect / 128;
     block_read(fs_device, buf[ind_ptr], buf);
     block_sector_t ret = buf[sector - DIR_PTR_CNT - IND_PTR_CNT - (128 * (ind_ptr))];
     free(buf);
     return ret;
  }
  free(buf);
  return -1;
}

/* List of open inodes, so that opening a single inode twice
   returns the same `struct inode'. */
static struct list open_inodes;

/* Initializes the inode module. */
void
inode_init (void)
{
  list_init (&open_inodes);
}

/* Initializes an inode with LENGTH bytes of data and
   writes the new inode to sector SECTOR on the file system
   device.
   Returns true if successful.
   Returns false if memory or disk allocation fails. */
bool
inode_create (block_sector_t sector, off_t length, uint32_t isDir)
{
  struct inode_disk *disk_inode = NULL;
 
  ASSERT (length >= 0);

  /* If this assertion fails, the inode structure is not exactly
     one sector in size, and you should fix that. */
  ASSERT (sizeof *disk_inode == BLOCK_SECTOR_SIZE);

  disk_inode = calloc (1, sizeof *disk_inode);

  if (disk_inode != NULL)
    {     
      volatile size_t sectors = bytes_to_sectors(length);
      init_disk_inode(disk_inode);
      disk_inode->length = length;
      disk_inode->isDir = isDir;
      disk_inode->space = sectors * BLOCK_SECTOR_SIZE;
      

      if(sectors == 0)
      {
        //SHOULD I REALLY BE ALLOCING HERE?
        free_map_allocate(1, &disk_inode->dir_sect[0]);
        //disk_inode->space = BLOCK_SECTOR_SIZE; I feel like this should be included but its leading to more bugs
        disk_inode->idx++;
        block_write(fs_device, sector, disk_inode);
        return true;
      }

      //Allocate and write and set sectors
      size_t cnt = 0;
      for(; cnt < sectors; cnt++){
        block_sector_t sector_ptr;
        if(free_map_allocate(1,&sector_ptr))
        {
          insert_inode_sector(disk_inode, cnt, sector_ptr);
        }
        else
        {
          return false;
        }
      } 
      block_write(fs_device, sector, disk_inode);
     }
  return true;

}


/* Sets b-th block pointer of i to block sector s */
static bool insert_inode_sector(struct inode_disk* i, uint32_t b, block_sector_t ptr){
  ASSERT(b < DIR_PTR_CNT + IND_PTR_CNT + DOB_PTR_CNT);
  
  static char zeros[BLOCK_SECTOR_SIZE];
  block_sector_t* buf;
  i->idx++; 
 // if(b == 103)
  //    printf("HELLO!");
  if(b < DIR_PTR_CNT){
    //printf("b: %d\n", b);
    i->dir_sect[b] = ptr;
    return true;
  }
 
  buf = malloc(BLOCK_SECTOR_SIZE);

  if(b < DIR_PTR_CNT + IND_PTR_CNT)
  { 
    if(i->ind_sect == 0)
    {
      if(free_map_allocate(1, &i->ind_sect))
        block_write(fs_device, i->ind_sect, zeros);
      else{
        free(buf);
        return false;
      }
    }

    block_read(fs_device, i->ind_sect, buf);
    buf[b - DIR_PTR_CNT] = ptr;
    block_write(fs_device, i->ind_sect, buf);
    
    free(buf);
    return true;
  } 

  if(i->doub_sect == 0)
  {
    if(free_map_allocate(1, &i->doub_sect))
      block_write(fs_device, i->doub_sect, zeros);
    else{
      free(buf);
      return false;
    }
  }

  block_read(fs_device, i->doub_sect, buf);
  
  //What IndPtr is it in ?
  uint32_t adj_block = b - DIR_PTR_CNT - IND_PTR_CNT;
  uint32_t ip_idx = adj_block / 128;

  if(buf[ip_idx] == 0){
    if(free_map_allocate(1, &buf[ip_idx])){
      block_write(fs_device, buf[ip_idx], zeros);
      block_write(fs_device, i->doub_sect, buf);
    }
    else{
      free(buf);
      return false;
    }
  }

  block_sector_t hold_ptr = buf[ip_idx];
  block_read(fs_device, buf[ip_idx], buf);
  //Now buf holds an array of DPs, have to set correct one to ptr
  //CHECK
  buf[b - DIR_PTR_CNT - IND_PTR_CNT - (128 * (adj_block/128))] = ptr;
  block_write(fs_device, hold_ptr, buf);  
  //Is the DP sect written in ?
  free(buf);
  return true;
}

static void init_disk_inode(struct inode_disk* i){
  i->ind_sect = 0;
  i->doub_sect = 0;
  i->idx = 0;
  i->magic = INODE_MAGIC;
}

/* Reads an inode from SECTOR
   and returns a `struct inode' that contains it.
   Returns a null pointer if memory allocation fails. */
struct inode *
inode_open (block_sector_t sector)
{
  struct list_elem *e;
  struct inode *inode;

  /* Check whether this inode is already open. */
  for (e = list_begin (&open_inodes); e != list_end (&open_inodes);
       e = list_next (e))
    {
      inode = list_entry (e, struct inode, elem);
      if (inode->sector == sector)
        {
          inode_reopen (inode);
          return inode;
        }
    }

  /* Allocate memory. */
  inode = malloc (sizeof *inode);
  if (inode == NULL)
    return NULL;

  /* Initialize. */
  list_push_front (&open_inodes, &inode->elem);
  inode->sector = sector;
  inode->open_cnt = 1;
  inode->deny_write_cnt = 0;
  inode->removed = false;
  block_read (fs_device, inode->sector, &inode->data);
  return inode;
}

/* Reopens and returns INODE. */
struct inode *
inode_reopen (struct inode *inode)
{
  if (inode != NULL)
    inode->open_cnt++;
  return inode;
}

/* Returns INODE's inode number. */
block_sector_t
inode_get_inumber (const struct inode *inode)
{
  return inode->sector;
}

/* Closes INODE and writes it to disk.
   If this was the last reference to INODE, frees its memory.
   If INODE was also a removed inode, frees its blocks. */
void
inode_close (struct inode *inode)
{
  /* Ignore null pointer. */
  if (inode == NULL)
    return;

  /* Release resources if this was the last opener. */
  if (--inode->open_cnt == 0)
    {
      /* Remove from inode list and release lock. */
      list_remove (&inode->elem);

       // Deallocate blocks if removed. 
      if (inode->removed)
        {
          free_map_release (inode->sector, 1);
          
          //Free direct ptr-blocks
          size_t cnt = 0;
          for(; cnt < DIR_PTR_CNT; cnt++){
            if(inode->data.dir_sect[cnt] == 0){
              free(inode);
               return;
            }            
            free_map_release(inode->data.dir_sect[cnt], 1);
          }
          
          block_sector_t* buf = malloc(BLOCK_SECTOR_SIZE);
         
          //Free Indirect-ptr blocks
          block_read(fs_device, inode->data.ind_sect, buf);
          for(cnt = 0; cnt < IND_PTR_CNT; cnt++){
            if(buf[cnt] == 0){
              free(buf);
              free(inode);               //TODO: I should add this for the bottom as well
              return;
            }
            free_map_release(buf[cnt], 1);
          }

          //Free Double Indirect-Ptr blocks
          block_read(fs_device, inode->data.doub_sect, buf);

          for(cnt = 0; cnt < IND_PTR_CNT; cnt++){
            block_sector_t* d_ptrs = malloc(BLOCK_SECTOR_SIZE);
            block_read(fs_device, buf[cnt], d_ptrs);
            size_t i = 0;
            for(; i < DIR_PTR_CNT; i++)
              free_map_release(d_ptrs[i], 1);
            free(d_ptrs);
          }

          free_map_release(inode->data.doub_sect, 1);
          free(buf);
        }

      free (inode);
    }
}

/* Marks INODE to be deleted when it is closed by the last caller who
   has it open. */
void
inode_remove (struct inode *inode)
{
  ASSERT (inode != NULL);
  inode->removed = true;
}

/* Reads SIZE bytes from INODE into BUFFER, starting at position OFFSET.
   Returns the number of bytes actually read, which may be less
   than SIZE if an error occurs or end of file is reached. */
off_t
inode_read_at (struct inode *inode, void *buffer_, off_t size, off_t offset)
{
  uint8_t *buffer = buffer_;
  off_t bytes_read = 0;
  uint8_t *bounce = NULL;

  while (size > 0)
    {
      /* Disk sector to read, starting byte offset within sector. */
      block_sector_t sector_idx = byte_to_sector (inode, offset);
      int sector_ofs = offset % BLOCK_SECTOR_SIZE;

      /* Bytes left in inode, bytes left in sector, lesser of the two. */
      off_t inode_left = inode_length (inode) - offset;
      int sector_left = BLOCK_SECTOR_SIZE - sector_ofs;
      int min_left = inode_left < sector_left ? inode_left : sector_left;

      /* Number of bytes to actually copy out of this sector. */
      int chunk_size = size < min_left ? size : min_left;
      if (chunk_size <= 0)
        break;

      if (sector_ofs == 0 && chunk_size == BLOCK_SECTOR_SIZE)
        {
          /* Read full sector directly into caller's buffer. */
          block_read (fs_device, sector_idx, buffer + bytes_read);
        }
      else
        {
          /* Read sector into bounce buffer, then partially copy
             into caller's buffer. */
          if (bounce == NULL)
            {
              bounce = malloc (BLOCK_SECTOR_SIZE);
              if (bounce == NULL)
                break;
            }
          block_read (fs_device, sector_idx, bounce);
          memcpy (buffer + bytes_read, bounce + sector_ofs, chunk_size);
        }

      /* Advance. */
      size -= chunk_size;
      offset += chunk_size;
      bytes_read += chunk_size;
    }
  free (bounce);

  return bytes_read;
}

/* Writes SIZE bytes from BUFFER into INODE, starting at OFFSET.
   Returns the number of bytes actually written, which may be
   less than SIZE if end of file is reached or an error occurs.
   (Normally a write at end of file would extend the inode, but
   growth is not yet implemented.) */
off_t
inode_write_at (struct inode *inode, const void *buffer_, off_t size,
                off_t offset)
{
  const uint8_t *buffer = buffer_;
  off_t bytes_written = 0;
  uint8_t *bounce = NULL;

  if (inode->deny_write_cnt)
    return 0;

  //Check for needed growth
  int possible_size = inode->data.space;
  if(offset + size > possible_size)
  {
    //Reailistically, we dont need to add all size bytes but this simplifies things
    if(offset > inode->data.length)
      allocate_sectors(&inode->data, offset + size);
    else
      allocate_sectors(&inode->data, size);
    block_write(fs_device, inode->sector, &inode->data);
  }

  while (size > 0)
    {
      /* Sector to write, starting byte offset within sector. */
      block_sector_t sector_idx = byte_to_sector (inode, offset);
      int sector_ofs = offset % BLOCK_SECTOR_SIZE;

      /* Bytes left in inode, bytes left in sector, lesser of the two. */
      off_t inode_left;
      if(offset == inode->data.length){
        inode_left = inode->data.space - offset;
        inode->data.length += size; //<--- Just assume that we will be able to right all size bytes
        block_write(fs_device, inode->sector, &inode->data);
      }
      else{
      inode_left = inode_length (inode) - offset;
      }
      int sector_left = BLOCK_SECTOR_SIZE - sector_ofs;
      int min_left = inode_left < sector_left ? inode_left : sector_left;

      /* Number of bytes to actually write into this sector. */
      int chunk_size = size < min_left ? size : min_left;
      if (chunk_size <= 0)
        break;

      if (sector_ofs == 0 && chunk_size == BLOCK_SECTOR_SIZE)
        {
          /* Write full sector directly to disk. */
          block_write (fs_device, sector_idx, buffer + bytes_written);
        }
      else
        {
          /* We need a bounce buffer. */
          if (bounce == NULL)
            {
              bounce = malloc (BLOCK_SECTOR_SIZE);
              if (bounce == NULL)
                break;
            }

          /* If the sector contains data before or after the chunk
             we're writing, then we need to read in the sector
             first.  Otherwise we start with a sector of all zeros. */
          if (sector_ofs > 0 || chunk_size < sector_left)
            block_read (fs_device, sector_idx, bounce);
          else
            memset (bounce, 0, BLOCK_SECTOR_SIZE);
          memcpy (bounce + sector_ofs, buffer + bytes_written, chunk_size);
          block_write (fs_device, sector_idx, bounce);
        }
      /* Advance. */
      size -= chunk_size;
      offset += chunk_size;
      bytes_written += chunk_size;
    }
  free (bounce);


  return bytes_written;
}

/* Allocate "bytes" more bytes inode */
static void allocate_sectors(struct inode_disk* i, size_t bytes){
  size_t sectors_needed = bytes_to_sectors(bytes);
  size_t cnt = 0;
  for(; cnt < sectors_needed; cnt++)
  {
    block_sector_t sector_ptr;
    if(free_map_allocate(1, &sector_ptr))
      insert_inode_sector(i, i->idx, sector_ptr);
    else
      printf("ERROR IN ALLOC_SECTORS");
  }
  i->length += bytes;
  //i->space += bytes; ADDED
}

/* Disables writes to INODE.
   May be called at most once per inode opener. */
void
inode_deny_write (struct inode *inode)
{
  inode->deny_write_cnt++;
  ASSERT (inode->deny_write_cnt <= inode->open_cnt);
}

/* Re-enables writes to INODE.
   Must be called once by each inode opener who has called
   inode_deny_write() on the inode, before closing the inode. */
void
inode_allow_write (struct inode *inode)
{
  ASSERT (inode->deny_write_cnt > 0);
  ASSERT (inode->deny_write_cnt <= inode->open_cnt);
  inode->deny_write_cnt--;
}

/* Returns the length, in bytes, of INODE's data. */
off_t
inode_length (const struct inode *inode)
{
  return inode->data.length;
}


bool isDir(const struct inode* i){
  return i->data.isDir;
}

bool isRemoved(const struct inode* i){
  return i->removed;
}