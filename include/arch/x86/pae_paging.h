#pragma once

#include <stdint.h>
#include <libk/lock.h>

// FIXME: put in truth/x86/private/paging.h
#define NUM_PDPT 4
typedef uintptr_t physical_t;
typedef uint64_t page_dir_t;

extern void enable_paging(physical_t page_dir);

struct page_dir_ptr_table {
    page_dir_t entry[NUM_PDPT];
};
// TODO: This should be a per-core variable.
struct paging_info {
    struct page_dir_ptr_table pdpt;
    physical_t phys;
    struct virt_region *free_list;
    spinlock_t lock;
} *Cur_paging;

void switch_paging(struct paging_info *pi);
struct paging_info *get_paging_info(void);
void put_paging_info(struct paging_info *pi);


// FIXME: put in truth/paging.h
void *get_region(size_t pages, uint16_t perms);
void put_region(void *addr, size_t pages);


// FIXME: put in truth/bootstrap/paging.h
void bootstrap_switch_pae(void);
