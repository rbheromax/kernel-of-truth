#include <stdbool.h>
#include <stdint.h>
#include <libk/kassert.h>
#include <libk/kmem.h>
#include <arch/x86/pae_paging.h>

#define PAGE_PRESENT 1

#define PAGE_TABLE_SIZE 512
#define NUM_FREE_ADDRS ((PAGE_SIZE / 4) - sizeof(size_t) - \
        sizeof(struct page_dir_ptr_table))

#define UNUSED(x) x __attribute__((unused))

#define GET_PDPTE(x) (uint64_t)((uintptr_t)x >> 30)
#define GET_PDE(x) (uint64_t)(((uintptr_t)x >> 21) & 0x1ff)
#define GET_PTE(x) (uint64_t)(((uintptr_t)x >> 12) & 0x1ff)

// The compiler really wants us to cast to uintptr_t first.
#define GET_PD_VIRT(x) (void*)(uintptr_t)((x >> 12) & 0xffffffff)
#define GET_PDE_VIRT(x) (void*)(uintptr_t)((x >> 12) & 0xffffffff)
#define GET_PTE_VIRT(x) (void*)(uintptr_t)((x >> 12) & 0xffffffff)

#define GET_FRAME(x) ((physical_t)x & ~0xfff)

// virtual memory manager
struct virt_region {
    void *addr;
    size_t size;
    struct virt_region *next;
} *Virt_mem;

static struct virt_region *init_free_list(void);
static void *find_region(size_t size);

static inline struct page_dir_ptr_table *get_page_dir_ptr_table(void) {
    return &Cur_paging->pdpt;
}

// Set once.
// Assume that the kernel fits in PAGE_TABLE_SIZE pages!
static physical_t kernel_pages = 0;

// ------------------ Bootstrap PAE paging -----------------------

// FIXME: This should change when switching to higher half.
static inline physical_t kernel_addr_to_phys(void *kern_addr) {
    return (physical_t)kern_addr - (KERNEL_PHYS_START - KERNEL_START);
}

// FIXME: This should change when switching to higher half.
physical_t *get_non_pae(physical_t phys, uint16_t UNUSED(perms)) {
    return (void*)phys;
}

// FIXME: This should change when switching to higher half.
void unmap_non_pae(void *UNUSED(virt), bool UNUSED(unmap)) {
}

static void set_kernel_pages(void) {
    kernel_pages = alloc_frame();
    // Kernel is loaded to 1 MB
    physical_t page = KERNEL_PHYS_START;
    // NULL makes a wonderful temporary page.
    physical_t *addr = get_non_pae(kernel_pages, 0);
    for (size_t pg = MB; pg < KERNEL_SIZE/PAGE_SIZE + MB; ++pg) {
        addr[pg] = page | PAGE_PRESENT;
        page += PAGE_SIZE;
    }
    unmap_non_pae(addr, false);
}

// Do the dirty work of switching to PAE paging mode.
// Bootstrap public function.
void bootstrap_switch_pae(void) {
    Cur_paging = kcalloc(0, sizeof(struct paging_info));
    set_kernel_pages();
    physical_t pd = alloc_frame();
    physical_t *pde = get_non_pae(alloc_frame(), 0);
    Cur_paging->free_list = init_free_list();
    // Initialize PDPT entry.
    Cur_paging->pdpt.entry[GET_PDPTE(KERNEL_START)] = pd | PAGE_PRESENT;
    // Mark kernel pages.
    pde[GET_PTE(KERNEL_START)] = kernel_pages | PAGE_PRESENT;
    // Fractal map.
    Cur_paging->pdpt.entry[PAGE_TABLE_SIZE-1] |= pd | PAGE_PRESENT;
    // Deep breath...
    klog("Switching to PAE paging mode\n");
    switch_paging(Cur_paging);
}

// ---------------------------------------------------------------

static void map_page(void *virt, physical_t phys, uint16_t perms) {
    kassert((phys % PAGE_SIZE) == 0);
    kassert(((uintptr_t)virt % PAGE_SIZE) == 0);
    struct page_dir_ptr_table *pdpt = get_page_dir_ptr_table();
    page_dir_t pd = pdpt->entry[GET_PDPTE(virt)];
    uint64_t *pdes = GET_PD_VIRT(pd);
    // If a page table must be allocated.
    if ((pdes[GET_PDE(virt)] & PAGE_PRESENT) == 0) {
        physical_t pte = alloc_frame();
        pdes[GET_PDE(virt)] = pte | perms | PAGE_PRESENT;
    }
    uint64_t *ptes = GET_PTE_VIRT(pdes[GET_PDE(virt)]);
    ptes[GET_PTE(virt)] = phys | perms | PAGE_PRESENT;
}

static void unmap_page(void *virt, bool free_phys) {
    kassert(((uintptr_t)virt % PAGE_SIZE) == 0);
    struct page_dir_ptr_table *pdpt = get_page_dir_ptr_table();
    page_dir_t pd = pdpt->entry[GET_PDPTE(virt)];
    uint64_t *pdes = GET_PD_VIRT(pd);
    // Page table must be allocated.
    if (pdes[GET_PDE(virt)] & PAGE_PRESENT) {
        uint64_t *ptes = GET_PTE_VIRT(pdes[GET_PDE(virt)]);
        if (free_phys) {
            free_frame(GET_FRAME(ptes[GET_PTE(virt)]));
        }
        ptes[GET_PTE(virt)] &= ~PAGE_PRESENT;
    }
}

static void free_pdpt(struct page_dir_ptr_table *pdpt) {
    // Obviously the pdpt should not be mapped!
    kassert(pdpt != get_page_dir_ptr_table());
    // For each PDPTE
    for (size_t i = 0; i < NUM_PDPT; ++i) {
        page_dir_t pd = pdpt->entry[i];
        if (pd & PAGE_PRESENT) {
            physical_t *pdes = GET_PDE_VIRT(pd);
            // For each PDE
            for (size_t j = 0; j < PAGE_TABLE_SIZE; ++j) {
                if (pdes[j] & PAGE_PRESENT) {
                    physical_t *ptes = GET_PTE_VIRT(pdes[j]);
                    // For each PTE
                    for (size_t k = 0; k < PAGE_TABLE_SIZE; ++k) {
                        // If it's absent, map it and return it.
                        if ((ptes[k] & PAGE_PRESENT) == 0) {
                            free_frame(GET_FRAME(ptes[k]));
                        }
                    }
                    free_frame(GET_FRAME(pdes[j]));
                }
            }
            free_frame(GET_FRAME(pd));
        }
    }
    kfree(pdpt);
}

static inline void fractal_map(page_dir_t pd) {
    struct virt_region *vr = find_region(1);
    map_page(vr->addr, pd, 0);
    physical_t *pdes = vr->addr;
    pdes[PAGE_TABLE_SIZE-1] = pd | PAGE_PRESENT;
}

static void init_pdpt(struct page_dir_ptr_table *pdpt) {
    pdpt->entry[0] = alloc_frame() | PAGE_PRESENT;
    fractal_map(pdpt->entry[0]);
    pdpt->entry[1] = alloc_frame() | PAGE_PRESENT;
    fractal_map(pdpt->entry[1]);
    pdpt->entry[2] = alloc_frame() | PAGE_PRESENT;
    fractal_map(pdpt->entry[2]);
    pdpt->entry[3] = alloc_frame() | PAGE_PRESENT;
    fractal_map(pdpt->entry[3]);
    physical_t pd = alloc_frame();
    physical_t *pde = find_region(1);
    map_page(pde, pd, 0);
    // Initialize PDPT entry.
    pdpt->entry[GET_PDPTE(KERNEL_START)] = (pd << 12)| PAGE_PRESENT;
    // Mark kernel pages.
    pde[GET_PTE(KERNEL_START)] = (kernel_pages << 12) | PAGE_PRESENT;
    unmap_page(pde, false);
}

static void acquire_region(void *vr, size_t size,  uint16_t perms) {
    for (void *addr = vr; addr < vr + (size * PAGE_SIZE);
            addr += PAGE_SIZE) {
        map_page(addr, alloc_frame(), perms);
    }
}

static void release_region(struct virt_region *vr) {
    for (void *addr = vr->addr; addr < vr->addr + (vr->size * PAGE_SIZE);
            addr += PAGE_SIZE) {
        unmap_page(addr, true);
    }
}

// TODO: Make this an rb tree insertion. This is O(N) linked list insertion.
// TODO: Implement region merging.
// Lock for free list must be acquired!
static void insert_region(struct virt_region *vr) {
    struct virt_region *prev = Cur_paging->free_list;
    kassert(prev != NULL);
    struct virt_region *curs = prev;
    while (curs != NULL && vr->size < curs->size) {
        prev = curs;
        curs = curs->next;
    }
    vr->next = curs;
    prev->next = vr;
}

// TODO: Make this an rb tree walk. This is O(N) linked list traversal.
// Lock for free list must be acquired!
static void *find_region(size_t size) {
    struct virt_region *prev = NULL;
    struct virt_region *vr = Cur_paging->free_list;
    struct virt_region *closest_prev = NULL;
    struct virt_region *closest = NULL;
    size_t closest_size = SIZE_MAX;
    while (vr->next != NULL && vr->size < vr->next->size) {
        if (vr->size >= size && closest_size > vr->size - size) {
            closest_size = vr->size;
            closest = vr;
            closest_prev = prev;
        }
        prev = vr;
        vr = vr->next;
    }
    // We know that closest is not NULL if closest_prev is not NULL.
    // Remove the closest match from the linked list.
    if (closest_prev != NULL) {
        closest_prev->next = closest->next;
    }
    // If the region is too big, split it and insert the smaller end into the
    // list.
    if (closest_size > size) {
        struct virt_region *split = kmalloc(sizeof(struct virt_region));
        split->addr = closest->addr + (size * PAGE_SIZE);
        split->size = closest->size - size;
        closest->size = size;
        insert_region(split);
    }
    if (closest != NULL) {
        void *addr = closest->addr;
        kfree(closest);
        return addr;
    } else {
        return NULL;
    }
}

// Lock for free list must be acquired!
static void destroy_free_list(struct virt_region *vr) {
    struct virt_region *cur = vr;
    while (cur->next != NULL) {
        struct virt_region *next = cur;
        kfree(cur);
        cur = next;
    }
}

static struct virt_region *init_free_list(void) {
    struct virt_region *vr = kmalloc(sizeof(struct virt_region));
    vr->addr = NULL + PAGE_SIZE;
    vr->size = KERNEL_START;
    vr->next = NULL;
    return vr;
}

// ---------- Functions used for managing per process pdpts ------------
// Private to kernel

void switch_paging(struct paging_info *pi) {
    acquire_spinlock(&Cur_paging->lock);
    acquire_spinlock(&pi->lock);

    struct paging_info *old = Cur_paging;
    Cur_paging = pi;
    enable_paging(Cur_paging->phys);

    release_spinlock(&Cur_paging->lock);
    release_spinlock(&old->lock);
}

// TODO: Cache multiple paging regions onto a single physical page
struct paging_info *get_paging_info(void) {
    // Here we have to duplicate some of the work of get_region and
    // acquire_region since we need the physical address of the structure.
    void*vr = find_region(1);
    if (vr == NULL) {
        return NULL;
    }
    physical_t phys = alloc_frame();
    map_page(vr, phys, 0);
    struct paging_info *pi = vr;
    // We no longer need the region metadata.
    kfree(vr);
    init_pdpt(&pi->pdpt);
    pi->lock = SPINLOCK_INIT;
    pi->free_list = init_free_list();
    pi->phys = phys;
    return pi;
}

void put_paging_info(struct paging_info *pi) {
    // Since we destroy the structure we never unlock it!
    // Nobody else should be trying to obtain it, but if they are, hopefully
    // they deadlock!
    acquire_spinlock(&pi->lock);
    // Don't put the current page table!
    kassert(get_page_dir_ptr_table() != &pi->pdpt);
    free_pdpt(&pi->pdpt);
    destroy_free_list(pi->free_list);
    unmap_page(pi, true);
}

// ------------- Public functions for general consumption --------------------

void *get_region(size_t pages, uint16_t perms) {
    void *vr = find_region(pages);
    acquire_region(vr, pages, perms);
    return vr;
}

void put_region(void *addr, size_t pages) {
    struct virt_region *vr = kmalloc(sizeof(struct virt_region));
    vr->addr = addr;
    vr->size = pages;
    insert_region(vr);
    release_region(vr);
}
