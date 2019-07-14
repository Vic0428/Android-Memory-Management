/* Translate from virtual address to physical address */
#include<unistd.h>
#include <stdio.h>
#include <sys/mman.h>
#define pgd_index(va, info) ((va) >> info.pgdir_shift)
#define pte_index(va, info) (((va) >> info.page_shift)&((1 << (info.pmd_shift - info.page_shift)) - 1))
#define syscall_get_layout 356
#define syscall_expose 357

/* The page table layout struct */
struct pagetable_layout_info {
    uint32_t pgdir_shift;
    uint32_t pmd_shift;
    uint32_t page_shift; 
};
/* Call expose_page_table system call */
int expose_page_table(pid_t Pid, unsigned long fake_pgd, unsigned long fake_pmds, unsigned long page_table_addr, 
unsigned long begin_vaddr, unsigned long end_vaddr) {
    return syscall(syscall_expose, Pid, fake_pgd, fake_pmds, page_table_addr, begin_vaddr, end_vaddr);
}

/* Call get_pagetable_layout system call */
int get_pagetable_layout(struct pagetable_layout_info *pgtbl_info, int size) {
    return syscall(syscall_get_layout, pgtbl_info, size);
}

/* Display the pagetable layout info */
int display_layout(struct pagetable_layout_info *info)
{
    /* Sanity check for null pointer */
    if(!info)
    {
        printf("Invalid pagetable_layout_info structure\n");
        return -1;
    }
    printf("pgdir_shift: %d, pmd_shift: %d, page_shift: %d\n", info -> pgdir_shift, info -> pmd_shift, info -> page_shift);
    return 0;
}

/* Allocate memory for page table */
int allocate_pagetable(struct pagetable_layout_info *info, unsigned long **page_table_addr, unsigned long **fake_pgd_addr)
{
    unsigned long page_size = 1 << (info -> page_shift);
    *page_table_addr = mmap(NULL, page_size, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    *fake_pgd_addr = malloc(sizeof(unsigned long) * page_size);
    if(!(*page_table_addr) || !(*fake_pgd_addr))
    {
        printf("Allocate memory failed\n");
        return -1;
    }
    printf("Allocate momemory for page table successfully\n");
    return 0;
}

/* Free memory for page table */
int free_pagetable(struct pagetable_layout_info *info, unsigned long **page_table_addr, unsigned long **fake_pgd_addr)
{
    unsigned long page_size = 1 << (info -> page_shift);
    free(*fake_pgd_addr);
    munmap(*page_table_addr, page_size);
    printf("Free memory for page table successfully\n");
    return 0;
}

/* Display helper message */
void helper()
{
    printf("Usage: ./VATranslate pid virtual_addr\n");
    printf("Example: ./VATranslate 1 8001\n");
}
int main(int argc, char **argv) {
    /* The process id */
    pid_t pid;
    /* info stores the pagetable layout information */
    struct pagetable_layout_info info;
    /* Define the page_size and the page_mask */
    unsigned long page_size, page_mask;
    /* Define the address for page table */
    unsigned long *page_table_addr, *fake_pgd_addr;
    /* Define the virtual memory address */
    unsigned long va;
    /* Define the return value */
    int ret;

    /* Sanity check for input arguments */
    if(argc != 3)
    {
        helper();
        return -1;
    }

    /* Convert from string to pid_t */
    pid = atoi(argv[1]);
    /* Conver from string to unsigned long with base of 16 */
    va = strtoul(argv[2], NULL, 16);

    /* Sanity check for error */
    if(get_pagetable_layout(&info, sizeof(struct pagetable_layout_info)))
    {
        printf("System call get_pagetable_layout failed\n");
        return -1;
    }
    /* Display the info for pagetable layout */
    display_layout(&info);

    /* Get the page size and the page_mask */
    page_size = 1 << (info.page_shift);
    page_mask = page_size - 1;

    /* Allocate memory space for page table */
    allocate_pagetable(&info, &page_table_addr, &fake_pgd_addr);

    /* Expose the page table */
    ret = expose_page_table(pid, fake_pgd_addr, 0, page_table_addr, va, va + 1);

    /* Get the pagetable index */
    unsigned long pgdIndex = pgd_index(va, info);
    /* Get the physical address for the pgdIndex */
    unsigned long* pgdBase = fake_pgd_addr[pgdIndex];

    /* Sanity check */
    if(!pgdBase)
        printf("Virtual address:0x%08lx is not in the memory.\n", va);
    else 
    {
        /* Get the physical address for the page table entry */
        unsigned long physical_addr = pgdBase[pte_index(va, info)];
        
        /* Mask the lower bit of the entry */
        physical_addr = physical_addr & (~page_mask);
        /* Sanity check */
        if(!physical_addr)
            printf("Virtual address: 0x%08lx is not in the memory\n", va);
        else 
        {
            physical_addr  = (va & page_mask) | physical_addr;
            printf("virtural address:0x%08lx ===> physical address:0x%08lx\n", va, physical_addr);
        }
    }

    /* Free memory space for page table */
    free_pagetable(&info, &page_table_addr, &fake_pgd_addr);

    return 0;
}