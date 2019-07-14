/* Inspect the virtual memory address */
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
int allocate_pagetable(struct pagetable_layout_info *info, unsigned long **page_table_addr, unsigned long **fake_pgd_addr, unsigned long begin_vaddr, unsigned long end_vaddr)
{
    struct pagetable_layout_info copy_info = *info;
    /* Get the page size and the page mask */
    unsigned long page_size = 1 << (info -> page_shift);
    unsigned long page_mask = page_size - 1;
    /* Rounded the begin address and end address */
    unsigned long begin_vaddr_rounded = begin_vaddr & (~page_mask);
    unsigned long end_vaddr_rounded = end_vaddr & (~page_mask);
    /* Calculated the page nums */
    unsigned long page_nums = pgd_index(begin_vaddr_rounded - 1, copy_info) - pgd_index(end_vaddr_rounded, copy_info) + 1;

    *page_table_addr = mmap(NULL, page_size * page_nums, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    *fake_pgd_addr = malloc(sizeof(unsigned long) * page_size);
    if(!(*page_table_addr) || !(*fake_pgd_addr))
    {
        printf("Allocate memory failed\n");
        return -1;
    }
    return 0;
}

/* Free memory for page table */
int free_pagetable(struct pagetable_layout_info *info, unsigned long **page_table_addr, unsigned long **fake_pgd_addr)
{
    unsigned long page_size = 1 << (info -> page_shift);
    free(*fake_pgd_addr);
    munmap(*page_table_addr, page_size);
    return 0;
}

/* Display helper message */
void helper()
{
    printf("Usage: ./vm_insepctor pid begin_vaddr end_vaddr\n");
    printf("Example: ./vm_inspector 1 8001 9000\n");
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
    unsigned long begin_vaddr, end_vaddr;
    /* Define the return value */
    int ret;

    /* Sanity check for input arguments */
    if(argc != 4)
    {
        helper();
        return -1;
    }

    /* Convert from string to pid_t */
    pid = atoi(argv[1]);
    /* Conver from string to unsigned long with base of 16 */
    begin_vaddr = strtoul(argv[2], NULL, 16);
    end_vaddr = strtoul(argv[3], NULL, 16);

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
    allocate_pagetable(&info, &page_table_addr, &fake_pgd_addr, begin_vaddr, end_vaddr);

    /* Expose the page table */
    ret = expose_page_table(pid, fake_pgd_addr, 0, page_table_addr, begin_vaddr, end_vaddr);

    /* Rounded the begin address and end address */
    unsigned long begin_vaddr_rounded = begin_vaddr & (~page_mask);
    unsigned long end_vaddr_rounded = end_vaddr & (~page_mask);
    /* Get the begin page index and end page index */
    unsigned long pageIndex;
    unsigned long begin_pageIndex = begin_vaddr_rounded >> info.page_shift ;
    unsigned long end_pageIndex = end_vaddr_rounded >> info.page_shift;

    /* Print page number and corresponding frame number */
    printf("\nPage Index\t\tFrame Index\n");
    for(pageIndex = begin_pageIndex; pageIndex < end_pageIndex; ++pageIndex)
    {
        /* Get the pgd index */
        unsigned long pgdIndex = pgd_index(pageIndex << info.page_shift, info);

        /* Get the physical address for next level page table */
        unsigned long *pageBase = fake_pgd_addr[pgdIndex];

        if(pageBase)
        {
            /* Get physical address for this frame */
            unsigned physical_addr = pageBase[pte_index(pageIndex << info.page_shift, info)];
            /* Get physical frame number */
            unsigned long frameIndex = physical_addr >> info.page_shift;
            /* Display the message for valid page */
            if(frameIndex)
            {
                printf("0x%08lx\t\t0x%08lx\n", pageIndex, frameIndex);
            }
        }
    }


    /* Free memory space for page table */
    free_pagetable(&info, &page_table_addr, &fake_pgd_addr);

    return 0;
}