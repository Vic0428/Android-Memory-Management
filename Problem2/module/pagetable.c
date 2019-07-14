/* Implement two new system calls */
#include<linux/module.h>
#include<linux/kernel.h>
#include<linux/init.h>
#include<linux/sched.h>
#include<linux/unistd.h>
#include<linux/mm.h>
#include<linux/slab.h>
#include<asm/uaccess.h>
MODULE_LICENSE("Dual BSD/GPL");
#define __NR_page_layout_call 356
#define __NR_expose_page_call 357

/* The structure for the page table layout info */
struct pagetable_layout_info {
    uint32_t pgdir_shift;
    uint32_t pmd_shift;
    uint32_t page_shift; 
};

/* The structure for storing walk information */
struct walk_info
{
    unsigned long pgtb_start;
    unsigned long fake_pgd;
    unsigned long *copied_pgd;
};

static int (*oldcall)(void);
static int (*tmpcall)(void);
/**
 * This function is used to investigate the page table layout. 
 * 
 * Args:
 *      pgtbl_info: user address to store the related information
 *      size: the memory size reserved for pgtbl_info
 */
static int get_pagetable_layout(struct pagetable_layout_info __user *pgtbl_info, int size) {
    struct pagetable_layout_info layout;

    /* Sanity check */
    if (!pgtbl_info || size < sizeof(struct pagetable_layout_info)) 
    {
        printk(KERN_INFO "The size is too small for struct pagetable_layout_info. \n");
        return -1;
    }

    /* Get current page layout information */
    layout.pgdir_shift = PGDIR_SHIFT;
    layout.pmd_shift = PMD_SHIFT;
    layout.page_shift = PAGE_SHIFT;

    /* Print the page table layout information in the kernel */
    printk(KERN_INFO "The pgdir_shift is %d\n", layout.pgdir_shift);
    printk(KERN_INFO "The pmd_shift is %d\n", layout.pmd_shift);
    printk(KERN_INFO "The page_shift is %d\n", layout.page_shift);

    /* Copy the page table layout information to user space */
    if(copy_to_user(pgtbl_info, &layout, sizeof(struct pagetable_layout_info))) 
    {
        printk("Copy from kernel to user failed\n");
        return -1;
    }

    return 0;
}
/**
 * This function is used to get the task_struct of process Pid.
 * 
 * Args:
 *      pid_t process Pid
 * 
 * Return:
 *      The task_struct of process Pid
 */ 
struct task_struct* get_Pid_task(pid_t Pid) {
    /* A struct pid is the kernel internal notion of process identifier */
    struct pid *Pid_struct;
    /* The task_struct of process Pid */
    struct task_struct *Pid_task;

    /* Lookup a Pid in the hash table, and return struct pid pointer */
    Pid_struct = find_get_pid(Pid);
    /* Get the task_struct of process PID */
    Pid_task = pid_task(Pid_struct, PIDTYPE_PID);

    return Pid_task;
}

/* Call back function */
int my_pgd_entry(pmd_t *pgd, unsigned long addr, unsigned long end, struct mm_walk *walk)
{
    /* Get the page index of addr */
    unsigned long pgdIndex = pgd_index(addr);
    /* Get the page address of the pgd page */
    unsigned long pgdPage = pmd_page(*pgd);
    /* Get the physical frame number of the pgdPage */
    unsigned long pgdPfn = page_to_pfn((struct page *)pgdPage);

    /* Sanity check for invalid pgd */
    if(pgd_none(*pgd) || pgd_bad(*pgd) || !pfn_valid(pgdPfn))
    {
        printk(KERN_INFO "Invalid pgdPage!\n");
        return -1;
    }

    /* Get the walk_info struct to store information */
    struct walk_info *copy_info = walk -> private;

    /* Sanity check for invalid walk_info */
    if(!copy_info)
    {
        printk(KERN_INFO "Invalid copy_info\n");
        return -1;
    }

    /* Get current process vm_area_struct */
    struct vm_area_struct *current_vma = current -> mm -> mmap;

    /* Sanity check for invalid vm */
    if(!current_vma)
    {
        printk(KERN_INFO "Invalid user vm area!");
        return -1;
    }

    /* Remap the whole memory frame to user space */
    down_write(&current -> mm -> mmap_sem);
    int err = remap_pfn_range(current_vma, copy_info -> pgtb_start, pgdPfn, PAGE_SIZE, current_vma -> vm_page_prot);
    up_write(&current -> mm -> mmap_sem);

    /* Sanity check for remap error */
    if(err)
    {
        printk(KERN_INFO "remap_pgdPfn_range failed!\n");
        return -1;
    }

    /* Store other information in kernel space */
    copy_info -> copied_pgd[pgdIndex] = copy_info -> pgtb_start;
    copy_info -> pgtb_start += PAGE_SIZE;

    return 0;
}

/**
 * This function is used to map a target process's page table into the 
 * current process's address space. 
 * 
 * Args:
 *     pid: pid of the target process you want to investigate
 *     fake_pid: base address of the fake pgd
 *     fake_pmds: base address of the fake pmds
 *     page_table_addr: base address in user space the ptes mapped to
 *     begin_vaddr: remapped memory beginning of the target process
 *     end_vaddr: remapped memory end of the target process
 */
static int expose_page_table(pid_t Pid, unsigned long fake_pgd, unsigned long fake_pmds, unsigned long page_table_addr, unsigned long begin_vaddr, unsigned long end_vaddr) {
    printk(KERN_INFO "Syscall expose_page_table invoked!");

    struct task_struct *Pid_task = NULL;
    struct mm_struct *Pid_mm = NULL;
    struct vm_area_struct *Pid_vm = NULL;
    struct vm_area_struct *tmp_vm = NULL;
    struct mm_walk walk = {};
    struct walk_info copy_info = {};    

    /* Get the task_struct for process Pid */
    Pid_task = get_Pid_task(Pid);

    /* Sanity check for invalid process id */
    if(!Pid_task)
    {
        printk(KERN_INFO "The process id is invalid\n");
        return -1;
    }

    printk(KERN_INFO "The target process is %s.\n", Pid_task -> comm);

    /* Get the mm_struct for process Pid */
    Pid_mm = Pid_task -> mm;

    /* Sanity check for invalid Pid_mm */
    if(!Pid_mm)
    {
        printk(KERN_INFO "The memory struct is invalid\n");
        return -1;
    }

    /* Get the vm_area_struct for process Pid */
    Pid_vm = Pid_mm -> mmap;

    /* Sanity check for invalid pid_Vm */
    if(!Pid_vm)
    {
        printk(KERN_INFO "The virtual memory struct is invalid\n");
        return -1;
    }


    /* Print the virtual memory address under lock */
    down_write(&Pid_mm -> mmap_sem);
    for(tmp_vm = Pid_vm; tmp_vm ; tmp_vm = tmp_vm -> vm_next) {
        printk(KERN_INFO "0x%08lx - 0x%08lx\n", tmp_vm -> vm_start, tmp_vm -> vm_end);
    }
    up_write(&Pid_task -> mm -> mmap_sem);

    /* Configure the mm_walk struct */
    walk.mm = Pid_mm;
    walk.pgd_entry = &my_pgd_entry;

    /* Configure the walk_info struct */
    copy_info.pgtb_start = page_table_addr;
    copy_info.fake_pgd = fake_pgd;
    copy_info.copied_pgd = kcalloc(PAGE_SIZE, sizeof(unsigned long), GFP_KERNEL);

    walk.private = &copy_info;

    /* Set current vm_flags (make vm non-mergable) */
    current -> mm -> mmap -> vm_flags |= VM_SPECIAL;

    /* Walk the page table recursively with our callback function */
    down_write(&Pid_mm -> mmap_sem);
    if(walk_page_range(begin_vaddr, end_vaddr, &walk))
    {
        printk(KERN_INFO "Walk failed\n");
        up_write(&Pid_task -> mm -> mmap_sem);
        return -1;
    }
    up_write(&Pid_task -> mm -> mmap_sem);

    /* Copy to user and sanity check */
    if(copy_to_user(fake_pgd, copy_info.copied_pgd, sizeof(unsigned long) * PAGE_SIZE))
    {
        printk(KERN_INFO "Copy to user failed\n");
        return -1;
    }


    /* Free the kernel space */
    kfree(copy_info.copied_pgd);
    
    /* Print the successful exit information */
    printk(KERN_INFO "Syscall expose_page_table exited!");
    return 0;

}

static int addsyscall_init(void) 
{
    long *syscall = (long*)0xc000d8c4;

    printk(KERN_INFO "module load!\n");

    oldcall = (int(*)(void))(syscall[__NR_page_layout_call]);
    syscall[__NR_page_layout_call] = (unsigned long)get_pagetable_layout;
    printk(KERN_INFO "Add get_pagetable_layout system call!\n");

    tmpcall = (int(*)(void))(syscall[__NR_expose_page_call]);
    syscall[__NR_expose_page_call] = (unsigned long)expose_page_table;
    printk(KERN_INFO "Add expose_page_table system call!\n");

    return 0;
}

static void addsyscall_exit(void) 
{
    long *syscall = (long*)0xc000d8c4;

    printk(KERN_INFO "Remove get_pagetable_layout system call!\n");
    syscall[__NR_page_layout_call] = (unsigned long)oldcall;

    printk(KERN_INFO "Remove expose_page_table system call!\n");
    syscall[__NR_expose_page_call] = (unsigned long)tmpcall;
    
    printk(KERN_INFO "module exit!\n");
}


module_init(addsyscall_init);
module_exit(addsyscall_exit);