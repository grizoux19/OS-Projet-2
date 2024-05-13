#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/proc_fs.h>
#include <linux/list.h>
#include <linux/sched/signal.h>
#include <linux/mm.h>
#include <linux/mm_types.h>

#define PROC_NAME "memory_info"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Your Name");
MODULE_DESCRIPTION("Memory usage tracking module");

// Structure to store memory information for a process
struct process_info {
    pid_t pid;                  // Process ID
    unsigned long total_pages;  // Total number of pages used by the process
    struct list_head list;      // List head for linking process_info structures
};

// List to store information about zsh processes
static LIST_HEAD(process_list);

extern struct mm_struct *get_task_mm(struct task_struct *task);

extern void mmput(struct mm_struct *);

// Function to calculate total pages used by a process
unsigned long calculate_total_pages(pid_t pid) {
    struct task_struct *task;
    struct mm_struct *mm;
    unsigned long total_pages = 0;

    task = pid_task(find_vpid(pid), PIDTYPE_PID);
    if (task == NULL) {
        printk(KERN_ERR "Process with PID %d not found\n", pid);
        return 0;
    }

    mm = get_task_mm(task);
    if (mm == NULL) {
        printk(KERN_ERR "Failed to get memory information for process with PID %d\n", pid);
        return 0;
    }

    total_pages = get_mm_counter(mm, MM_ANONPAGES) +
                  get_mm_counter(mm, MM_FILEPAGES) +
                  get_mm_counter(mm, MM_SHMEMPAGES);

    mmput(mm);
    return total_pages;
}

// Function to add a process_info structure to the list
void add_process_info(pid_t pid, unsigned long total) {
    struct process_info *info = kmalloc(sizeof(struct process_info), GFP_KERNEL);
    if (!info) {
        printk(KERN_ERR "Memory allocation failed for process_info\n");
        return;
    }
    info->pid = pid;
    info->total_pages = total;
    INIT_LIST_HEAD(&info->list);
    list_add_tail(&info->list, &process_list);
}

static int __init memory_info_init(void) {
    struct task_struct *task;
    pid_t pid;

    // Retrieve PIDs of zsh processes
    for_each_process(task) {
        if (strcmp(task->comm, "zsh") == 0) {
            pid = task->pid;
            // Calculate total pages used by the process
            unsigned long total = calculate_total_pages(pid);
            // Add process information to the data structure
            add_process_info(pid, total);
        }
    }

    // Display information about zsh processes
    struct process_info *info;
    printk(KERN_INFO "List of zsh processes and their total pages:\n");
    list_for_each_entry(info, &process_list, list) {
        printk(KERN_INFO "PID: %d, Total Pages: %lu\n", info->pid, info->total_pages);
    }

    printk(KERN_INFO "Memory info module initialized\n");
    return 0;
}

// Module cleanup function
static void __exit memory_info_exit(void) {
    // Cleanup the process_list here
    printk(KERN_INFO "Memory info module removed\n");
}

module_init(memory_info_init);
module_exit(memory_info_exit);
