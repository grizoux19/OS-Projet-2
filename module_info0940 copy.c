#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/proc_fs.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/list.h>
#include <linux/sched/signal.h>

#define PROC_NAME "memory_info"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Your Name");
MODULE_DESCRIPTION("Memory usage tracking module");

// Structure to store memory information for a process
struct process_info {
    pid_t pid;                  // Process ID
    char name[64];              // Process name
    unsigned long total_pages;  // Total number of pages used by the process
    unsigned long valid_pages;  // Number of valid pages (present in RAM)
    unsigned long invalid_pages; // Number of invalid pages (not present in RAM)
    unsigned long shareable_pages; // Number of read-only pages that may be shared
    unsigned int group_count;   // Number of groups of identical read-only pages
    struct list_head list;      // List head for linking process_info structures
};

struct q1 {
    unsigned long total_pages;
};

// List to store information about all processes
static LIST_HEAD(process_list);

// Function to add a process_info structure to the list
void add_process_info(pid_t pid, const char *name, unsigned long total, unsigned long valid,
                      unsigned long invalid, unsigned long shareable, unsigned int group_count) {
    struct process_info *info = kmalloc(sizeof(struct process_info), GFP_KERNEL);
    if (!info) {
        printk(KERN_ERR "Memory allocation failed for process_info\n");
        return;
    }
    info->pid = pid;
    strncpy(info->name, name, sizeof(info->name));
    info->total_pages = total;
    info->valid_pages = valid;
    info->invalid_pages = invalid;
    info->shareable_pages = shareable;
    info->group_count = group_count;
    INIT_LIST_HEAD(&info->list);
    list_add_tail(&info->list, &process_list);
}

void display_all_processes(void) {
    struct process_info *info;
    
    printk(KERN_INFO "List of all processes:\n");
    
    list_for_each_entry(info, &process_list, list) {
        printk(KERN_INFO "PID: %d, Name: %s\n", info->pid, info->name);
    }
}

unsigned long calculate_total_pages(void) {
    struct task_struct *task;
    unsigned long total_pages_used = 0;
    
    // Iterate through all processes
    for_each_process(task) {
        if (task->mm) {
            // Add the total number of virtual pages used by the process to the total count
            total_pages_used += task->mm->total_vm;
        }
    }
    
    return total_pages_used;
}

static int __init memory_info_init(void) {
    struct task_struct *task;
    
    // Iterate through all processes
    for_each_process(task) {
        // Add process information to the data structure
        add_process_info(task->pid, task->comm, 0, 0, 0, 0, 0);
        // You may need to collect more information about each process here
    }
    display_all_processes();

    unsigned long total_pages = calculate_total_pages();
    printk(KERN_INFO "Total number of pages used by all processes: %lu\n", total_pages);
    
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
