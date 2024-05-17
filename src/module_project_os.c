#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/proc_fs.h>
#include <linux/uaccess.h>
#include <linux/string.h>
#include <linux/sched.h>
#include <linux/sched/signal.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/seq_file.h>
#include <linux/sched/mm.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/ksm.h>
#include <linux/highmem.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <linux/pid.h>
#include <linux/sched/task.h>
#include <linux/mm_types.h>
#include <asm/page.h>
#include <linux/hashtable.h>
#include <linux/crypto.h>
#include <crypto/hash.h>
#include <crypto/sha.h>

#define PROC_NAME "memory_info"
#define MAX_PROCESS_NAME_LEN 256

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Bowser & Ogre");
MODULE_DESCRIPTION("Module pour l'information sur la mémoire");

struct process_info *info;
static int num_processes = 0;

struct process_info
{
    pid_t pid[10];
    unsigned long total_pages;
    unsigned long valid_pages;
    unsigned long invalid_pages;
    unsigned long nb_group;
    unsigned long identical_page_groups;
    unsigned long may_be_shared;
    char name[255];
};

static void retrieve_process_info(void);
static void detect_identical_pages(void);

static char proc_buffer[65536]; // Tampon pour stocker les données du fichier proc
int compare_pages(struct page *page1, struct page *page2);
struct page *get_page_by_vaddr(struct mm_struct *mm, unsigned long vaddr);
void compare_pages_within_process(struct mm_struct *mm, int index);
unsigned long count_valid_pages(struct mm_struct *mm);

unsigned long count_valid_pages(struct mm_struct *mm) {
    struct vm_area_struct *vma;
    unsigned long address;
    unsigned long valid_pages = 0;
    
    // Obtenir le sémaphore de mémoire pour éviter les conditions de course
    down_read(&mm->mmap_sem);

    // Parcourir chaque VMA
    for (vma = mm->mmap; vma; vma = vma->vm_next) {
        pgd_t *pgd;
        p4d_t *p4d;
        pud_t *pud;
        pmd_t *pmd;
        pte_t *pte;
        spinlock_t *ptl;
        
        // Parcourir les adresses de page dans cette VMA
        for (address = vma->vm_start; address < vma->vm_end; address += PAGE_SIZE) {
            pgd = pgd_offset(mm, address);
            if (pgd_none(*pgd) || pgd_bad(*pgd))
                continue;

            p4d = p4d_offset(pgd, address);
            if (p4d_none(*p4d) || p4d_bad(*p4d))
                continue;

            pud = pud_offset(p4d, address);
            if (pud_none(*pud) || pud_bad(*pud))
                continue;

            pmd = pmd_offset(pud, address);
            if (pmd_none(*pmd) || pmd_bad(*pmd))
                continue;

            if (pmd_trans_huge(*pmd)) {
                if (pmd_present(*pmd))
                    valid_pages++;
                continue;
            }

            pte = pte_offset_map_lock(mm, pmd, address, &ptl);
            if (!pte)
                continue;

            if (pte_present(*pte))
                valid_pages++;

            pte_unmap_unlock(pte, ptl);
        }
    }

    // Libérer le sémaphore de mémoire
    up_read(&mm->mmap_sem);

    return valid_pages;
}

void retrieve_processes_by_name(const int index, char *buffer, size_t buffer_size)
{
    int offset = 0;
    int j;

    // Ajouter les informations de ce processus au buffer
    // buf_pttr + offset ->popinteur vers la position actuel
    // sizeof(buffer) - offset -> espace restant dans le buffer
    offset += snprintf(buffer + offset, buffer_size - offset,
                       "%s, total: %lu, valid: %lu, invalid: %lu, may_be_shared: %lu, nb_group: %lu, pid(%lu): ",
                       info[index].name, info[index].total_pages, info[index].valid_pages,
                       info[index].invalid_pages, info[index].may_be_shared,
                       info[index].nb_group, info[index].identical_page_groups + 1);
    for (j = 0; j <= info[index].identical_page_groups; j++)
    {
        offset += snprintf(buffer + offset, buffer_size - offset, "%d", info[index].pid[j]);
        if (j < info[index].identical_page_groups)
        { // Ajoute un ; sauf au dernier
            offset += snprintf(buffer + offset, buffer_size - offset, "; ");
        }
    }
    offset += snprintf(buffer + offset, buffer_size - offset, "\n"); // ajout de retour à la ligne
}

static ssize_t write_proc(struct file *file, const char __user *buffer, size_t count, loff_t *pos)
{
    bool delete_success = false;
    char process_name[MAX_PROCESS_NAME_LEN];
    char *pipe_position;
    bool filter_success = false;
    int i;
    int name_size = 0;

    // Vérifie si les données écrites dépassent la taille du tampon
    if (count >= sizeof(proc_buffer))
    {
        return -EINVAL;
    }

    // Copie les données du buffer utilisateur vers le tampon du fichier proc
    if (copy_from_user(proc_buffer, buffer, count))
    {
        return -EFAULT;
    }

    // Ajoute un caractère nul à la fin des données pour s'assurer qu'elles sont bien terminées
    // proc_buffer[count] = '\0';

    // Affiche les données du buffer dans les logs du noyau

    // Si les données écrites sont "echo" suivi de "Bonjour", écrivez "Bonjour" dans le fichier proc

    if (strncmp(proc_buffer, "FILTER", 6) == 0)
    {

        // Trouver le premier '|' dans proc_buffer
        pipe_position = strchr(proc_buffer, '|');

        // Vérifier si le '|' a été trouvé et s'il y a du texte après
        if (pipe_position != NULL && *(pipe_position + 1) != '\0' && *(pipe_position + 1) != '\n')
        {
            // Copy characters after '|' until newline or null terminator
            for (i = 0; i < MAX_PROCESS_NAME_LEN - 1; i++)
            {
                if (pipe_position[i + 1] == '\n' || pipe_position[i + 1] == '\0')
                {
                    break;
                }
                process_name[i] = pipe_position[i + 1];
                name_size++;
            }
            process_name[name_size] = '\0'; // Ensure null termination
        }

        else
        {
            return -EINVAL;
        }

        for (i = 0; i < num_processes; i++)
        {
            if (strncmp(info[i].name, process_name, strlen(process_name)) == 0)
            {
                char *process_info = kmalloc(4096 * sizeof(char), GFP_KERNEL);
                retrieve_processes_by_name(i, process_info, 4096);
                if (process_info != NULL)
                {
                    filter_success = true;
                    snprintf(proc_buffer, sizeof(proc_buffer), process_info);
                }
            }
        }

        if (!filter_success)
        {
            snprintf(proc_buffer, sizeof(proc_buffer), "[ERROR]: No such process\n");
        }

        // Renvoie la longueur de la chaîne "Bonjour" comme le nombre d'octets écrit
    }
    else if (strncmp(proc_buffer, "DEL", 3) == 0)
    {
        pipe_position = strchr(proc_buffer, '|');

        // Vérifier si le '|' a été trouvé et s'il y a du texte après
        if (pipe_position != NULL && *(pipe_position + 1) != '\0' && *(pipe_position + 1) != '\n')
        {
            // Copy characters after '|' until newline or null terminator
            for (i = 0; i < MAX_PROCESS_NAME_LEN - 1; i++)
            {
                if (pipe_position[i + 1] == '\n' || pipe_position[i + 1] == '\0')
                {
                    break;
                }
                process_name[i] = pipe_position[i + 1];
                name_size++;
            }
            process_name[name_size] = '\0';
        }
        for (i = 0; i < num_processes; i++)
        {
            if (strncmp(info[i].name, process_name, strlen(process_name)) == 0)
            {
                // Supprimer le processus trouvé en décalant les éléments suivants dans le tableau

                memmove(&info[i], &info[i + 1], (num_processes - i - 1) * sizeof(struct process_info));
                // Décrémenter le nombre total de processus
                delete_success = true;
                num_processes--;
                break; // Sortir de la boucle une fois que le processus est supprimé
            }
        }
        memset(proc_buffer, '\0', sizeof(proc_buffer));
        if (delete_success)
        {

            snprintf(proc_buffer, sizeof(proc_buffer), "[SUCCESS]\n");
        }
        else
        {
            snprintf(proc_buffer, sizeof(proc_buffer), "[ERROR]\n");
        }
    }
    else if (strncmp(proc_buffer, "ALL", 3) == 0)
    {
        char *process_info = kmalloc(4096 * sizeof(char), GFP_KERNEL);
        memset(proc_buffer, '\0', sizeof(proc_buffer));

        for (i = 0; i < num_processes; i++)
        {
            retrieve_processes_by_name(i, process_info, 4096);
            if (i == 0)
            {
                strcpy(proc_buffer, process_info);
            }
            else
            {
                strcat(proc_buffer, process_info);
            }
        }
    }
    else if (strncmp(proc_buffer, "RESET", 5) == 0)
    {
        retrieve_process_info();
        detect_identical_pages();
        memset(proc_buffer, '\0', sizeof(proc_buffer));
        snprintf(proc_buffer, sizeof(proc_buffer), "[SUCCESS]\n");
    }
    else
    {
        snprintf(proc_buffer, sizeof(proc_buffer), "[ERROR]: Invalid argument\n");
    }

    // Renvoie le nombre d'octets écrits
    return count;
}

static ssize_t read_proc(struct file *file, char __user *buffer, size_t count, loff_t *pos)
{
    size_t bytes_to_copy;
    size_t remaining_bytes;
    // Vérifie si la position est en dehors des limites du tampon
    if (*pos >= strlen(proc_buffer))
    {
        // Si la position est au-delà de la fin du fichier, indique la fin de fichier (EOF)
        return 0;
    }

    // Détermine la quantité de données à copier dans le buffer utilisateur
    remaining_bytes = strlen(proc_buffer) - *pos;
    bytes_to_copy = count < remaining_bytes ? count : remaining_bytes;

    // Copie les données du tampon du fichier proc vers le buffer utilisateur
    if (copy_to_user(buffer, proc_buffer + *pos, bytes_to_copy))
    {
        return -EFAULT;
    }

    // Met à jour la position de fichier pour refléter le nombre d'octets lus
    *pos += bytes_to_copy;

    // Renvoie le nombre d'octets lus
    return bytes_to_copy;
}

// Définit les opérations de fichier pour le fichier proc
static const struct file_operations proc_fops = {
    .write = write_proc,
    .read = read_proc,
};


static void retrieve_process_info(void)
{
    struct task_struct *task;
    struct mm_struct *mm;
    num_processes = 0;
    // Libérer l'ancienne mémoire si nécessaire
    if (info != NULL)
    {
        kfree(info);
        info = NULL;
    }

    // Parcourir la liste des processus
    for_each_process(task)
    {
        int i;
        int found = 0;
        printk(KERN_INFO "Nom du processus: %s, PID: %d\n", task->comm, task->pid);

        // Vérifier si le nom du processus existe déjà dans la structure
        for (i = 0; i < num_processes; i++)
        {
            if (strcmp(task->comm, info[i].name) == 0)
            {
                // Le nom du processus existe déjà, mettre à jour les valeurs
                info[i].total_pages += task->mm->total_vm;
                info[i].valid_pages += count_valid_pages(task->mm);
                info[i].invalid_pages = info[i].total_pages - info[i].valid_pages;

                // Ajouter le PID au tableau dynamique
                //info[i].pid = krealloc(info[i].pid, (info[i].identical_page_groups + 2) * sizeof(pid_t), GFP_KERNEL);
                // (!info[i].pid)
                //{
                //    printk(KERN_ERR "Erreur d'allocation de mémoire pour les PID\n");
                //    return;
                //}
                info[i].pid[info[i].identical_page_groups + 1] = task->pid;
                info[i].identical_page_groups++;
                found = 1;
                break;
            }
        }

        if (!found)
        {
            if(task->mm)
            {
                printk(KERN_INFO "PAS TROUVE \n");
                // Le nom du processus n'existe pas encore, ajouter une nouvelle entrée
                if (num_processes == 0)
                {
                    printk(KERN_INFO "Allocation de mémoire pour la structure info\n");
                    info = kmalloc(sizeof(struct process_info), GFP_KERNEL);
                }
                else
                {
                    printk(KERN_INFO "Réalocation de mémoire pour la structure info\n");
                    info = krealloc(info, (num_processes + 1) * sizeof(struct process_info), GFP_KERNEL);
                }

                if (!info)
                {
                    printk(KERN_ERR "Erreur d'allocation de mémoire pour la structure info\n");
                    return;
                }

                strncpy(info[num_processes].name, task->comm, sizeof(info[num_processes].name) - 1);
                info[num_processes].name[sizeof(info[num_processes].name) - 1] = '\0'; // Assurez-vous de la terminaison
                printk(KERN_INFO "Nom du processus copié\n");

                mm = task->mm;
                if (mm != NULL)
                {
                    info[num_processes].total_pages = mm->total_vm;
                    info[num_processes].valid_pages = count_valid_pages(task->mm);
                    info[num_processes].invalid_pages = info[num_processes].total_pages - info[num_processes].valid_pages;
                }
                else
                {
                    info[num_processes].total_pages = 0;
                    info[num_processes].valid_pages = 0;
                    info[num_processes].invalid_pages = 0;
                }

                info[num_processes].nb_group = 0;
                info[num_processes].identical_page_groups = 0;
                info[num_processes].may_be_shared = 0;
                //info[num_processes].pid = kmalloc(sizeof(pid_t), GFP_KERNEL);
                //if (!info[num_processes].pid)
                //{
                //    printk(KERN_ERR "Erreur d'allocation de mémoire pour les PID\n");
                //    return;
                //}
                info[num_processes].pid[0] = task->pid;
                num_processes++;
            }
        }
    }
}

struct page *get_page_by_vaddr(struct mm_struct *mm, unsigned long vaddr)
{
    pgd_t *pgd;
    p4d_t *p4d;
    pud_t *pud;
    pmd_t *pmd;
    pte_t *ptep, pte;
    struct page *page = NULL;

    pgd = pgd_offset(mm, vaddr);
    if (pgd_none(*pgd) || pgd_bad(*pgd))
        return NULL;

    p4d = p4d_offset(pgd, vaddr);
    if (p4d_none(*p4d) || p4d_bad(*p4d))
        return NULL;

    pud = pud_offset(p4d, vaddr);
    if (pud_none(*pud) || pud_bad(*pud))
        return NULL;

    pmd = pmd_offset(pud, vaddr);
    if (pmd_none(*pmd) || pmd_bad(*pmd))
        return NULL;

    ptep = pte_offset_map(pmd, vaddr);
    if (!ptep)
        return NULL;

    pte = *ptep;
    if (!pte_present(pte))
        return NULL;

    page = pte_page(pte);
    pte_unmap(ptep);

    return page;
}

int compare_pages(struct page *page1, struct page *page2)
{
    return page_to_pfn(page1) == page_to_pfn(page2);

    char *buf1, *buf2;
    void *mapped_page1, *mapped_page2;
    int result = 0;
    // Vérifie si les pages sont valides
    if (!page1 || !page2)
    {
        return -EINVAL;
    }
    // Alloue un tampon pour stocker le contenu des pages
    buf1 = kmalloc(PAGE_SIZE, GFP_KERNEL);
    buf2 = kmalloc(PAGE_SIZE, GFP_KERNEL);
    if (!buf1 || !buf2)
    {
        kfree(buf1);
        kfree(buf2);
        return -ENOMEM;
    }
    // Mappe les pages en mémoire
    mapped_page1 = kmap(page1);
    mapped_page2 = kmap(page2);
    if (!mapped_page1 || !mapped_page2)
    {
        result = -EFAULT;
        goto out_unmap;
    }
    // Copie le contenu des pages dans les tampons
    memcpy(buf1, mapped_page1, PAGE_SIZE);
    memcpy(buf2, mapped_page2, PAGE_SIZE);
    // Compare le contenu des tampons
    if (memcmp(buf1, buf2, PAGE_SIZE) == 0)
    {
        result = 1;
    }
    else
    {
        result = 0;
    }

out_unmap:
    if (mapped_page1)
        kunmap(page1);
    if (mapped_page2)
        kunmap(page2);
    kfree(buf1);
    kfree(buf2);
    
    return result;
    return 0;
}

unsigned long list_page[15000];
int list_length = 0;
bool find_list = false;
DEFINE_HASHTABLE(page_table, 16);



struct page_node {
    struct page *page;
    struct hlist_node hnode;
    char hash[SHA1_DIGEST_SIZE];  // Store the hash of the page data
};

void compare_pages_within_process(struct mm_struct *mm, int index)
{
    struct vm_area_struct *vma1;
    struct shash_desc *shash;
    struct crypto_shash *alg;

    char *hash = kmalloc(SHA1_DIGEST_SIZE, GFP_KERNEL);
    if (!hash) {
        printk(KERN_ERR "Failed to allocate memory for hash\n");
        return;  // or return; depending on your logic
    }


    alg = crypto_alloc_shash("sha1", 0, 0);
    if (IS_ERR(alg)) {
        printk(KERN_ERR "Failed to allocate sha1 algorithm\n");
        return;
    }

    shash = kmalloc(sizeof(*shash) + crypto_shash_descsize(alg), GFP_KERNEL);
    if (!shash) {
        printk(KERN_ERR "Failed to allocate shash\n");
        crypto_free_shash(alg);
        return;
    }

    shash->tfm = alg;
    shash->flags = 0;

    for (vma1 = mm->mmap; vma1; vma1 = vma1->vm_next)
    {
        if (vma1->vm_flags & VM_READ || vma1->vm_flags & VM_WRITE || vma1->vm_flags & VM_EXEC || vma1->vm_flags & VM_SHARED)
        {
            unsigned long addr;
            for (addr = vma1->vm_start; addr < vma1->vm_end; addr += PAGE_SIZE) {
                struct page *page1 = get_page_by_vaddr(mm, addr);
                if (!page1) {
                    printk(KERN_ERR "Impossible de récupérer la page pour l'adresse virtuelle\n");
                    continue;
                }

                void *data = kmap(page1);
                if (!data) {
                    printk(KERN_ERR "Failed to map page data\n");
                    continue;
                }

                if (crypto_shash_digest(shash, data, PAGE_SIZE, hash) != 0) {
                    printk(KERN_ERR "Failed to compute hash of page data\n");
                    kunmap(page1);
                    continue;
                }

                kunmap(page1);

                struct page_node *pnode;
                bool find_list = false;
                hash_for_each_possible(page_table, pnode, hnode, *(unsigned long *)hash) {
                    if (memcmp(pnode->hash, hash, SHA1_DIGEST_SIZE) == 0) {
                        printk(KERN_INFO "Identical page found");
                        find_list = true;
                        info[index].may_be_shared++;
                        break;
                    }
                }

                if (!find_list) {
                    pnode = kmalloc(sizeof(*pnode), GFP_KERNEL);
                    if (!pnode) {
                        printk(KERN_ERR "Failed to allocate memory for page_node\n");
                        return;
                    }
                    pnode->page = page1;
                    memcpy(pnode->hash, hash, SHA1_DIGEST_SIZE);
                    hash_add(page_table, &pnode->hnode, *(unsigned long *)hash);
                    info[index].nb_group++;
                    info[index].may_be_shared++;
                }
            }
        }
    }

    kfree(shash);
    crypto_free_shash(alg);
}

void detect_identical_pages()
{
    int i, j, k;

    for (i = 0; i < num_processes; i++)
    {
        struct mm_struct *mm1 = NULL;
        struct mm_struct *mm2 = NULL;
        struct vm_area_struct *vma1, *vma2;
        struct task_struct *task;
        int result = 0;

        //list_page = NULL;
        list_length = 0;

        find_list = false;

        /*list_page = kmalloc(sizeof(unsigned long), GFP_KERNEL);
        if (!list_page)
        {
            // Gestion de l'erreur d'allocation de mémoire
            return;
        }*/
        //list_length++;
        for(j = 0; j <= info[i].identical_page_groups; j++)
        {
            printk(KERN_INFO "Je suis au début du for \n");
            printk(KERN_INFO "Je print le PID %d\n", info[i].pid[j]);
            task = pid_task(find_vpid(info[i].pid[j]), PIDTYPE_PID); // On récupère le premier PID
            if (task)
            {
                mm1 = get_task_mm(task);
                if (mm1)
                {
                    compare_pages_within_process(mm1, i);
                    printk(KERN_INFO "Je passe aus process suivant");
                    
                    mmput(mm1);
                }
            }
            printk(KERN_INFO "Je suis à la fin du for \n");
        }
        printk(KERN_INFO "Je vais free le tableau \n");
        /*for(j = 0; j < list_length; j++)
            list_page[j] = 0;*/
        printk(KERN_INFO "J'ai free le tableau \n");
    }
}

// Fonction d'initialisation du module
static int __init process_info_init(void)
{
    // Créer le fichier proc pour afficher les informations sur les processus
    if (!proc_create(PROC_NAME, 0666, NULL, &proc_fops))
    {
        printk(KERN_ALERT "Erreur lors de la création du fichier proc\n");
        return -ENOMEM;
    }

    printk(KERN_INFO "Initialisation de la structure\n");
    // Récupérer les informations sur les processus lors de l'initialisation
    retrieve_process_info();

    // Pages identical
    printk(KERN_INFO "Détection des pages identiques\n");
    detect_identical_pages();

    printk(KERN_INFO "Module de memory info du fichier proc initialisé\n");
    return 0;
}

static void __exit proc_exit(void)
{
    // Supprime le fichier proc lors du déchargement du module
    remove_proc_entry(PROC_NAME, NULL);
    printk(KERN_INFO "Module de memory info du fichier proc déchargé\n");
}

module_init(process_info_init);
module_exit(proc_exit);
