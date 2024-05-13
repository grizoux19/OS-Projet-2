#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/proc_fs.h>
#include <linux/uaccess.h>
#include <linux/string.h>
#include <linux/sched.h>
#include <linux/sched/signal.h>
#include <linux/mm.h>
#include <linux/slab.h>:
#include <linux/seq_file.h>
#include <linux/sched/mm.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/ksm.h>

#define PROC_NAME "module_info0940"
#define MAX_PROCESS_NAME_LEN 256

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Votre Nom");
MODULE_DESCRIPTION("Module de test pour /proc");

struct process_info *info;
static int num_processes = 0;

struct process_info {
    pid_t *pid;
    unsigned long total_pages;
    unsigned long valid_pages;
    unsigned long invalid_pages;
    unsigned long readonly_pages;
    unsigned int identical_page_groups;
    char name[255];
};

static void retrieve_process_info(void);
static void detect_identical_pages(void);


static char proc_buffer[1024]; // Tampon pour stocker les données du fichier proc
static char kernel_buffer[1024];

void retrieve_processes_by_name(const char *name) {
    struct task_struct *task;

    size_t name_length = strlen(name);
    name_length -= 1;
    
    printk(KERN_INFO "Name length : %d\n", name_length);
    printk(KERN_INFO "Info number : %d\n", num_processes);

    int i;
    for(i=0; i< num_processes; i++) {
        printk(KERN_INFO "Je print i et le nom : %d : %c\n", i, info[i].name);

        char *process_name = info[i].name;
        // Afficher chaque caractère du nom du processus
        int j;
        for (j = 0; j < strlen(process_name); j++) {
            printk(KERN_INFO "Nom : %c\n", process_name[j]);
        }
        printk(KERN_INFO "\n");

        if (strncmp(info[i].name, name, name_length) == 0) {
            // Faire quelque chose avec le processus, par exemple l'afficher
            printk(KERN_INFO "Processus trouvé : PID = %d, Nom = %s\n", info[i].pid, info[i].name);
        }
    }
}

static ssize_t write_proc(struct file *file, const char __user *buffer, size_t count, loff_t *pos) {
    // Vérifie si les données écrites dépassent la taille du tampon
    if (count >= sizeof(proc_buffer)) {
        printk(KERN_ALERT "Trop de données pour écrire dans le fichier proc\n");
        return -EINVAL;
    }

    // Copie les données du buffer utilisateur vers le tampon du fichier proc
    if (copy_from_user(proc_buffer, buffer, count)) {
        return -EFAULT;
    }

    // Ajoute un caractère nul à la fin des données pour s'assurer qu'elles sont bien terminées
    //proc_buffer[count] = '\0';

    // Affiche les données du buffer dans les logs du noyau
    printk(KERN_INFO "Données écrites dans le fichier proc: %s\n", proc_buffer);

    // Si les données écrites sont "echo" suivi de "Bonjour", écrivez "Bonjour" dans le fichier proc
    if (strncmp(proc_buffer, "FILTER", 6) == 0) {
        printk(KERN_INFO "Je suis dans le filter\n");
        // Efface le contenu précédent du fichier proc
        char process_name[MAX_PROCESS_NAME_LEN];
        // Trouver le premier '|' dans proc_buffer
        char *pipe_position = strchr(proc_buffer, '|');

        // Vérifier si le '|' a été trouvé et s'il y a du texte après
        if (pipe_position != NULL && *(pipe_position + 1) != '\0') {
            // Copier le texte après '|' dans process_name
            strcpy(proc_buffer, pipe_position + 1);
        }


        printk(KERN_INFO "J'affiche process_name: %s\n", proc_buffer);
        printk(KERN_INFO "Je print la longueue de la chaine : %d\n", strlen(proc_buffer));
        size_t len = strlen(process_name);

        size_t i;
            for (i = 0; i < strlen(proc_buffer); ++i) {
                char current_char = proc_buffer[i];
                printk(KERN_INFO "Je print les caracs : %c\n", current_char);
                
            }
        retrieve_processes_by_name(proc_buffer);
        // Renvoie la longueur de la chaîne "Bonjour" comme le nombre d'octets écrit        
    }
    if (strncmp(proc_buffer, "DEL", 3) == 0) {
        printk(KERN_INFO "Je suis dans le delete\n");
        // Efface le contenu précédent du fichier proc
        char process_name[MAX_PROCESS_NAME_LEN];
        // Trouver le premier '|' dans proc_buffer
        char *pipe_position = strchr(proc_buffer, '|');

        // Vérifier si le '|' a été trouvé et s'il y a du texte après
        if (pipe_position != NULL && *(pipe_position + 1) != '\0') {
            // Copier le texte après '|' dans process_name
            strcpy(proc_buffer, pipe_position + 1);
        }

        int i;
        for (i = 0; i < num_processes; ++i) {
            size_t proc_buffer_length = strlen(proc_buffer);
            proc_buffer_length -= 1;
            printk(KERN_INFO "PID: %d, Nom: %s\n", info[i].pid, info[i].name);
            if (strncmp(info[i].name, proc_buffer, proc_buffer_length) == 0 && strlen(info[i].name) == proc_buffer_length) {
                // Supprimer le processus trouvé en décalant les éléments suivants dans le tableau
                printk(KERN_INFO "Processus trouvé : PID = %d, Nom = %s\n", info[i].pid, info[i].name);

                memmove(&info[i], &info[i + 1], (num_processes - i - 1) * sizeof(struct process_info));
                // Décrémenter le nombre total de processus
                num_processes--;
                break; // Sortir de la boucle une fois que le processus est supprimé
            }
        }
    }
    if (strncmp(proc_buffer, "ALL", 3) == 0) {
        printk(KERN_INFO "Je suis dans le all\n");
        printk(KERN_INFO "Nombre de processus : %d\n", num_processes);
        int i,j;

        size_t bytes_written = 0;
        ssize_t ret;
        for(i = 0; i < num_processes; i++) {
            
            printk(KERN_INFO "PID: %d, Nom: %s\n", info[i].pid, info[i].name);

            for (j = 0; j < info[i].identical_page_groups; j++) {
                printk(KERN_INFO "PID(%d): %d\n", j+1, info[i].pid[j]);
            }
            //int len = snprintf(proc_buffer + bytes_written, sizeof(proc_buffer) - bytes_written, "[%lu] PID: %d, Nom: %s Total pages : %lu Valide Page : %lu Invalid page : %lu \n", jiffies, info[i].pid, info[i].name, info[i].total_pages, info[i].valid_pages, info[i].invalid_pages);
            // Vérifie si la longueur formatée dépasse la taille du tampon
            //if (len >= sizeof(proc_buffer) - bytes_written) {
            //    printk(KERN_ALERT "Tampon de sortie trop petit pour écrire toutes les informations sur les processus\n");
            //    return -ENOMEM;
            //}
            //bytes_written += len;
        }
        count = bytes_written;
        *pos += count;
        if (copy_to_user(buffer, proc_buffer, count)) {
            return -EFAULT;
        }
    }
    if(strncmp(proc_buffer, "RESET", 3) == 0) {
        kfree(info);
        retrieve_process_info();
        printk(KERN_INFO "Reset fini");
    }

    // Renvoie le nombre d'octets écrits
    return count;
}

static ssize_t read_proc(struct file *file, char __user *buffer, size_t count, loff_t *pos) {
    // Vérifie si la position est en dehors des limites du tampon
    if (*pos >= strlen(proc_buffer)) {
        // Si la position est au-delà de la fin du fichier, indique la fin de fichier (EOF)
        return 0;
    }

    // Détermine la quantité de données à copier dans le buffer utilisateur
    size_t remaining_bytes = strlen(proc_buffer) - *pos;
    size_t bytes_to_copy = count < remaining_bytes ? count : remaining_bytes;

    // Copie les données du tampon du fichier proc vers le buffer utilisateur
    if (copy_to_user(buffer, proc_buffer + *pos, bytes_to_copy)) {
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

static void retrieve_process_info(void) {
    struct task_struct *task;
    
    num_processes = 0;
    // Parcourir la liste des processus
    for_each_process(task) {
        int i;
        int found = 0;
        
        // Vérifier si le nom du processus existe déjà dans la structure
        for (i = 0; i < num_processes; i++) {
            if (strcmp(task->comm, info[i].name) == 0) {
                // Le nom du processus existe déjà, mettre à jour les valeurs
                info[i].total_pages += task->mm->total_vm;
                info[i].valid_pages += task->mm->total_vm - task->mm->data_vm;
                info[i].invalid_pages += task->mm->total_vm - get_mm_rss(task->mm);
                // Ajouter le PID au tableau dynamique
                info[i].pid = krealloc(info[i].pid, (info[i].identical_page_groups + 1) * sizeof(pid_t), GFP_KERNEL);
                if (!info[i].pid) {
                    printk(KERN_ALERT "Échec de l'allocation de mémoire\n");
                    return;
                }
                info[i].pid[info[i].identical_page_groups + 1] = task->pid;
                info[i].identical_page_groups++;
                found = 1;
                printk(KERN_INFO "Il y a un process en double le voici -> PID: %d, Nom: %s \n", info[i].pid[info[i].identical_page_groups], info[i].name);
                printk(KERN_INFO "Process auquel il se rapporte : %d  \n", info[i].pid[0]);

                break;
            }
        }
        
        if (!found) {
            // Le nom du processus n'existe pas encore, ajouter une nouvelle entrée
            if (!info) {
                info = kmalloc(sizeof(struct process_info), GFP_KERNEL);
            } else {
                struct process_info *temp = krealloc(info, (num_processes + 1) * sizeof(struct process_info), GFP_KERNEL);
                if (!temp) {
                    printk(KERN_ALERT "Échec de l'allocation de mémoire\n");
                    return;
                }
                info = temp;
            }
            strncpy(info[num_processes].name, task->comm, sizeof(info[num_processes].name) - 1);

            struct mm_struct *mm = task->mm;
            if (mm != NULL) {
                info[num_processes].total_pages = mm->total_vm;
                info[num_processes].valid_pages = mm->total_vm - mm->data_vm;
                info[num_processes].invalid_pages = mm->total_vm - get_mm_rss(mm);
                //total_pages_used += info[num_processes].total_pages; // Ajouter au total des pages utilisées
            } else {
                info[num_processes].total_pages = 0;
                info[num_processes].valid_pages = 0;
                info[num_processes].invalid_pages = 0;
            }

            info[num_processes].readonly_pages = 0; // À implémenter si nécessaire
            info[num_processes].identical_page_groups = 0; // À implémenter si nécessaire
            info[num_processes].pid = kmalloc(sizeof(pid_t), GFP_KERNEL);
            if (!info[num_processes].pid) {
                printk(KERN_ALERT "Échec de l'allocation de mémoire\n");
                return;
            }
            info[num_processes].pid[0] = task->pid;
            num_processes++;

            printk(KERN_INFO "PID: %d, Nom: %s Total pages : %lu Valide Page : %lu Invalid page : %lu \n", info[num_processes - 1].pid[0], info[num_processes - 1].name, info[num_processes - 1].total_pages, info[num_processes - 1].valid_pages, info[num_processes - 1].invalid_pages);
        }
    }

    printk(KERN_INFO "OK CEST FINIIIIIIIIIIIIIIIIIIIIIIII \n");

    int i,j;

    for(i = 0; i < num_processes; i++) {
        
        printk(KERN_INFO "PID: %d, Nom: %s\n", info[i].pid[0], info[i].name);

        for (j = 1; j <= info[i].identical_page_groups; j++) {
            printk(KERN_INFO "PID identique %d: %d\n", j, info[i].pid[j]);
        }
    }
}

void detect_identical_pages(){
    int i,j,k;

    for(i = 0; i < num_processes; i++) {
        struct mm_struct *mm1 = NULL;
        struct mm_struct *mm2 = NULL;
        struct vm_area_struct *vma1, *vma2;
        struct task_struct *task;

        task = pid_task(find_vpid(info[i].pid[0]), PIDTYPE_PID); //On récupère le premier PID
        if(task) {
            mm1 = get_task_mm(task);
            if(mm1) {
                for (vma1 = mm1->mmap; vma1; vma1 = vma1->vm_next) {
                    if (vma1->vm_flags & VM_READ) { //Si on est en lecture
                        for(j = 1; j <= info[i].identical_page_groups; j++) { //Si on a plusieurs PID ou le même
                            task = pid_task(find_vpid(info[i].pid[j]), PIDTYPE_PID);
                            if(task) {
                                mm2 = get_task_mm(task);
                                if(mm2) {
                                    for (vma2 = mm2->mmap; vma2; vma2 = vma2->vm_next) {
                                        if (vma2->vm_flags & VM_READ) {
                                            if (vma1->vm_start == vma2->vm_start && vma1->vm_end == vma2->vm_end) {
                                                printk(KERN_INFO "Les pages sont identiques avec le PID : %d et le PID : %d \n", info[i].pid[0], info[i].pid[j]);
                                            }
                                        }
                                    }
                                    mmput(mm2);
                                }
                            }
                        }
                    }
                }
                mmput(mm1);
            }
        }

    }
}
// Fonction d'initialisation du module
static int __init process_info_init(void) {
    // Créer le fichier proc pour afficher les informations sur les processus
    if (!proc_create(PROC_NAME, 0666, NULL, &proc_fops)) {
        printk(KERN_ALERT "Erreur lors de la création du fichier proc\n");
        return -ENOMEM;
    }

    // Récupérer les informations sur les processus lors de l'initialisation
    retrieve_process_info();

    //Pages identical 
    detect_identical_pages();

    printk(KERN_INFO "Module de test du fichier proc initialisé\n");
    return 0;
}

static void __exit proc_exit(void) {
    // Supprime le fichier proc lors du déchargement du module
    remove_proc_entry(PROC_NAME, NULL);
    printk(KERN_INFO "Module de test du fichier proc déchargé\n");
}

module_init(process_info_init);
module_exit(proc_exit);
