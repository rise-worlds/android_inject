#include "progress.hpp"
#include <stdio.h>
#include <unistd.h>
#include <dirent.h>
#include <fcntl.h>
#include <cstring>

// 根据进程名查找进程id  读取/proc/%d/cmdline获取进程名
int find_pid_of(const char *process_name)
{
    int id;
    pid_t pid = -1;
    DIR *dir;
    FILE *fp;
    char filename[32];
    char cmdline[256];

    struct dirent *entry;

    if (process_name == NULL)
        return -1;

    dir = opendir("/proc");
    if (dir == NULL)
        return -1;

    while ((entry = readdir(dir)) != NULL)
    {
        id = atoi(entry->d_name);
        if (id != 0)
        {
            sprintf(filename, "/proc/%d/cmdline", id);
            fp = fopen(filename, "r");
            if (fp)
            {
                fgets(cmdline, sizeof(cmdline), fp);
                fclose(fp);

                if (strcmp(process_name, cmdline) == 0)
                {
                    /* process found */
                    pid = id;
                    break;
                }
            }
        }
    }

    closedir(dir);
    return pid;
}

// 内存工具 针对so注入情况 魔改了
long getModuleBase(const char *moduleName)
{
    char path[1024], line[1024];
    sprintf(path, "/proc/self/maps");
    FILE *file = fopen(path, "r");
    long len = 0;
    if (file)
    {
        while (fgets(line, sizeof(line), file))
        {
            if (strstr(line, moduleName) != NULL)
            {
                len = strtoul(line, NULL, 16);
                break;
            }
        }
    }
    return len;
}

bool isLibraryLoaded(const char *libraryName)
{
    char line[512] = {0};
    FILE *fp = fopen("/proc/self/maps", "rt");
    if (fp != NULL)
    {
        while (fgets(line, sizeof(line), fp))
        {
            if (strstr(line, libraryName))
                return true;
        }
        fclose(fp);
    }
    return false;
}
