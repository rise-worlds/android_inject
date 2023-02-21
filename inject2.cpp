

#include <sys/types.h>
#include <dirent.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string>
#include <android/log.h>
#include <dlfcn.h>
#include "Logger.hpp"
#include "dlfcn_compat.h"

int find_pid_of(const char *process_name)
{
    int id;
    pid_t pid = -1;
    DIR* dir;
    FILE *fp;
    char filename[32];
    char cmdline[256];

    struct dirent * entry;

    if (process_name == NULL)
        return -1;

    dir = opendir("/proc");
    if (dir == NULL)
        return -1;

    while((entry = readdir(dir)) != NULL) {
        id = atoi(entry->d_name);
        if (id != 0) {
            sprintf(filename, "/proc/%d/cmdline", id);
            fp = fopen(filename, "r");
            if (fp) {
                fgets(cmdline, sizeof(cmdline), fp);
                fclose(fp);

                if (strcmp(process_name, cmdline) == 0) {
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

void* get_module_base(pid_t pid, const char* module_name)
{
    FILE* fp;
    long addr = 0;
    char* pch;
    char filename[32];
    char line[1024];

    if (pid < 0)
    {
        snprintf(filename, sizeof(filename), "/proc/self/maps");
    }
    else
    {
        snprintf(filename, sizeof(filename), "/proc/%d/maps", pid);
    }
    fp = fopen(filename, "r");
    if (fp != NULL)
    {
        while (fgets(line, sizeof(line), fp))
        {
            if (strstr(line, module_name))
            {
                pch = strtok(line, "-");
                addr = strtoul(pch, NULL, 16);
                if (addr == 0x8000)
                    addr = 0;
                break;
            }
        }
        fclose(fp);
    }
    return (void*) addr;
}


__attribute__((constructor)) static void ctor()
{
    LOGE("start hook");
}

__attribute__ ((visibility ("default"))) 
void main_entry(const char* str)
{
    LOGE("enter main_entry");

    void *handle = dlopen_compat("libutils.so", RTLD_NOW);
    if (!handle) {
        LOGE("cannot load libutils.so");
        return;
    }

    // Constructor:  android::String8::String8(char const*)
    // The first argument is a pointer where "this" of a new object is to be stored.
    void (*create_string)(void **, const char *) = (__typeof(create_string)) dlsym_compat(handle, "_ZN7android7String8C1EPKc");

    // Member function:  size_t android::String8::getUtf32Length() const
    // The argument is a pointer to "this" of the object
    size_t(*get_len)(void **) = (__typeof(get_len)) dlsym_compat(handle, "_ZNK7android7String814getUtf32LengthEv");
    
    // Destructor:  android::String8::~String8()
    void (*delete_string)(void **) = (__typeof(delete_string)) dlsym_compat(handle, "_ZN7android7String8D1Ev");

    // All required library addresses known now, so don't need its handle anymore
    dlclose_compat(handle);

    if (!create_string || !get_len || !delete_string) {
        LOGE("required functions missing in libutils.so");
        return;
    }

    // Fire up now.
    void *str8 = 0;

    create_string(&str8, str);
    if (!str8) {
        LOGE("failed to create string");
        return;
    }

    size_t len = get_len(&str8);
    LOGE("%s: length = %d", str, (int) len);

    delete_string(&str8);
}
