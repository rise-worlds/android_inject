#include <frida-core.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/xattr.h>

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

int main(int argc, char *argv[])
{
    int result = 0;
    const char *sopath = "/data/local/tmp/libagent.so";
    const char *context = "u:object_r:frida_file:s0";
    FridaInjector *injector;
    int pid;
    GError *error;
    guint id;

    const char *process_name = "com.unity.timetest";
    if (argc > 1)
    {
        process_name = argv[1];
    }
    pid = find_pid_of(process_name);
    if (pid <= 0)
    {
        pid = atoi(argv[1]);
        if (pid <= 0)
        {
            goto bad_usage;
        }
    }
    g_printerr("target_pid=%d argc=%d \n", pid, argc);
    if (argc > 2)
    {
        sopath = argv[2];
    }
    g_printerr("target=%s so=%s \n", process_name, sopath);

    frida_init();

    frida_selinux_patch_policy();

    if (setxattr(sopath, XATTR_NAME_SELINUX, context, strlen(context) + 1, 0) != 0)
        goto setxattr_failed;

    injector = frida_injector_new();

    error = NULL;
    id = frida_injector_inject_library_file_sync(injector, pid, sopath, "example_agent_main", "example data", NULL, &error);
    if (error != NULL)
    {
        g_printerr("%s\n", error->message);
        g_clear_error(&error);

        result = 1;
    }

    frida_injector_close_sync(injector, NULL, NULL);
    g_object_unref(injector);

    frida_deinit();

    return result;

bad_usage:
{
    g_printerr("Usage: %s <process name>|<pid> <so path>\n", argv[0]);
    frida_deinit();
    return 1;
}
setxattr_failed:
{
    g_printerr("Failed to set SELinux permissions\n");
    frida_deinit();
    return 1;
}
}