
#include "selinux.h"
#include "shark_inject.h"
#include <string.h>
#include "progress.h"

int main(int argc, char **argv) {
    pid_t target_pid;
    const char *process_name = "com.shark.initapp";
    if (argc > 1) {
        process_name = argv[1];
    }
    target_pid = find_pid_of(process_name);
    if (-1 == target_pid) {
        printf("Can't find the process\n");
        return -1;
    }
    printf("target_pid=%d argc=%d\n ", target_pid, argc);
    const char *sopath = "/data/local/tmp/libinject2.so";
    if (argc > 2) {
        sopath = argv[2];
    }
    const char *main_entry = "main_entry";
    if (argc > 3) {
        main_entry = argv[3];
    }
    const char *parameter = "parameter";
    if (argc > 4) {
        parameter = argv[4];
    }

    SELinux::init();
    SELinux::setEnforce(SELinuxStatus::PERMISSIVE);

    printf("inject_remote_process start\n");
    inject_remote_process(target_pid, sopath, main_entry, parameter, strlen(parameter));
    return 0;
}
