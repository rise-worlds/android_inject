#ifndef __Shark_Inject_H__
#define __Shark_Inject_H__
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

extern "C"
{
    int inject_remote_process(pid_t target_pid, const char *library_path, const char *function_name, const char *param, size_t param_size);
}

#endif