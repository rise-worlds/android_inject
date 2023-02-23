#pragma once
#include <stdlib.h>
#include <stdbool.h>

/*根据进程名查找进程id*/
int find_pid_of(const char *process_name);
/*读取模块地址*/
long getModuleBase(const char *moduleName);
/*判断目标so是否加载*/
bool isLibraryLoaded(const char *libraryName);
