#include <MapTools.hpp>
#include <MemoryTools.hpp>

std::vector<MapsInfo> getMapsInfo()
{
    MapsInfo *map = new MapsInfo;
    std::vector<MapsInfo> maps;
    FILE *maps_fd = fopen("/proc/self/maps", "r");
    if (maps_fd == NULL)
    {
        LOGD("\033[41;37mOpen /proc/self/maps Failed !!\033[0m");
        delete map;  // free memory
        return maps; // return empty vector
    }
    else
    {
        char line[2048];
        while (fgets(line, sizeof(line), maps_fd))
        {
            sscanf(line, "%lx-%lx %4s %lx %lx:%lx %lu %s", &map->start, &map->end, map->perms, &map->useless, &map->useless, &map->useless, &map->inode, map->name); // 格式化字符串
            map->size = map->end - map->start;                                                                                                                       // 段大小 == 结束地址 - 开始地址
            if (strlen(map->name) == 0 && strstr(map->perms, "rw") != NULL)
            { // 如果段名为空(A内存) 并且段权限中包含rw(可读写)
                // 过滤条件 -- 后期添加过滤条件 根据传入的参数 决定过滤出什么maps段
                maps.push_back(*map); // 将段信息放入vector中
            }
            memset(map, 0, sizeof(MapsInfo)); // 清空内存
        }
        delete map;  // 释放内存
        return maps; // 返回vector
    }
}

/*从地址判断所属内存段的属性*/
int getMemPermission(unsigned long address)
{
    char line[PATH_MAX] = {0};
    char perms[5];
    int bol = 1;
    FILE *fp = fopen("/proc/self/maps", "r");
    if (fp == nullptr)
    {
        return 0;
    }
    while (fgets(line, PATH_MAX, fp) != nullptr)
    {
        unsigned long start, end;
        int eol = (strchr(line, '\n') != nullptr);
        if (bol)
        {
            if (!eol)
            {
                bol = 0;
            }
        }
        else
        {
            if (eol)
            {
                bol = 1;
            }
            continue;
        }
        if (sscanf(line, "%lx-%lx %4s", &start, &end, perms) != 3)
        {
            continue;
        }
        if (start <= address && address < end)
        {
            int prot = 0;
            if (perms[0] == 'r')
            {
                prot |= PROT_READ;
            }
            else if (perms[0] != '-')
            {
                goto unknown_perms;
            }
            if (perms[1] == 'w')
            {
                prot |= PROT_WRITE;
            }
            else if (perms[1] != '-')
            {
                goto unknown_perms;
            }
            if (perms[2] == 'x')
            {
                prot |= PROT_EXEC;
            }
            else if (perms[2] != '-')
            {
                goto unknown_perms;
            }
            if (perms[3] != 'p')
            {
                goto unknown_perms;
            }
            if (perms[4] != '\0')
            {
                perms[4] = '\0';
                goto unknown_perms;
            }
            fclose(fp);
            return prot;
        }
    }
unknown_perms:
    fclose(fp);
    return 0;
}

// 修改内存段权限 : 注入后 部分目标内存段可能无权限读写 eg. xa cb
bool editMemProt(unsigned long address, int prot)
{
    void *page_start = (void *)(address - address % PAGE_SIZE);
    if (-1 == mprotect(page_start, PAGE_SIZE, prot))
    {
        return false; // 修改内存段保护属性失败
    }
    else
    {
        return true; // 修改内存段保护属性成功
    }
}