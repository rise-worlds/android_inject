#include <MemoryTools.hpp>

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

// 因为是注入 直接读写
void readin(unsigned long address, void *buffer, size_t size)
{
    memcpy(buffer, (void *)address, size);
}

void writein(unsigned long address, void *buffer, size_t size)
{
    memcpy((void *)address, buffer, size);
}

// hook
bool myHook(unsigned long address, void *myFuntion, void **origFuntion, const char *str)
{
    LOGD("Installing hook at %lx", address);
    int prot = getMemPermission(address); // 获取内存所属内存段的权限属性
    if (prot == 0)
    {
        LOGD("Map Permission got failed !!");
        return false; // 获取内存段的权限属性失败
    }
    else
    {
        if (!(editMemProt(address, PROT_READ | PROT_WRITE | PROT_EXEC)))
        { // 修改内存段的权限属性 -- 可读|可写|可执行
            LOGD("Edit Mem Prot Failed !!");
            return false;
        }
        else
        {
            if (DobbyHook(reinterpret_cast<void *>(address), myFuntion, origFuntion) == RS_SUCCESS)
            {
                LOGD("Hook %s Succeed at %lx !!", str, address);
                if (editMemProt(address, prot))
                { // 开始恢复内存段权限属性
                    LOGD("Rec Mem Succeed !!");
                    return true;
                }
                else
                {
                    LOGD("Rec Mem Failed !!");
                    return true; // 这里 说明hook是成功的 但是内存段的权限属性恢复失败
                }
            }
            else
            {
                LOGD("Hook %s Faild at %lx!!", str, address);
                return false;
            }
        }
    }
    LOGD("Hook erro !!");
    return false;
}

// unhook
bool unHook(unsigned long address, const char *str)
{
    LOGD("Start Destroy Hook at %lx", address);
    int prot = getMemPermission(address); // 获取内存所属内存段的权限属性
    if (prot == 0)
    {
        LOGD("Map Permission got failed !!");
        return false; // 获取内存段的权限属性失败
    }
    else
    {
        if (!(editMemProt(address, PROT_READ | PROT_WRITE | PROT_EXEC)))
        { // 修改内存段的权限属性 -- 可读|可写|可执行
            LOGD("Edit Mem Prot Failed !!");
            return false;
        }
        else
        {
            if (DobbyDestroy(reinterpret_cast<void *>(address)) == RS_SUCCESS)
            {
                LOGD("Destroy %s Succeed at %lx!!", str, address);
                if (editMemProt(address, prot))
                { // 开始恢复内存段权限属性
                    LOGD("Rec Mem Succeed !!");
                    return true;
                }
                else
                {
                    LOGD("Rec Mem Failed !!");
                    return true; // 这里 说明unhook是成功的 但是内存段的权限属性恢复失败
                }
            }
            else
            {
                LOGD("Destroy %s Failed at %lx!!", str, address);
                return false;
            }
        }
    }
    LOGD("Destroy Hook erro !!");
    return false;
}

// 两内存地址逐一比较
bool Memcmp(unsigned const char *target, unsigned const char *pattern, int Len)
{
    for (int i = 0; i < Len; i++)
    {
        if (target[i] == pattern[i])
        {
            continue;
        }
        else
        {
            return false;
        }
    }
    return true;
}

// 特征码搜索
int AOBScan(unsigned const char *target, int tLen, unsigned const char *pattern, int pLen)
{
    if (tLen < pLen)
    {
        return -1;
    }
    for (int i = 0; i < tLen; i++)
    {
        if (Memcmp(target + i, pattern, pLen))
        {
            return i;
        }
    }
    return -1;
}