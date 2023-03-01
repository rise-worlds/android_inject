#include <stdio.h>
#include <stdlib.h>
#include <zlib.h>
#include <ioapi.h>
#include <unzip.h>
#include <spdlog/spdlog.h>
#include <cstring>

bool CheckUnity(const char* zipFilePath)
{
    bool find = false;
    // 1. open zip
    unzFile zipfile = unzOpen(zipFilePath);
    if (zipfile == NULL)
    {
        SPDLOG_ERROR("open zip failed , path = {}", zipFilePath);
        return find;
    }

    // 2. get global info
    unz_global_info global_info;
    if (unzGetGlobalInfo(zipfile, &global_info) != UNZ_OK)
    {
        unzClose(zipfile);
        SPDLOG_ERROR("get global info failed");
        return find;
    }

    static const char* libs_path[] = {"lib/arm64-v8a/libil2cpp.so", "lib/armeabi-v7a/libil2cpp.so", "lib/x86/libil2cpp.so", "lib/x86_64/libil2cpp.so"};
    // 3. loop files
    for (uLong i = 0; i < global_info.number_entry; ++i)
    {
        unz_file_info64 file_info64;
        char filename[1024] = {0};

        unzGetCurrentFileInfo64(zipfile, &file_info64, filename, sizeof(filename), NULL, 0, NULL, 0);
        unzCloseCurrentFile(zipfile);

        SPDLOG_DEBUG("get file: {}", filename);
        for (auto &&path : libs_path)
        {
            if (std::strstr(filename, path) == filename)
            {
                find = true;
                break;
            }
        }
        
        if (find || ((i + 1) < global_info.number_entry && unzGoToNextFile(zipfile) != UNZ_OK))
        {
            break;
        }
    }

    // 4. close zip file
    unzClose(zipfile);

    return find;
}

int main(int argv, const char **args)
{
    bool result = CheckUnity(args[1]);

    SPDLOG_INFO("currect apk is {} app", result ? "Unity 3D": "not Unity 3D");
}
