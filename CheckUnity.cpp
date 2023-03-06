#include <stdio.h>
#include <stdlib.h>
#include <zlib.h>
#include <ioapi.h>
#include <unzip.h>
#include <cstring>
#include <thread>
#define SPDLOG_ACTIVE_LEVEL SPDLOG_LEVEL_TRACE
#include <spdlog/spdlog.h>
#include <asio2/asio2.hpp>
#include <asio2/tcp/tcp_server.hpp>
#include <nlohmann/json.hpp>
#ifdef ANDROID
#include <frida-core.h>
#include <sys/xattr.h>
#endif

struct aop_log
{
    bool before(http::web_request &req, http::web_response &rep)
    {
        asio2::ignore_unused(rep);
        SPDLOG_DEBUG("aop_log before {}", req.method_string().data());
        return true;
    }
    bool after(std::shared_ptr<asio2::http_session> &session_ptr, http::web_request &req, http::web_response &rep)
    {
        ASIO2_ASSERT(asio2::get_current_caller<std::shared_ptr<asio2::http_session>>().get() == session_ptr.get());
        asio2::ignore_unused(session_ptr, req, rep);
        SPDLOG_DEBUG("aop_log after");
        return true;
    }
};

struct aop_check
{
    bool before(std::shared_ptr<asio2::http_session> &session_ptr, http::web_request &req, http::web_response &rep)
    {
        ASIO2_ASSERT(asio2::get_current_caller<std::shared_ptr<asio2::http_session>>().get() == session_ptr.get());
        asio2::ignore_unused(session_ptr, req, rep);
        SPDLOG_DEBUG("aop_check before");
        return true;
    }
    bool after(http::web_request &req, http::web_response &rep)
    {
        asio2::ignore_unused(req, rep);
        SPDLOG_DEBUG("aop_check after");
        return true;
    }
};

bool CheckUnity(const std::string& zipFilePath)
{
    bool find = false;
    // 1. open zip
    unzFile zipfile = unzOpen(zipFilePath.c_str());
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

    static const char *libs_path[] = {"lib/arm64-v8a/libil2cpp.so", "lib/armeabi-v7a/libil2cpp.so", "lib/x86/libil2cpp.so", "lib/x86_64/libil2cpp.so"};
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

#ifdef ANDROID
int find_pid_of(const char *process_name);
int inject(const char* process_name, const char* so_path)
{
    int result = 0;

    FridaInjector *injector;
    int pid;
    GError *error;
    guint id;
    const char *context = "u:object_r:frida_file:s0";

    pid = find_pid_of(process_name);
    if (pid <= 0)
    {
        pid = std::atoi(process_name);
        if (pid <= 0)
        {
            SPDLOG_ERROR("process {} not found", process_name);
            return 2;
        }
    }
    SPDLOG_DEBUG("target={} so={} target_pid={}", process_name, so_path, pid);

    if (setxattr(so_path, XATTR_NAME_SELINUX, context, strlen(context) + 1, 0) != 0)
    {
        SPDLOG_ERROR("Failed to set SELinux permissions");
        return 3;
    }

    injector = frida_injector_new();

    error = NULL;
    id = frida_injector_inject_library_file_sync(injector, pid, so_path, "example_agent_main", "example data", NULL, &error);
    if (error != NULL)
    {
        SPDLOG_DEBUG("{}", error->message);
        g_clear_error(&error);

        result = 1;
    }

    SPDLOG_DEBUG("inject end");
    frida_injector_close_sync(injector, NULL, NULL);
    g_object_unref(injector);

    return result;
}
#endif

int main(int argv, const char **args)
{
    spdlog::set_level(spdlog::level::debug);
    
    frida_init();
    frida_selinux_patch_policy();

    asio2::http_server server;

    server.bind_recv([&](http::web_request &req, http::web_response &rep)
                     {
                        asio2::ignore_unused(req, rep);
                        // all http and websocket request will goto here first.
                        SPDLOG_INFO("path: {}, query: {}", req.path(), req.query()); })
        .bind_connect([](auto &session_ptr)
                      {
                          SPDLOG_INFO("client enter : {} {} {} {}",
                                 session_ptr->remote_address(), session_ptr->remote_port(),
                                 session_ptr->local_address(), session_ptr->local_port());
                          // session_ptr->set_response_mode(asio2::response_mode::manual);
                      })
        .bind_disconnect([](auto &session_ptr)
                         { SPDLOG_INFO("client leave : {} {} {}",
                                  session_ptr->remote_address(), session_ptr->remote_port(),
                                  asio2::last_error_msg()); })
        .bind_start([&]()
                    { SPDLOG_INFO("start http server : {} {} {} {}",
                             server.listen_address(), server.listen_port(),
                             asio2::last_error_val(), asio2::last_error_msg()); })
        .bind_stop([&]()
                   { SPDLOG_INFO("stop http server : {} {}",
                            asio2::last_error_val(), asio2::last_error_msg()); });

    server.bind<http::verb::post>("/app_u3d", [](std::shared_ptr<asio2::http_session> &session_ptr, http::web_request &req, http::web_response &rep) {
        asio2::ignore_unused(session_ptr);
        try {
            nlohmann::json json = nlohmann::json::parse(req.body());
            bool result = CheckUnity(json["path"]);
            std::string content = fmt::format("{{\"name\" : \"{}\", \"result\" : {} }}", json["name"].get<std::string>(), result ? "true" : "false");
            rep.fill_json(content);
        }
        catch(const nlohmann::detail::exception&) {
            rep.fill_page(http::status::bad_request);
        }
    }, aop_check{});

#ifdef ANDROID
    server.bind<http::verb::post>("/inject", [](http::web_request& req, http::web_response& rep) {
        try {
            nlohmann::json json = nlohmann::json::parse(req.body());
            auto process_name = json["name"].get<std::string>();
            auto type = json["type"].get<int>();
            auto result = inject(process_name.c_str(), "/data/local/tmp/libUnityCheat2.so");
            std::string content = fmt::format("{{\"name\" : \"{}\", \"result\" : {} }}", json["name"].get<std::string>(), result);
            rep.fill_json(content);
        }
        catch(const nlohmann::detail::exception&) {
            rep.fill_page(http::status::bad_request);
        }
    }, aop_check{});
#endif

    server.bind_not_found([](http::web_request &req, http::web_response &rep)
                          {
        asio2::ignore_unused(req);
        rep.fill_page(http::status::not_found); });

    server.start("0.0.0.0", 10086);

    while (std::getchar() != '\n')
        std::this_thread::sleep_for(std::chrono::milliseconds(1));

    server.stop();

    SPDLOG_DEBUG("frida deinit");
    frida_deinit();
}

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
