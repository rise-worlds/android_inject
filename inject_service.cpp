#include <stdio.h>
#include <stdlib.h>
#include <zlib.h>
#include <ioapi.h>
#include <unzip.h>
#include <cstring>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <csignal>
#include <thread>
#define SPDLOG_ACTIVE_LEVEL SPDLOG_LEVEL_TRACE
#include <spdlog/spdlog.h>
#include <spdlog/sinks/android_sink.h>
#include <spdlog/sinks/stdout_sinks.h>
#include <spdlog/sinks/daily_file_sink.h>
#include <asio2/asio2.hpp>
#include <asio2/tcp/tcp_server.hpp>
#include <nlohmann/json.hpp>
#ifdef ANDROID
#include <frida-core.h>
#include <sys/xattr.h>
#endif

static int service_port = 10086;
static std::string current_path;

void sigFunc(int sig);
int daemon();

bool copyFile(const std::string& from, const std::string& to);
bool exec(const std::string& cmd);

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

        SPDLOG_TRACE("get file: {}", filename);
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

int find_pid_of(const char *process_name);
int inject(const char* process_name, const char* so_path, int service_port)
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
    id = frida_injector_inject_library_file_sync(injector, pid, so_path, "example_agent_main", fmt::format("{}", service_port).c_str(), NULL, &error);
    if (error != NULL)
    {
        SPDLOG_ERROR("{}", error->message);
        g_clear_error(&error);

        result = 1;
    }

    SPDLOG_DEBUG("inject end");
    frida_injector_close_sync(injector, NULL, NULL);
    g_object_unref(injector);

    return result;
}

int main(int argc, const char **argv)
{
    signal(SIGINT, sigFunc);
    signal(SIGTERM, sigFunc);
    signal(SIGHUP, SIG_IGN);
    signal(SIGQUIT, SIG_IGN);
    signal(SIGPIPE, SIG_IGN);
    signal(SIGTTOU, SIG_IGN);
    signal(SIGTTIN, SIG_IGN);
    signal(SIGCHLD, SIG_IGN);

    if (argc < 4)
        return EINVAL;

    current_path = argv[1];
    auto stdout_sink = std::make_shared<spdlog::sinks::stdout_sink_mt>();
    auto rotating_sink = std::make_shared<spdlog::sinks::daily_file_sink_mt>(current_path + "/log/service.log", 0, 0);
    auto android_sink = std::make_shared<spdlog::sinks::android_sink_mt>("YY-INJECT");
    auto logger = std::make_shared<spdlog::logger>("InjectService", spdlog::sinks_init_list{stdout_sink, rotating_sink, android_sink});
    spdlog::set_default_logger(logger);
    spdlog::set_level(spdlog::level::debug);

    chdir(argv[1]);
    service_port = std::atoi(argv[2]);
    if (std::atoi(argv[3]) != 0)
        daemon();
    
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

    server.bind<http::verb::post>("/inject", [](http::web_request& req, http::web_response& rep) {
        try {
            nlohmann::json json = nlohmann::json::parse(req.body());

            bool result = false;
            auto process_name = json["name"].get<std::string>();
            auto type = json["type"].get<int>();
            auto speed = json["speed"].get<int>();
            const char* so_path = nullptr;
            if (type == 1) {
                so_path = "libUnityCheat.so";
            } else {
                std::string content = fmt::format("{{\"name\" : \"{}\", \"result\" : {} }}", json["name"].get<std::string>(), result);
                rep.fill_json(content);
                return;
            }
            auto so_full_path = fmt::format("/data/local/tmp/{}", so_path);
            auto cmd = fmt::format("rm {2}; cp '{0}/{1}' {2}", current_path, so_path, so_full_path);
            SPDLOG_DEBUG("call {}", cmd);
            exec(cmd);
            result = inject(process_name.c_str(), so_full_path.c_str(), service_port);
            std::string content = fmt::format("{{\"name\" : \"{}\", \"result\" : {} }}", json["name"].get<std::string>(), result);
            rep.fill_json(content);
        }
        catch(const nlohmann::detail::exception&) {
            rep.fill_page(http::status::bad_request);
        }
    }, aop_check{});

    server.bind<http::verb::post>("/ping", [](http::web_request& req, http::web_response& rep) {
        rep.fill_json("{\"status\" : \"0\"}");
    });

    server.bind_not_found([](http::web_request &req, http::web_response &rep)
                          {
        asio2::ignore_unused(req);
        rep.fill_page(http::status::not_found); });

    server.start("0.0.0.0", service_port);

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

void sigFunc(int sig) {
    if (sig == SIGINT || sig == SIGTERM) {
        
    }
}

int daemon()
{
    pid_t pid;
    if ((pid = fork()) != 0)
    {
        /* parent process exit */
        _exit(0);
    }

    setsid();

    signal(SIGINT, sigFunc);
    signal(SIGTERM, sigFunc);
    signal(SIGHUP, SIG_IGN);
    signal(SIGQUIT, SIG_IGN);
    signal(SIGPIPE, SIG_IGN);
    signal(SIGTTOU, SIG_IGN);
    signal(SIGTTIN, SIG_IGN);
    signal(SIGCHLD, SIG_IGN);

    struct sigaction sig;
    sig.sa_handler = SIG_IGN;
    sig.sa_flags   = 0;

    sigemptyset(&sig.sa_mask);
    sigaction(SIGPIPE, &sig, nullptr);

    if ((pid = fork()) != 0)
    {
        /* parent process exit */
        _exit(0);
    }

    umask(0);
    setpgrp();

    return 0;
}

bool copyFile(const std::string& from, const std::string& to)
{
    namespace fs = std::filesystem;
    try {
        return fs::copy_file(from, to);
    } catch(fs::filesystem_error& e) {
        SPDLOG_WARN(e.what());
    }

    return false;
}

bool exec(const std::string& cmd)
{
    FILE * pff = popen(cmd.c_str(), "r");
    if (pff)
      pclose(pff);
}
