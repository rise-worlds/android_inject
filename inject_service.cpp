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
#include <httplib/httplib.h>
#include <nlohmann/json.hpp>
using json = nlohmann::json;
#include <frida-core.h>
#include <sys/xattr.h>

struct app_state
{
    std::string app_package;
    int pid;
    int speed;
};

static int service_port = 10086;
static std::string current_path;
static std::unordered_map<std::string, app_state> apps_state;

void sigFunc(int sig);
int daemon();

bool copyFile(const std::string &from, const std::string &to);
bool exec(const std::string &cmd);

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

bool CheckUnity(const std::string &zipFilePath)
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
int inject(const char *process_name, const char *so_path, int service_port, int speed)
{
    int result = 0;

    FridaInjector *injector;
    int pid = 0, wait_process_count = 0;
    GError *error;
    guint id;
    const char *context = "u:object_r:frida_file:s0";

    do {
        pid = find_pid_of(process_name);
        if (pid <= 0)
        {
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
            wait_process_count++;
        }
    } while (pid <= 0 && wait_process_count < 100);

    if (apps_state.count(process_name) && apps_state[process_name].pid == pid)
    {
        apps_state[process_name].speed = speed;
        SPDLOG_INFO("target={} so={} target_pid={} speed={}", process_name, so_path, pid, speed);
        return 0;
    }
    SPDLOG_INFO("target={} so={} target_pid={} speed={}", process_name, so_path, pid, speed);

    if (setxattr(so_path, XATTR_NAME_SELINUX, context, strlen(context) + 1, 0) != 0)
    {
        SPDLOG_ERROR("Failed to set SELinux permissions");
        return 3;
    }

    injector = frida_injector_new();

    error = NULL;
    json j_data = {{"port", service_port}, {"name", process_name}, {"pid", pid}, {"speed", speed}};
    std::string data = j_data.dump();
    id = frida_injector_inject_library_file_sync(injector, pid, so_path, "example_agent_main", data.c_str(), NULL, &error);
    if (error != NULL)
    {
        SPDLOG_ERROR("{}", error->message);
        g_clear_error(&error);

        result = 1;
    }

    SPDLOG_DEBUG("inject end");
    frida_injector_close_sync(injector, NULL, NULL);
    g_object_unref(injector);

    apps_state[process_name] = {process_name, pid, speed};

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
        .bind_start([&]()
                    { SPDLOG_INFO("start http server : {} {} {} {}",
                                  server.listen_address(), server.listen_port(),
                                  asio2::last_error_val(), asio2::last_error_msg()); })
        .bind_stop([&]()
                   { SPDLOG_INFO("stop http server : {} {}",
                                 asio2::last_error_val(), asio2::last_error_msg()); });

    server.bind<http::verb::post>(
        "/app_u3d", [](std::shared_ptr<asio2::http_session> &session_ptr, http::web_request &req, http::web_response &rep)
        {
        asio2::ignore_unused(session_ptr);
        try {
            json body = json::parse(req.body());
            bool result = CheckUnity(body["path"]);
            json content = {{"status", 0}, body["name"], {"result", result}};
            rep.fill_json(content);
        }
        catch(const json::exception&) {
            rep.fill_page(http::status::bad_request);
        } });

    server.bind<http::verb::post>(
        "/inject", [](http::web_request &req, http::web_response &rep)
        {
        try {
            json body = json::parse(req.body());

            int result = 0;
            auto process_name = body["name"].get<std::string>();
            auto type = body["type"].get<int>();
            auto speed = body["speed"].get<int>();
            const char* so_path = nullptr;
            json content = {{"status", 0}, {"name", process_name}, {"result", result}};
            if (type == 1) {
                so_path = "libUnityCheat.so";
            } else {
                content["result"] = -1;
                rep.fill_json(std::string(content.dump()));
                return;
            }

            auto so_full_path = fmt::format("{}/{}", current_path, so_path);
            // auto so_full_path = fmt::format("/data/local/tmp/{}", so_path);
            // auto cmd = fmt::format("rm {2}; cp '{0}/{1}' {2}", current_path, so_path, so_full_path);
            // SPDLOG_DEBUG("call {}", cmd);
            // exec(cmd);
            result = inject(process_name.c_str(), so_full_path.c_str(), service_port, speed);
            
            rep.fill_json(std::string(content.dump()));
        }
        catch(const json::exception&) {
            rep.fill_page(http::status::bad_request);
        } });

    server.bind<http::verb::get>("/ping", [](http::web_request &req, http::web_response &rep)
                                  { 
        try {
            json json = {{"status", 0}};
            rep.fill_json(json);
        }
        catch(const json::exception&) {
            rep.fill_page(http::status::bad_request);
        } });

    server.bind<http::verb::post>("/status", [](http::web_request &req, http::web_response &rep)
                                 { 
        try {
            // auto query = req.query();
            // auto pos = query.find("=");
            // std::string process_name = query.substr(pos+1, query.size() - pos - 1).data();

            json body = json::parse(req.body());
            auto process_name = body["name"].get<std::string>();
            json json = {{"status", 0}, {"name", process_name}, {"speed", 0}};
            if (apps_state.count(process_name))
            {
                json["speed"] = apps_state[process_name].speed;
            } else {
                // sync status
                auto pid = json["pid"].get<int>();
                auto speed = json["speed"].get<int>();
                apps_state[process_name] = {process_name, pid, speed};
                json["speed"] = speed;
            }
            std::string content = json.dump();
            rep.fill_json(content);
        }
        catch(const json::exception&) {
            rep.fill_page(http::status::bad_request);
        } });

    server.bind_not_found([](http::web_request &req, http::web_response &rep)
                          {
        asio2::ignore_unused(req);
        rep.fill_page(http::status::not_found); });

    server.start("0.0.0.0", service_port);

    // httplib::Server server;
    // server.set_error_handler([](const Request & /*req*/, Response &res) {
    //     const char *fmt = "<p>Error Status: <span style='color:red;'>%d</span></p>";
    //     char buf[BUFSIZ];
    //     snprintf(buf, sizeof(buf), fmt, res.status);
    //     res.set_content(buf, "text/html");
    // });

    // server.set_logger([](const Request &req, const Response &res) {
    //     printf("%s", log(req, res).c_str());
    // });
    
    // server.listen("localhost", service_port);

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

void sigFunc(int sig)
{
    if (sig == SIGINT || sig == SIGTERM)
    {
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
    sig.sa_flags = 0;

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

bool copyFile(const std::string &from, const std::string &to)
{
    namespace fs = std::filesystem;
    try
    {
        return fs::copy_file(from, to);
    }
    catch (fs::filesystem_error &e)
    {
        SPDLOG_WARN(e.what());
    }

    return false;
}

bool exec(const std::string &cmd)
{
    FILE *pff = popen(cmd.c_str(), "r");
    if (pff)
    {
        pclose(pff);
        return true;
    }
    return false;
}
