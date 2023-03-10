#include <fcntl.h>
#include <frida-gum.h>
#include <unistd.h>
#include <thread>
#include <memory>
#include <Logger.hpp>
#include <ResolverInit.hpp>
#include <httplib/httplib.h>
#include <spdlog/spdlog.h>
#include <spdlog/sinks/android_sink.h>
#include <nlohmann/json.hpp>
using json = nlohmann::json;

static std::string process_name;
static int pid;
static int server_port = 10086;
static int g_speed = 1.0;
static bool g_modify_time = false;
static struct timeval g_tv = {0, 0};
static struct timespec g_ts = {0, 0};

static std::shared_ptr<std::thread> gp_run;
static unsigned long il2cppAddress = 0;  // 存储il2cpp.so基地址
int (*Screen$$get_height)();             // 预定义一个方法
int (*Screen$$get_width)();              // 预定义一个方法
float (*Time$$get_timeScale)();          // 预定义一个方法
void (*Time$$set_timeScale)(float);      // 预定义一个方法
float (*Time$$get_deltaTime)();          // 预定义一个方法
float (*Time$$get_fixedDeltaTime)();     // 预定义一个方法
void (*Time$$set_fixedDeltaTime)(float); // 预定义一个方法

// static int open_hook(const char *path, int oflag, ...);
// static int gettimeofday_hook(struct timeval *tv, struct timezone *tz);
// static int clock_gettime_hook(clockid_t clock, struct timespec *ts);

int64_t getUnixTimestamp()
{
    auto duration = std::chrono::system_clock::now().time_since_epoch();
    return std::chrono::duration_cast<std::chrono::milliseconds>(duration).count();
}

YY_API void example_agent_main(const gchar *data, gboolean *stay_resident)
{
    GumInterceptor *interceptor = nullptr;

    if (data)
    {
        try
        {
            json json = json::parse(data);

            server_port = json["port"].get<int>();
            g_speed = json["speed"].get<int>();
            pid = json["pid"].get<int>();
            process_name = json["name"].get<std::string>();
        }
        catch (const json::exception &e)
        {
            SPDLOG_ERROR("parse args error: {}", e.what());
            return;
        }
    }
    SPDLOG_INFO("example_agent_main(\"{}\")", data);
    SPDLOG_INFO("service port: {}", server_port);
    SPDLOG_INFO("speed: {}", g_speed);

    /* We don't want to our library to be unloaded after we return. */
    *stay_resident = TRUE;

    gum_init_embedded();

    // interceptor = gum_interceptor_obtain();
    // // listener = my_callback_listener_new();
    //
    // /* Transactions are optional but improve performance with multiple hooks. */
    // gum_interceptor_begin_transaction(interceptor);

    // gpointer open_origin_address = reinterpret_cast<gpointer>(gum_module_find_export_by_name(NULL, "open"));
    // gum_interceptor_replace(interceptor, open_origin_address, reinterpret_cast<gpointer>(&open_hook), NULL, NULL);
    // gpointer gettimeofday_origin_address = reinterpret_cast<gpointer>(gum_module_find_export_by_name(NULL, "gettimeofday"));
    // gum_interceptor_replace(interceptor, gettimeofday_origin_address, reinterpret_cast<gpointer>(&gettimeofday_hook), NULL, NULL);
    // gpointer clock_gettime_origin_address = reinterpret_cast<gpointer>(gum_module_find_export_by_name(NULL, "clock_gettime"));
    // gum_interceptor_replace(interceptor, clock_gettime_origin_address, reinterpret_cast<gpointer>(&clock_gettime_hook), NULL, NULL);

    il2cppAddress = (GumAddress)gum_module_find_base_address("libil2cpp.so");
    while (il2cppAddress == 0)
    { // 动态库已经完全加载
        il2cppAddress = (GumAddress)gum_module_find_base_address("libil2cpp.so");
        if (il2cppAddress != 0)
        {
            SPDLOG_DEBUG("libil2cpp.so BaseAddress: {}", il2cppAddress);
            break;
        }
        usleep(100);
    }

    SPDLOG_INFO("get il2cpp address: {:08x}", il2cppAddress);
// 初始化il2cpp API
#define DO_API(r, n, p) n = (r(*) p)gum_module_find_export_by_name("libil2cpp.so", #n)
#include "Il2cppApi/il2cppApiFunctions.h"
#undef DO_API
    // il2cpp_resolve_icall = reinterpret_cast<Il2CppMethodPointer (*)(const char *name)>(gum_module_find_export_by_name("libil2cpp.so", "il2cpp_resolve_icall"));
    SPDLOG_INFO("get il2cpp_resolve_icall address: {}", fmt::ptr(il2cpp_resolve_icall));

    gp_run = std::make_shared<std::thread>([]()
                                           {
                        do {
                            // il2cpp_init
                            InitResolveFunc(Screen$$get_height, "UnityEngine.Screen::get_height");
                            SPDLOG_DEBUG("get UnityEngine.Screen::get_height address: {}", fmt::ptr(Screen$$get_height));
                            InitResolveFunc(Screen$$get_width, "UnityEngine.Screen::get_width");
                            SPDLOG_DEBUG("get UnityEngine.Screen::get_height address: {}", fmt::ptr(Screen$$get_width));
                            // 使用Unity游戏内的导出方法 获取屏幕宽高
                            if (Screen$$get_height && Screen$$get_width)
                            {
                                SPDLOG_INFO("Screen size is {}x{}", Screen$$get_width(), Screen$$get_height());
                            }
                            std::this_thread::sleep_for(std::chrono::milliseconds(500));
                        } while (!Screen$$get_height && !Screen$$get_width);

                        InitResolveFunc(Time$$set_timeScale, "UnityEngine.Time::set_timeScale");
                        InitResolveFunc(Time$$get_timeScale, "UnityEngine.Time::get_timeScale");
                        SPDLOG_DEBUG("get get_timeScale: {}", fmt::ptr(Time$$get_timeScale));
                        SPDLOG_DEBUG("get set_timeScale: {}", fmt::ptr(Time$$set_timeScale));
                        if (Time$$get_timeScale && Time$$set_timeScale)
                        {
                            SPDLOG_INFO("Time scale is {}", Time$$get_timeScale());
                            Time$$set_timeScale(10.0f);
                            SPDLOG_INFO("Time scale set {}", Time$$get_timeScale());
                        }

                        InitResolveFunc(Time$$get_deltaTime, "UnityEngine.Time::get_fixedDeltaTime");
                        SPDLOG_DEBUG("get get_deltaTime: {}", fmt::ptr(Time$$get_deltaTime));

                        InitResolveFunc(Time$$set_fixedDeltaTime, "UnityEngine.Time::set_fixedDeltaTime");
                        InitResolveFunc(Time$$get_fixedDeltaTime, "UnityEngine.Time::get_fixedDeltaTime");
                        SPDLOG_DEBUG("get get_fixedDeltaTime: {}", fmt::ptr(Time$$get_fixedDeltaTime));
                        SPDLOG_DEBUG("get set_fixedDeltaTime: {}", fmt::ptr(Time$$set_fixedDeltaTime));
                        if (Time$$get_fixedDeltaTime && Time$$set_fixedDeltaTime)
                        {
                            auto value = Time$$get_fixedDeltaTime();
                            SPDLOG_INFO("fixed delta time is {}", value);
                            Time$$set_fixedDeltaTime(value);
                            SPDLOG_INFO("fixed delta time set {}", Time$$get_fixedDeltaTime());
                        }
                        
                        int64_t last_check = getUnixTimestamp(), now;
                        httplib::Client client("localhost", server_port);
                        std::string path = fmt::format("/status?name={}", process_name);
                        json req_body = {{"name", process_name}, {"speed", g_speed}, {"pid", pid}};
                        std::string body = req_body.dump();
                        while(1) {
                            now = getUnixTimestamp();
                            if (now - last_check > 900) {
                                last_check = now;
                                if (auto res = client.Post(path, body, "application/json")) {
                                    try
                                    {
                                        json json = json::parse(res->body);

                                        g_speed = json["speed"].get<int>();
                                        req_body["speed"] = g_speed;
                                        body = req_body.dump();
                                    }
                                    catch (const json::exception &e)
                                    {
                                        SPDLOG_ERROR("parse status error: {}", e.what());
                                    }
                                }
                            }
                            // LOGD("seconds");
                            if (Time$$set_timeScale) {
                                Time$$set_timeScale(g_speed);
                            }
                            std::this_thread::sleep_for(std::chrono::milliseconds(50));
                        } });
    gp_run->join();

    // gum_interceptor_end_transaction(interceptor);
    //
    // // g_object_unref (listener);
    // // g_object_unref (interceptor);
    // // gum_deinit_embedded();
}

// static int open_hook(const char *path, int oflag, ...)
// {
//     LOGD("open(\"%s\", 0x%x)", path, oflag);

//     return open(path, oflag);
// }

// static int gettimeofday_hook(struct timeval *tv, struct timezone *tz)
// {
//     int result = gettimeofday(tv, tz);
//     // LOGD("gettimeofday %p, %p %d", tv, tz, result);
//     // if (result == 0 && tv != NULL)
//     if (g_modify_time)
//     {
//         if (g_tv.tv_sec == 0)
//         {
//             g_tv.tv_sec = tv->tv_sec;
//             g_tv.tv_usec = tv->tv_usec;
//         }
//         tv->tv_sec = g_tv.tv_sec + (tv->tv_sec - g_tv.tv_sec) * g_speed;
//         tv->tv_usec = g_tv.tv_usec + (tv->tv_usec - g_tv.tv_usec) * g_speed;
//
//         // LOGD("gettimeofday %ld -> %ld,  %ld -> %ld", g_tv.tv_sec, tv->tv_sec, g_tv.tv_usec, tv->tv_usec);
//     }
//     g_modify_time = false;
//
//     return result;
// }

// static int clock_gettime_hook(clockid_t clock, struct timespec *ts)
// {
//     int result = clock_gettime(clock, ts);
//     // LOGD("clock_gettime %p, %p %d", &clock, ts, result);
//     // if (result == 0 && ts != NULL)
//     if (g_modify_time)
//     {
//         if (g_ts.tv_sec == 0)
//         {
//             g_ts.tv_sec = ts->tv_sec;
//             g_ts.tv_nsec = ts->tv_nsec;
//         }
//         ts->tv_sec = g_ts.tv_sec + (ts->tv_sec - g_ts.tv_sec) * g_speed;
//         ts->tv_nsec = g_ts.tv_nsec + (ts->tv_nsec - g_ts.tv_nsec) * g_speed;
//
//         // LOGD("clock_gettime time %ld -> %ld", g_ts.tv_sec, ts->tv_sec);
//     }
//     g_modify_time = false;
//
//     return result;
// }

__attribute__((constructor)) void constructor_main()
{
    LOGD("YYCheat");
    auto android_sink = std::make_shared<spdlog::sinks::android_sink_mt>("YY-INJECT");
    auto logger = std::make_shared<spdlog::logger>("InjectCheat", spdlog::sinks_init_list{android_sink});
    spdlog::set_default_logger(logger);
    spdlog::set_level(spdlog::level::debug);
}
