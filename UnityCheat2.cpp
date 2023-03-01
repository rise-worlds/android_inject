#include <fcntl.h>
#include <frida-gum.h>
#include <unistd.h>
#include <thread>
#include <memory>
#include <Logger.hpp>
#include <ResolverInit.hpp>


static int g_speed = 5.0;
static bool g_modify_time = false;
static struct timeval g_tv = {0, 0};
static struct timespec g_ts = {0, 0};

static std::shared_ptr<std::thread> gp_run;
static unsigned long il2cppAddress = 0;     // 存储il2cpp.so基地址
int (*Screen$$get_height)();                // 预定义一个方法
int (*Screen$$get_width)();                 // 预定义一个方法
float (*Time$$get_timeScale)();             // 预定义一个方法
void (*Time$$set_timeScale)(float);         // 预定义一个方法
float (*Time$$get_deltaTime)();             // 预定义一个方法
float (*Time$$get_fixedDeltaTime)();        // 预定义一个方法
void (*Time$$set_fixedDeltaTime)(float);    // 预定义一个方法

// static int open_hook(const char *path, int oflag, ...);
// static int gettimeofday_hook(struct timeval *tv, struct timezone *tz);
// static int clock_gettime_hook(clockid_t clock, struct timespec *ts);

YY_API void example_agent_main(const gchar *data, gboolean *stay_resident)
{
    GumInterceptor *interceptor;

    /* We don't want to our library to be unloaded after we return. */
    *stay_resident = TRUE;

    gum_init_embedded();

    LOGD("example_agent_main(\"%s\")\n", data);

    interceptor = gum_interceptor_obtain();
    // listener = my_callback_listener_new();

    /* Transactions are optional but improve performance with multiple hooks. */
    gum_interceptor_begin_transaction(interceptor);

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
            LOGD("libil2cpp.so BaseAddress: %lx", il2cppAddress);
            break;
        }
        usleep(100);
    }
    
    LOGD("get il2cpp address: %#lx", il2cppAddress);
    // 初始化il2cpp API
    #define DO_API(r, n, p)    n = (r(*) p) gum_module_find_export_by_name("libil2cpp.so", #n)
    #include "Il2cppApi/il2cppApiFunctions.h"
    #undef DO_API
    // il2cpp_resolve_icall = reinterpret_cast<Il2CppMethodPointer (*)(const char *name)>(gum_module_find_export_by_name("libil2cpp.so", "il2cpp_resolve_icall"));
    LOGD("get il2cpp_resolve_icall address: %p", il2cpp_resolve_icall);

    // // il2cpp_init
    InitResolveFunc(Screen$$get_height, "UnityEngine.Screen::get_height");
    LOGD("get UnityEngine.Screen::get_height address: %p", Screen$$get_height);
    InitResolveFunc(Screen$$get_width, "UnityEngine.Screen::get_width");
    LOGD("get UnityEngine.Screen::get_height address: %p", Screen$$get_width);
    // 使用Unity游戏内的导出方法 获取屏幕宽高
    if (Screen$$get_height && Screen$$get_width)
    {
        LOGI("Screen height is %d \nScreen width is %d", Screen$$get_height(), Screen$$get_width());
    }

    InitResolveFunc(Time$$set_timeScale, "UnityEngine.Time::set_timeScale");
    InitResolveFunc(Time$$get_timeScale, "UnityEngine.Time::get_timeScale");
    LOGD("get get_timeScale: %p", Time$$get_timeScale);
    LOGD("get set_timeScale: %p", Time$$set_timeScale);
    if (Time$$get_timeScale && Time$$set_timeScale)
    {
        LOGI("Time scale is %f \n", Time$$get_timeScale());
        Time$$set_timeScale(10.0f);
        LOGI("Time scale set %f \n", Time$$get_timeScale());
    }

    InitResolveFunc(Time$$get_deltaTime, "UnityEngine.Time::get_fixedDeltaTime");
    LOGD("get get_deltaTime: %p", Time$$get_deltaTime);

    InitResolveFunc(Time$$set_fixedDeltaTime, "UnityEngine.Time::set_fixedDeltaTime");
    InitResolveFunc(Time$$get_fixedDeltaTime, "UnityEngine.Time::get_fixedDeltaTime");
    LOGD("get get_fixedDeltaTime: %p", Time$$get_fixedDeltaTime);
    LOGD("get set_fixedDeltaTime: %p", Time$$set_fixedDeltaTime);
    if (Time$$get_fixedDeltaTime && Time$$set_fixedDeltaTime)
    {
        LOGI("fixed delta time is %f \n", Time$$get_fixedDeltaTime());
        Time$$set_fixedDeltaTime(1.0f);
        LOGI("fixed delta time set %f \n", Time$$get_fixedDeltaTime());
    }

    gum_interceptor_end_transaction(interceptor);

    // g_object_unref (listener);
    // g_object_unref (interceptor);
    // gum_deinit_embedded();

    gp_run = std::make_shared<std::thread>([]()
                    {
                        while(1) {
                            // LOGD("seconds");
                            if (Time$$set_timeScale) {
                                Time$$set_timeScale(10.0f);
                            }
                            std::this_thread::sleep_for(std::chrono::milliseconds(10));
                        }
                    });
    gp_run->join();
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
}
