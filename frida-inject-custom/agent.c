#include <fcntl.h>
#include <frida-gum.h>
#include <unistd.h>
#include <android/log.h>

#define TEST_TYPE_CALLBACK_LISTENER (my_callback_listener_get_type())
G_DECLARE_FINAL_TYPE(MyCallbackListener, my_callback_listener, MY,
                     CALLBACK_LISTENER, GObject)

typedef void (*MyCallbackListenerFunc)(gpointer user_data, GumInvocationContext *context);
typedef enum _MyHookId MyHookId;

struct _MyCallbackListener
{
    GObject parent;

    MyCallbackListenerFunc on_enter;
    MyCallbackListenerFunc on_leave;
    gpointer user_data;
};

enum _MyHookId
{
  MY_HOOK_StringFromJNI,
  MY_HOOK_GetTimeOfDay,
  MY_HOOK_ClockGetTime
};

MyCallbackListener *my_callback_listener_new(void);

static int g_speed = 5.0;
static bool g_modify_time = false;
static struct timeval g_tv = {0, 0};
static struct timespec g_ts = {0, 0};

static int open_hook(const char *path, int oflag, ...);
static int gettimeofday_hook(struct timeval *tv, struct timezone *tz);
static int clock_gettime_hook(clockid_t clock, struct timespec *ts);

void example_agent_main(const gchar *data, gboolean *stay_resident)
{
    GumInterceptor *interceptor;
    MyCallbackListener *listener;

    /* We don't want to our library to be unloaded after we return. */
    *stay_resident = TRUE;

    gum_init_embedded();

    g_printerr("example_agent_main(\"%s\")\n", data);

    interceptor = gum_interceptor_obtain();
    listener = my_callback_listener_new();

    /* Transactions are optional but improve performance with multiple hooks. */
    gum_interceptor_begin_transaction(interceptor);

    gum_interceptor_replace(interceptor, (gpointer)gum_module_find_export_by_name(NULL, "open"), &open_hook, NULL, NULL);
    gum_interceptor_replace(interceptor, (gpointer)gum_module_find_export_by_name(NULL, "gettimeofday"), &gettimeofday_hook, NULL, NULL);
    // gum_interceptor_replace(interceptor, (gpointer)gum_module_find_export_by_name(NULL, "clock_gettime"), &clock_gettime_hook, NULL, NULL);

    GumAddress address = gum_module_find_export_by_name("libtimetest.so", "Java_com_example_timetest_MainActivity_stringFromJNI");
    g_printerr("stringFromJNI addr:%d\n", address);
    if (address > 0)
    {
        gum_interceptor_attach(interceptor,
                            GSIZE_TO_POINTER(address),
                            GUM_INVOCATION_LISTENER(listener),
                            GSIZE_TO_POINTER(MY_HOOK_StringFromJNI));
    }

    /*
     * ^
     * |
     * This is using replace(), but there's also attach() which can be used to hook
     * functions without any knowledge of argument types, calling convention, etc.
     * It can even be used to put a probe in the middle of a function.
     */

    gum_interceptor_end_transaction(interceptor);

    // g_object_unref (listener);
    // g_object_unref (interceptor);
    // gum_deinit_embedded();
}

static int open_hook(const char *path, int oflag, ...)
{
    g_printerr("open(\"%s\", 0x%x)\n", path, oflag);

    return open(path, oflag);
}

static int gettimeofday_hook(struct timeval *tv, struct timezone *tz)
{
    int result = gettimeofday(tv, tz);
    // g_printerr("gettimeofday %p, %p %d", tv, tz, result);
    // if (result == 0 && tv != NULL)
    if (g_modify_time)
    {
        if (g_tv.tv_sec == 0)
        {
            g_tv.tv_sec = tv->tv_sec;
            g_tv.tv_usec = tv->tv_usec;
        }
        tv->tv_sec = g_tv.tv_sec + (tv->tv_sec - g_tv.tv_sec) * g_speed;
        tv->tv_usec = g_tv.tv_usec + (tv->tv_usec - g_tv.tv_usec) * g_speed;

        // g_printerr("gettimeofday %ld -> %ld,  %ld -> %ld\n", g_tv.tv_sec, tv->tv_sec, g_tv.tv_usec, tv->tv_usec);
    }
    g_modify_time = false;

    return result;
}

static int clock_gettime_hook(clockid_t clock, struct timespec *ts)
{
    int result = clock_gettime(clock, ts);
    // g_printerr("clock_gettime %p, %p %d", &clock, ts, result);
    if (result == 0 && ts != NULL)
    {
        if (g_ts.tv_sec == 0)
        {
            g_ts.tv_sec = ts->tv_sec;
            g_ts.tv_nsec = ts->tv_nsec;
        }
        ts->tv_sec = g_ts.tv_sec + (ts->tv_sec - g_ts.tv_sec) * g_speed;
        ts->tv_nsec = g_ts.tv_nsec + (ts->tv_nsec - g_ts.tv_nsec) * g_speed;

        g_printerr("clock_gettime time %ld -> %ld", g_ts.tv_sec, ts->tv_sec);
    }

    return result;
}

static void my_callback_listener_iface_init(gpointer g_iface,
                                              gpointer iface_data);

G_DEFINE_TYPE_EXTENDED(MyCallbackListener,
                       my_callback_listener,
                       G_TYPE_OBJECT,
                       0,
                       G_IMPLEMENT_INTERFACE(GUM_TYPE_INVOCATION_LISTENER,
                                             my_callback_listener_iface_init))

static void
my_callback_listener_on_enter(GumInvocationListener *listener,
                                GumInvocationContext *context)
{
    __android_log_print(ANDROID_LOG_DEBUG, "yy-hook", "enter stringFromJNI %p -> %p", listener, context);
    MyCallbackListener *self = MY_CALLBACK_LISTENER(listener);
    MyHookId hook_id = GUM_IC_GET_FUNC_DATA(context, MyHookId);

    if (hook_id == MY_HOOK_StringFromJNI)
    {
        g_modify_time = true;
    }
    if (self->on_enter != NULL)
        self->on_enter(self->user_data, context);
}

static void
my_callback_listener_on_leave(GumInvocationListener *listener,
                                GumInvocationContext *context)
{
    __android_log_print(ANDROID_LOG_DEBUG, "yy-hook", "leave stringFromJNI %p -> %p", listener, context);
    MyCallbackListener *self = MY_CALLBACK_LISTENER(listener);

    g_modify_time = false;
    if (self->on_leave != NULL)
        self->on_leave(self->user_data, context);
}

static void
my_callback_listener_iface_init(gpointer g_iface,
                                  gpointer iface_data)
{
    GumInvocationListenerInterface *iface = g_iface;

    iface->on_enter = my_callback_listener_on_enter;
    iface->on_leave = my_callback_listener_on_leave;
}

static void
my_callback_listener_class_init(MyCallbackListenerClass *klass)
{
}

static void
my_callback_listener_init(MyCallbackListener *self)
{
}

MyCallbackListener *my_callback_listener_new(void)
{
    return g_object_new(TEST_TYPE_CALLBACK_LISTENER, NULL);
}
