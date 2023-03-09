#pragma once
#include <android/log.h>
#include <errno.h>

// 日志
#ifndef LOG_TAG
#define LOG_TAG "YY-INJECT"
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, __VA_ARGS__)
#define LOGW(...) __android_log_print(ANDROID_LOG_WARN, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#endif

#ifdef __GNUC__
    #define API  __attribute__((visibility("default")))
#else
    #define API
#endif
 
#if defined __cplusplus
    #define EXTERN extern "C"
#else
    #include <stdarg.h>
    #include <stdbool.h>
    #define EXTERN extern
#endif
 
#define YY_API EXTERN API
