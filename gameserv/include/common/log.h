#ifndef _COMMON_LOG_H_
#define _COMMON_LOG_H_

#include <stdint.h>

#ifdef ANDROID

#ifndef LOG_TAG
#define LOG_TAG "gameserv"
#endif

#include "jni.h"
#include <android/log.h>

#define LOGV(...) __android_log_print(ANDROID_LOG_VERBOSE, LOG_TAG, __VA_ARGS__)
#define LOGD(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define LOGW(...) __android_log_print(ANDROID_LOG_WARN, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

#else

#include <stdio.h>

#define LOGV(...)    printf(__VA_ARGS__)
#define LOGD(...)    printf(__VA_ARGS__)
#define LOGI(...)    printf(__VA_ARGS__)
#define LOGW(...)    printf(__VA_ARGS__)
#define LOGE(...)    printf(__VA_ARGS__)

#endif

#ifdef VDEBUG

#define  logv( fmt... )   LOGV(fmt)

static inline void dump_data(const char *desc, void *data, int len) 
{
    int i;
    uint8_t *p = (uint8_t *)data;

    logd("[%s]dump data(%d):\n", desc, len);
    for(i=0; i<len; i++) {
        if((i % 16) == 0)
            logd("\n");
        logd("%02x ", *(p + i));
    }

    logd("\n");
}

#else

#define  logv( fmt... )

static inline void dump_data(const char *desc, void *data, int len) 
{
}

#endif

/* XXX */
//#ifdef DEBUG
#if 1
#define  logd( fmt... )   LOGD(fmt)
#else
#define  logd( fmt... )
#endif

#define  logi( fmt... )   LOGI(fmt)
#define  logw( fmt... )   LOGW(fmt)
#define  loge( fmt... )   LOGE(fmt)

#define fatal(...) 	do { loge(__VA_ARGS__); exit(-1); } while(0)


#endif

