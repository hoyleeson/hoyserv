#ifndef _COMMON_LOG_H_
#define _COMMON_LOG_H_

#include <stdint.h>

#ifdef ANDROID

#ifndef LOG_TAG
#define LOG_TAG "UINPUT"
#endif

#include "jni.h"
#include <android/log.h>

#define LOGV(...) __android_log_print(ANDROID_LOG_VERBOSE, LOG_TAG, __VA_ARGS__)
#define LOGD(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define LOGW(...) __android_log_print(ANDROID_LOG_WARN, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

#define  logv( fmt... )   LOGV(fmt)
#define  logd( fmt... )   LOGD(fmt)
#define  logi( fmt... )   LOGI(fmt)
#define  logw( fmt... )   LOGW(fmt)
#define  loge( fmt... )   LOGE(fmt)

#else

#include <stdio.h>

#define  logd( fmt... )   printf( fmt)
#define  logi( fmt... )   printf( fmt)
#define  logw( fmt... )   printf( fmt)
#define  loge( fmt... )   printf( fmt)

#endif

#define fatal(...) 	do { loge(__VA_ARGS__); exit(-1); } while(0)

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


#endif

