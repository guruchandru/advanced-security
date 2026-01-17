/*
 * Advanced Security User Base Platform Interface
 * This provides Linux platform-specific definitions and threading APIs
 * for the Advanced Security RBUS implementation
 *
 * Copyright 2016 Comcast Cable Communications Management, LLC
 * Licensed under the Apache License, Version 2.0
 */

#ifndef _ADVSECURITY_USER_BASE_H_
#define _ADVSECURITY_USER_BASE_H_

/*
 * Include our compatibility types which handles most Advanced Security definitions
 */
#include "advsec_compat_types.h"

/*
 * Linux platform includes for threading and synchronization
 */
#include <pthread.h>
#include <semaphore.h>
#include <sys/ipc.h>
#include <sys/sem.h>
#include <sys/shm.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netdb.h>
#include <fcntl.h>
#include <assert.h>
#include <stdarg.h>

/*
 * Platform detection and basic definitions
 */
#define LINUX
#ifndef _ADVSEC_LINUX
#define _ADVSEC_LINUX
#endif

#ifndef _ADVSEC_LITTLE_ENDIAN_
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#define _ADVSEC_LITTLE_ENDIAN_
#endif
#endif

/*
 * Linux User-mode platform synchronization primitives
 */
typedef pthread_mutex_t             ADVSEC_LOCK, *PADVSEC_LOCK;
typedef sem_t                       ADVSEC_SEMAPHORE, *PADVSEC_SEMAPHORE;
typedef ADVSEC_LOCK                 ADVSEC_SPINLOCK, *PADVSEC_SPINLOCK;

/* Legacy compatibility typedefs */
typedef ADVSEC_LOCK                 USER_LOCK, *PUSER_LOCK;
typedef ADVSEC_SEMAPHORE            USER_SEMAPHORE, *PUSER_SEMAPHORE;
typedef ADVSEC_SPINLOCK             USER_SPINLOCK, *PUSER_SPINLOCK;

/*
 * Event structures for advanced security components
 */
#ifndef _BUILD_ANDROID
union semun {
    int val;
    struct semid_ds* buf;
    unsigned short int* array;
    struct seminfo* __buf;
};

typedef struct _advsec_event {
    int eventId;
    key_t keyId;
} ADVSEC_EVENT, *PADVSEC_EVENT;

typedef struct _advsec_sem_event {
    int inited;
    sem_t sem;
} ADVSEC_SEM_EVENT, *PADVSEC_SEM_EVENT;

/* Legacy compatibility typedefs */
typedef ADVSEC_EVENT                USER_EVENT, *PUSER_EVENT;
typedef ADVSEC_SEM_EVENT            SEM_EVENT, *PSEM_EVENT;

#else
typedef struct _advsec_event {
    pthread_mutex_t msg_mutex;
    pthread_cond_t msg_threshold_cv;
} ADVSEC_EVENT, *PADVSEC_EVENT, ADVSEC_SEM_EVENT, *PADVSEC_SEM_EVENT;

typedef ADVSEC_EVENT                USER_EVENT, *PUSER_EVENT, SEM_EVENT, *PSEM_EVENT;
#endif

/*
 * Memory cache structure for platform memory management
 */
typedef struct _ADVSEC_MEMORY_CACHE {
    ULONG ulBlockSize;
} ADVSEC_MEMORY_CACHE, *PADVSEC_MEMORY_CACHE;

/* Legacy compatibility typedef */
typedef ADVSEC_MEMORY_CACHE         USER_MEMORY_CACHE, *PUSER_MEMORY_CACHE;

/*
 * Linux task/threading priority definitions
 */
#define ADVSEC_TASK_PRIORITY_HIGH   1
#define ADVSEC_TASK_PRIORITY_NORMAL 0
#define ADVSEC_TASK_PRIORITY_LOW    -1
#define ADVSEC_TASK_STACK_SIZE      16384

/* Legacy compatibility defines */
#define USER_TASK_PRIORITY_HIGH     ADVSEC_TASK_PRIORITY_HIGH
#define USER_TASK_PRIORITY_NORMAL   ADVSEC_TASK_PRIORITY_NORMAL
#define USER_TASK_PRIORITY_LOW      ADVSEC_TASK_PRIORITY_LOW
#define USER_TASK_STACK_SIZE        ADVSEC_TASK_STACK_SIZE

/*
 * System configuration constants
 */
#define ADVSEC_KERNEL_VERSION       "2.6"
#define ADVSEC_SYSTEM_LOG_FACILITY  LOG_USER

/* Legacy compatibility defines */
#define USER_KERNEL_VERSION         ADVSEC_KERNEL_VERSION
#define USER_SYSTEM_LOG_FACILITY    ADVSEC_SYSTEM_LOG_FACILITY

/*
 * Inline static function qualifiers for Linux
 */
#define __advsec_static_inline      static __inline__
#define _ADVSEC_STATIC_             static
#define _ADVSEC_INLINE_             __inline__

/* Legacy compatibility defines */
#define __static_inline             __advsec_static_inline
#define _USER_STATIC_               _ADVSEC_STATIC_
#define _USER_INLINE_               _ADVSEC_INLINE_

/*
 * Global event key for advanced security IPC
 */
extern key_t pubEventKey;

/*
 * Advanced Security Platform Threading API Implementation
 */

/**
 * Initialize a mutex lock
 */
static inline int AdvsecInitializeLock(PADVSEC_LOCK pLock) {
    if (!pLock) return -1;
    return pthread_mutex_init(pLock, NULL);
}

/**
 * Acquire a mutex lock
 */
static inline int AdvsecAcquireLock(PADVSEC_LOCK pLock) {
    if (!pLock) return -1;
    return pthread_mutex_lock(pLock);
}

/**
 * Release a mutex lock  
 */
static inline int AdvsecReleaseLock(PADVSEC_LOCK pLock) {
    if (!pLock) return -1;
    return pthread_mutex_unlock(pLock);
}

/**
 * Destroy a mutex lock
 */
static inline int AdvsecFreeLock(PADVSEC_LOCK pLock) {
    if (!pLock) return -1;
    return pthread_mutex_destroy(pLock);
}

/**
 * Initialize a semaphore
 */
static inline int AdvsecInitializeSemaphore(PADVSEC_SEMAPHORE pSemaphore, UINT uInitialCount, UINT uMaxCount) {
    (void)uMaxCount;  /* Not used in POSIX semaphores */
    if (!pSemaphore) return -1;
    return sem_init(pSemaphore, 0, uInitialCount);
}

/**
 * Wait on a semaphore
 */
static inline int AdvsecWaitSemaphore(PADVSEC_SEMAPHORE pSemaphore, ULONG ulTimeout) {
    if (!pSemaphore) return -1;
    
    if (ulTimeout == 0xFFFFFFFF) {  /* INFINITE wait */
        return sem_wait(pSemaphore);
    } else {
        struct timespec ts;
        clock_gettime(CLOCK_REALTIME, &ts);
        ts.tv_sec += ulTimeout / 1000;
        ts.tv_nsec += (ulTimeout % 1000) * 1000000;
        return sem_timedwait(pSemaphore, &ts);
    }
}

/**
 * Release/signal a semaphore
 */
static inline int AdvsecReleaseSemaphore(PADVSEC_SEMAPHORE pSemaphore, ULONG ulReleaseCount) {
    if (!pSemaphore) return -1;
    
    for (ULONG i = 0; i < ulReleaseCount; i++) {
        if (sem_post(pSemaphore) != 0) return -1;
    }
    return 0;
}

/**
 * Destroy a semaphore
 */
static inline int AdvsecFreeSemaphore(PADVSEC_SEMAPHORE pSemaphore) {
    if (!pSemaphore) return -1;
    return sem_destroy(pSemaphore);
}

/**
 * Initialize an event
 */
static inline int AdvsecInitializeEvent(PADVSEC_EVENT pEvent) {
#ifndef _BUILD_ANDROID
    if (!pEvent) return -1;
    pEvent->eventId = -1;
    pEvent->keyId = 0;
    return 0;
#else
    if (!pEvent) return -1;
    int result = pthread_mutex_init(&pEvent->msg_mutex, NULL);
    if (result != 0) return result;
    return pthread_cond_init(&pEvent->msg_threshold_cv, NULL);
#endif
}

/**
 * Set an event
 */
static inline int AdvsecSetEvent(PADVSEC_EVENT pEvent) {
#ifndef _BUILD_ANDROID
    /* Implementation for Linux IPC events */
    (void)pEvent;
    return 0;  /* Placeholder implementation */
#else
    if (!pEvent) return -1;
    pthread_mutex_lock(&pEvent->msg_mutex);
    pthread_cond_broadcast(&pEvent->msg_threshold_cv);
    pthread_mutex_unlock(&pEvent->msg_mutex);
    return 0;
#endif
}

/**
 * Reset an event
 */
static inline int AdvsecResetEvent(PADVSEC_EVENT pEvent) {
#ifndef _BUILD_ANDROID
    (void)pEvent;
    return 0;  /* Placeholder implementation */
#else
    /* For condition variables, reset is implicit */
    (void)pEvent;
    return 0;
#endif
}

/**
 * Wait for an event
 */
static inline int AdvsecWaitEvent(PADVSEC_EVENT pEvent, ULONG ulTimeout) {
#ifndef _BUILD_ANDROID
    (void)pEvent;
    (void)ulTimeout;
    return 0;  /* Placeholder implementation */
#else
    if (!pEvent) return -1;
    
    pthread_mutex_lock(&pEvent->msg_mutex);
    if (ulTimeout == 0xFFFFFFFF) {  /* INFINITE wait */
        pthread_cond_wait(&pEvent->msg_threshold_cv, &pEvent->msg_mutex);
    } else {
        struct timespec ts;
        clock_gettime(CLOCK_REALTIME, &ts);
        ts.tv_sec += ulTimeout / 1000;
        ts.tv_nsec += (ulTimeout % 1000) * 1000000;
        pthread_cond_timedwait(&pEvent->msg_threshold_cv, &pEvent->msg_mutex, &ts);
    }
    pthread_mutex_unlock(&pEvent->msg_mutex);
    return 0;
#endif
}

/**
 * Destroy an event
 */
static inline int AdvsecFreeEvent(PADVSEC_EVENT pEvent) {
#ifndef _BUILD_ANDROID
    (void)pEvent;
    return 0;  /* Placeholder implementation */
#else
    if (!pEvent) return -1;
    pthread_cond_destroy(&pEvent->msg_threshold_cv);
    pthread_mutex_destroy(&pEvent->msg_mutex);
    return 0;
#endif
}

/**
 * Get current system time in milliseconds
 */
static inline ULONG AdvsecGetTickInMilliSeconds(void) {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (ULONG)(tv.tv_sec * 1000 + tv.tv_usec / 1000);
}

/**
 * Get current system time in seconds  
 */
static inline ULONG AdvsecGetTickInSeconds(void) {
    return (ULONG)time(NULL);
}

/**
 * Platform-specific socket startup (no-op on Linux)
 */
static inline int AdvsecStartupSocketWrapper(void* param) {
    (void)param;
    return 0;  /* No-op on Linux */
}

/**
 * Platform-specific socket cleanup (no-op on Linux)
 */
static inline int AdvsecCleanupSocketWrapper(void* param) {
    (void)param;
    return 0;  /* No-op on Linux */
}

/**
 * Advanced Security specific logging mutex access
 */
extern pthread_mutex_t logMutex;
extern pthread_cond_t logCond;

/**
 * Initialize platform-specific logging
 */
static inline int AdvsecInitializeLogging(void) {
    /* logMutex and logCond are statically initialized */
    return 0;
}

/**
 * Acquire logging mutex
 */
static inline int AdvsecAcquireLogLock(void) {
    return pthread_mutex_lock(&logMutex);
}

/**
 * Release logging mutex
 */
static inline int AdvsecReleaseLogLock(void) {
    return pthread_mutex_unlock(&logMutex);
}

/* Legacy compatibility function aliases */
#define AnscInitializeLock          AdvsecInitializeLock
#define AnscAcquireLock             AdvsecAcquireLock
#define AnscReleaseLock             AdvsecReleaseLock
#define AnscFreeLock                AdvsecFreeLock
#define AnscInitializeSemaphore     AdvsecInitializeSemaphore
#define AnscWaitSemaphore           AdvsecWaitSemaphore
#define AnscReleaseSemaphore        AdvsecReleaseSemaphore
#define AnscFreeSemaphore           AdvsecFreeSemaphore
#define AnscInitializeEvent         AdvsecInitializeEvent
#define AnscSetEvent                AdvsecSetEvent
#define AnscResetEvent              AdvsecResetEvent
#define AnscWaitEvent               AdvsecWaitEvent
#define AnscFreeEvent               AdvsecFreeEvent
#define AnscGetTickInMilliSeconds   AdvsecGetTickInMilliSeconds
#define AnscGetTickInSeconds        AdvsecGetTickInSeconds
#define AnscStartupSocketWrapper    AdvsecStartupSocketWrapper
#define AnscCleanupSocketWrapper    AdvsecCleanupSocketWrapper
#define AnscInitializeLogging       AdvsecInitializeLogging
#define AnscAcquireLogLock          AdvsecAcquireLogLock
#define AnscReleaseLogLock          AdvsecReleaseLogLock

#endif /* _ADVSECURITY_USER_BASE_H_ */