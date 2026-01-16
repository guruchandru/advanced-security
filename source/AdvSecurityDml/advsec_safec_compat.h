/*
 * RBUS SafecLib Compatibility Layer - Full Functional Implementation
 * Based on common-library/source/cosa/include/safec_lib_common.h
 * Provides complete SafecLib functionality without external dependencies
 */

#ifndef _ADVSEC_SAFEC_COMPAT_H_
#define _ADVSEC_SAFEC_COMPAT_H_

#include <stdio.h>
#include <string.h>
#include <stddef.h>
#include <stdarg.h>
#include <errno.h>

/* SafecLib Error Codes - matching real SafecLib */
#ifndef EOK
#define EOK 0                           /* No error */
#endif

#ifndef ESNULLP
#define ESNULLP         400             /* null ptr */
#endif

#ifndef ESLEMAX  
#define ESLEMAX         403             /* length exceeds RSIZE_MAX */
#endif

#ifndef ESNOSPC
#define ESNOSPC         406             /* not enough space for dest */
#endif

#ifndef RSIZE_MAX
#define RSIZE_MAX       0x7FFFFFFF      /* Maximum safe string/memory size */
#endif

/* SafecLib Error Logging - based on RDK_SAFECLIB_ERR */
#define ADVSEC_SAFECLIB_ERR(rc) \
    printf("safeclib error at rc - %d %s %s:%d\n", (int)rc, __FILE__, __FUNCTION__, __LINE__)

/* String Copy Functions */
static inline errno_t strcpy_s(char *dst, size_t dmax, const char *src) {
    size_t src_len;
    
    if (dst == NULL) return ESNULLP;
    if (src == NULL) {
        if (dmax > 0) dst[0] = '\0';
        return ESNULLP;
    }
    if (dmax == 0) return ESLEMAX;
    if (dmax > RSIZE_MAX) return ESLEMAX;
    
    src_len = strlen(src);
    if (src_len >= dmax) {
        dst[0] = '\0';
        return ESNOSPC;
    }
    
    strcpy(dst, src);
    return EOK;
}

static inline errno_t strncpy_s(char *dst, size_t dmax, const char *src, size_t len) {
    size_t copy_len;
    
    if (dst == NULL) return ESNULLP;
    if (src == NULL) {
        if (dmax > 0) dst[0] = '\0';
        return ESNULLP;
    }
    if (dmax == 0) return ESLEMAX;
    if (dmax > RSIZE_MAX) return ESLEMAX;
    if (len > RSIZE_MAX) return ESLEMAX;
    
    copy_len = (len < strlen(src)) ? len : strlen(src);
    if (copy_len >= dmax) {
        dst[0] = '\0';
        return ESNOSPC;
    }
    
    strncpy(dst, src, copy_len);
    dst[copy_len] = '\0';
    return EOK;
}

/* String Concatenation Functions */
static inline errno_t strcat_s(char *dst, size_t dmax, const char *src) {
    size_t dst_len, src_len;
    
    if (dst == NULL) return ESNULLP;
    if (src == NULL) return ESNULLP;
    if (dmax == 0) return ESLEMAX;
    if (dmax > RSIZE_MAX) return ESLEMAX;
    
    dst_len = strlen(dst);
    src_len = strlen(src);
    
    if (dst_len + src_len >= dmax) {
        return ESNOSPC;
    }
    
    strcat(dst, src);
    return EOK;
}

static inline errno_t strncat_s(char *dst, size_t dmax, const char *src, size_t len) {
    size_t dst_len, copy_len;
    
    if (dst == NULL) return ESNULLP;
    if (src == NULL) return ESNULLP;
    if (dmax == 0) return ESLEMAX;
    if (dmax > RSIZE_MAX) return ESLEMAX;
    if (len > RSIZE_MAX) return ESLEMAX;
    
    dst_len = strlen(dst);
    copy_len = (len < strlen(src)) ? len : strlen(src);
    
    if (dst_len + copy_len >= dmax) {
        return ESNOSPC;
    }
    
    strncat(dst, src, copy_len);
    return EOK;
}

/* Memory Functions */
/* Note: memset_s is provided by the system on macOS */

static inline errno_t memcpy_s(void *dst, size_t dmax, const void *src, size_t len) {
    if (dst == NULL) return ESNULLP;
    if (src == NULL) return ESNULLP;
    if (dmax == 0) return ESLEMAX;
    if (dmax > RSIZE_MAX) return ESLEMAX;
    if (len > dmax) return ESNOSPC;
    if (len > RSIZE_MAX) return ESLEMAX;
    
    memcpy(dst, src, len);
    return EOK;
}

/* String Comparison Functions */
static inline errno_t strcmp_s(const char *dst, size_t dmax, const char *src, int *r) {
    if (dst == NULL || src == NULL || r == NULL) return ESNULLP;
    if (dmax == 0) return ESLEMAX;
    if (dmax > RSIZE_MAX) return ESLEMAX;
    
    *r = strcmp(dst, src);
    return EOK;
}

static inline errno_t strcasecmp_s(const char *dst, size_t dmax, const char *src, int *r) {
    if (dst == NULL || src == NULL || r == NULL) return ESNULLP;
    if (dmax == 0) return ESLEMAX;
    if (dmax > RSIZE_MAX) return ESLEMAX;
    
    *r = strcasecmp(dst, src);
    return EOK;
}

/* String Tokenization */
static inline char *strtok_s(char *dest, size_t *dmax, const char *delim, char **ptr) {
    (void)dmax; /* Unused in this implementation */
    return strtok_r(dest, delim, ptr);
}

/* Formatted String Functions */
static inline int sprintf_s(char *dst, size_t max, const char *fmt, ...) {
    va_list args;
    int len;
    
    if (dst == NULL || fmt == NULL || max == 0) {
        if (dst && max > 0) dst[0] = '\0';
        return -ESNULLP;
    }
    if (max > RSIZE_MAX) return -ESLEMAX;
    
    va_start(args, fmt);
    len = vsnprintf(dst, max, fmt, args);
    va_end(args);
    
    if (len < 0) return -ESNOSPC;
    if ((size_t)len >= max) return -ESNOSPC;
    
    return len;
}

static inline errno_t sscanf_s(const char *buffer, const char *fmt, ...) {
    va_list args;
    int result;
    
    if (buffer == NULL || fmt == NULL) return ESNULLP;
    
    va_start(args, fmt);
    result = vsscanf(buffer, fmt, args);
    va_end(args);
    
    return (result >= 0) ? EOK : ESNOSPC;
}

/* No-Clobber Versions - Advanced SafecLib variants */
#define STRCPY_S_NOCLOBBER(dst, dmax, src) \
    (((src) != NULL) ? (strlen(src) < (dmax) ? strcpy_s(dst, dmax, src) : ESNOSPC) : ESNULLP)

#define MEMCPY_S_NOCLOBBER(dst, dmax, src, len) \
    (((src) != NULL) ? ((len) <= (dmax) ? memcpy_s(dst, dmax, src, len) : ESNOSPC) : ESNULLP)

/* ERR_CHK already defined in advsec_compat_types.h */

#endif /* _ADVSEC_SAFEC_COMPAT_H_ */