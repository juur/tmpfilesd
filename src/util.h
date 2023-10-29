#ifndef _UTIL_H
#define _UTIL_H

#include <sys/stat.h>
#include <fcntl.h>

extern char *trim(char *str) __attribute__((nonnull));
extern int is_dot(const char *path) __attribute__((nonnull));
extern char *pathcat(const char *a, const char *b) __attribute__((nonnull));
extern int isnumber(const char *t) __attribute__((nonnull));
extern int mkpath(char *dir, mode_t mode) __attribute__((nonnull));

#define MAX(a, b) ((a) < (b) ? (b) : (a))
#define MIN(a, b) ((a) < (b) ? (a) : (b))

#endif
