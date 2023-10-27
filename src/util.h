#ifndef _UTIL_H
#define _UTIL_H

#include <sys/stat.h>
#include <fcntl.h>

char *trim(char *str) __attribute__((nonnull));
int is_dot(const char *path) __attribute__((nonnull));
char *pathcat(const char *a, const char *b) __attribute__((nonnull));
int isnumber(const char *t) __attribute__((nonnull));
int mkpath(char *dir, mode_t mode) __attribute__((nonnull));

#define MAX(a, b) (a < b ? b : a)

#endif
