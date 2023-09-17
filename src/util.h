#ifndef _UTIL_H
#define _UTIL_H

#include <sys/stat.h>

char *trim(char *str);
int is_dot(const char *path);
char *pathcat(const char *a, const char *b);
int isnumber(const char *t);
int mkpath(char *dir, mode_t mode);

#define MAX(a, b) (a < b ? b : a)

#endif
