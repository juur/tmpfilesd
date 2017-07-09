#ifndef _UTIL_H
#define _UTIL_H

char *trim(char *str);
int is_dot(const char *path);
char *pathcat(const char *a, const char *b);
int isnumber(const char *t);

#define MAX(a, b) (a < b ? b : a)

#endif
