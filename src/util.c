#define _XOPEN_SOURCE 700

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <err.h>
#include <unistd.h>
#include <ctype.h>
#include <stdbool.h>

#include "util.h"

/* TODO refactor to not free(str) */
char *trim(char *str)
{
	char *ret = str;
	int i, len;

	len = strlen(str);

	for (i = len - 1; i; i--)
	{
		if (isspace(str[i])) 
			str[i] = '\0';
		else 
			break;
	}
	
	len = strlen(str);

	for (i = 0; i < len; i++)
		if (!isspace(str[i]))
			break;

	if (i == 0)
		return str;

	if ( (ret = calloc(1, MAX(1, len - i))) == NULL )
		warn("trim: calloc");
	else {
		snprintf(ret, len, "%s", str + i);
		free(str);
	}

	return ret;
}

int is_dot(const char *path)
{
	if( !*path )
		return false;

	if( !strcmp(path, ".") || !strcmp(path, ".." ) )
		return true;

	return false;
}

char *pathcat(const char *a, const char *b)
{
	size_t len = strlen(a) + strlen(b) + 2;
	char *ret;

	if ( (ret = malloc(len)) == NULL ) {
		warn("malloc");
		return NULL;
	}

	strncpy(ret, a, len);
	if ( *b != '/' && a[strlen(a)-1] != '/')
		strncat(ret, "/", len);
	strncat(ret, b, len);

	return ret;
}

int isnumber(const char *t)
{
	size_t i;

	for (i = 0; i < strlen(t); i++)
		if( !isdigit(t[i]) )
			return false;

	return true;
}


