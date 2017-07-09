#define _GNU_SOURCE

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <err.h>
#include <unistd.h>
#include <ctype.h>

#include "util.h"

char *trim(char *str)
{

	if (str == NULL) {
		warnx("str is NULL");
		return str;
	}

	char *ret = str;
	int i, len;

	len = strlen(str);

	for (i = len - 1; i; i--)
	{
		if (isspace(str[i])) str[i] = '\0';
		else break;
	}
	
	len = strlen(str);

	for (i = 0; i < len; i++)
		if (!isspace(str[i])) break;

	if (i == 0) return str;

	if ( (ret = calloc(1, MAX(1, len - i))) == NULL )
		warn("calloc");
	else {
		snprintf(ret, len, "%s", str + i);
		free(str);
	}

	return ret;
}

int is_dot(char * const path)
{
	if( !path || !*path ) return 0;

	if( !strcmp(path, ".") || !strcmp(path, ".." ) )
		return 1;

	return 0;
}

char *pathcat(const char *a, const char *b)
{
	if ( !a || !b ) return NULL;

	int len = strlen(a) + strlen(b) + 2;
	char *ret = malloc(len);

	if ( !ret ) {
		warn("malloc");
		return NULL;
	}

	strncpy(ret, a, len);
	strncpy(ret, "/", len);
	strncat(ret, b, len);

	return ret;
}

int isnumber(char *t)
{
	int i;

	for (i=0; i<strlen(t); i++)
		if (!isdigit(t[i])) 
			return 0;

	return 1;
}


