/* mkpath() -- Create all components leading up to a given directory
 *
 * Copyright (c) 2013-2016  Joachim Nilsson <troglobit@gmail.com>
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#define _XOPEN_SOURCE 700
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>
#include <libgen.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <string.h>

/**
 * mkpath - Like makepath() but takes a mode_t argument
 * @dir:  Directory to created, relative or absolute
 * @mode: A &mode_t mode to create @dir with
 *
 * Returns:
 * POSIX OK(0) on success, otherwise -1 with @errno set.
 */
int mkpath(char *dir, mode_t mode)
{
	struct stat sb;
	char *tmp;

	if (dir == NULL) {
		errno = EINVAL;
		return -1;
	}

	if (stat(dir, &sb) == 0)
		return 0;

	if (errno != ENOENT)
		return -1;

	if ((tmp = strdup(dir)) == NULL)
		return -1;

	mkpath(dirname(tmp), mode);

	free(tmp);

	return mkdir(dir, mode);
}

/**
 * makepath - Create all components of the specified directory.
 * @dir: Directory to create.
 *
 * Returns:
 * POSIX OK (0) on success, otherwise -1 and errno set appropriately.
 * This function returns EINVAL on bad argument, or ENOMEM when it
 * fails allocating temporary memory.  For other error codes see the
 * mkdir() syscall description.
 */
int makepath(char *dir)
{
	return mkpath(dir, 0777);
}

/**
 * Local Variables:
 *  indent-tabs-mode: t
 *  c-file-style: "linux"
 * End:
 */
