#define _XOPEN_SOURCE 700

#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <getopt.h>
#include <err.h>
#include <dirent.h>
#include <errno.h>
#include <ctype.h>
#include <sys/time.h>
#include <sys/types.h>
#include <pwd.h>
#include <grp.h>
#include <unistd.h>
#include <sys/utsname.h>
#include <glob.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <time.h>
#include <stdbool.h>
#include <limits.h>

#include "config.h"
#include "util.h"

#define	CREAT_FILE	0x00
#define TRUNC_FILE	0x01
#define WRITE_ARG	0x02
#define MKDIR		0x04
#define MKDIR_RMF	0x05
#define CREATE_SVOL	0x06
#define CREATE_PIPE	0x08
#define CREATE_SYM	0x0A
#define	CREATE_CHAR	0x0C
#define CREATE_BLK	0x0E
#define	COPY		0x10
#define	IGN			0x12
#define	IGNR		0x13
#define	RM			0x14
#define	RMRF		0x15
#define	CHMOD		0x16
#define	CHMODR		0x17
#define	CHATTR		0x18
#define	CHATTRR		0x19
#define	ACL			0x20
#define	ACLR		0x21

#define MAX_TYPE	0x21

#define MAX(a, b) (a < b ? b : a)

#define DEF_FILE (S_IRUSR|S_IWUSR|S_IRGRP|S_IROTH)
#define DEF_FOLD (DEF_FILE|S_IXUSR|S_IXGRP|S_IXOTH)

#define MOD_BOOT_ONLY    (1<<0)
#define MOD_NO_ERR       (1<<1)
#define MOD_NOMATCH_RM   (1<<2)
#define MOD_BASE64       (1<<3)
#define MOD_SERVICE_CRED (1<<4)
#define MOD_PLUS         (1<<5)

static int do_create=0, do_clean=0, do_remove=0, do_boot=0;
static int do_help=0, do_version=0; 
static char *prefix = NULL, *exclude = NULL, *root = NULL;
static char **config_files = NULL;
static int num_config_files = 0;
static char *hostname = NULL;
static char *machineid = NULL;
static char *kernelrel = NULL;
static char *bootid = NULL;

typedef struct ignent {
	char path[PATH_MAX];
	bool contents;
} ignent_t;

static ignent_t *ignores = NULL;
int ignores_size = 0;

static void show_version(void)
{
	printf("tmpfilesd %s\n", VERSION);
	exit(EXIT_SUCCESS);
}

static void show_help(void)
{
	printf(
	"Usage: tmpfilesd [OPTIONS]... [CONFIGURATION FILE]...\n"
	"Manage tmpfiles entries\n\n"
	"  -h, --help                 show help\n"
	"      --version              show version number\n"
	"      --create               create or write to files\n"
	"      --clean                clean up files or folders\n"
	"      --remove               remove directories or filse\n"
	"      --boot                 also execute lines with a !\n"
	"      --prefix=PATH          only apply rules with a matching path\n"
	"      --exclude-prefix=PATH  ignores rules with paths that match\n"
	"      --root=ROOT            all paths including config will be prefixed\n"
	"\n"
	);

	exit(EXIT_SUCCESS);
}

__attribute__((nonnull))
static int validate_type(const char *raw, char *type)
{
	const char *tmp;
	int ret;

	ret = 0;

	*type = raw[0];

	for (tmp = (raw + 1); *tmp; tmp++)
		switch (*tmp)
		{
			case '+': ret |= MOD_PLUS;       break;
			case '~': ret |= MOD_BASE64;     break;
			case '-': ret |= MOD_NO_ERR;     break;
			case '!': ret |= MOD_BOOT_ONLY;  break;
			case '=': ret |= MOD_NOMATCH_RM; break;

			case '^': 
			default:
				warnx("type modifier '%c' is unsupported", isprint(*type) ? *type : '?');
				return -1;
		}

	return ret;
}

/*
 * If omitted or - use 0 unless z/Z then leave UID alone
 */
__attribute__((nonnull))
static uid_t vet_uid(const char **t, uid_t *defuid)
{
	if (/*!t ||*/ !*t || **t == '-') {
		*defuid = 1;
		return 0;
	}

	*defuid = 0;

	if (isnumber(*t))
		return atol(*t);

	struct passwd *pw;

	if ( (pw = getpwnam(*t)) == NULL) {
		warn("getpwnam");
		return -1;
	}

	return pw->pw_uid;
}

/*
 * If omitted or - use 0 unless z/Z then leave GID alone
 */
__attribute__((nonnull))
static gid_t vet_gid(const char **t, gid_t *defgid)
{
	if (/*!t ||*/ !*t || **t == '-') {
		*defgid = 1;
		return 0;
	}

	*defgid = 0;

	if (isnumber(*t))
		return atol(*t);

	struct group *gr;

	if ( (gr = getgrnam(*t)) == NULL) {
		warn("getgrnam");
		return -1;
	}

	return gr->gr_gid;
}


static const char *getbootid(void)
{
	if (bootid)
		return bootid;

	FILE *fp = NULL;
	size_t ign = 0;

	if ( (fp = fopen("/proc/sys/kernel/random/boot_id", "r")) == NULL ) {
		warn("fopen");
		return NULL;
	}

	if ( getline(&bootid, &ign, fp) < 36 ) {
		if (bootid) {
			free(bootid);
			bootid = NULL;
		}
		warnx("getline");
	}
	bootid = trim(bootid);
	fclose(fp);
	return bootid;
}


static const char *getkernelrelease(void)
{
	if (kernelrel)
		return kernelrel;

	struct utsname *un;

	if ( !(un = calloc(1, sizeof(struct utsname))) ) {
		warn("calloc");
		return NULL;
	}

	if ( uname(un) ) {
		warn("uname");
	} else {
		kernelrel = strdup(un->release);
	}

	free(un);
	return kernelrel;
}

static const char *gethost(void)
{
	if (hostname)
		return hostname;

	if ((hostname = calloc(1, HOST_NAME_MAX + 1)) == NULL)
		return NULL;

	if (gethostname(hostname, HOST_NAME_MAX)) {
		warn("gethostname");
		free(hostname);
		hostname = NULL;
	}

	return hostname;
}

static const char *getmachineid(void)
{
	if (machineid)
		return machineid;

	FILE *fp = NULL;
	size_t ign = 0;

	if ( !(fp = fopen("/etc/machine-id", "r")) ) {
		warn("getmachineid");
		return NULL;
	}

	if ( getline(&machineid, &ign, fp) < 32 ) {
		if (machineid) {
			free(machineid);
			machineid = NULL;
		}
		warnx("getline");
	}
	machineid = trim(machineid);
	fclose(fp);
	return machineid;
}

// FIXME implement '~'

/* if NULL/- files are 0644 and folders are 0755 except for z/Z where this
 * means mode will not be touched
 *
 * If prefixed with "~" this is masked on the already set bits.
 */
__attribute__((nonnull))
static int vet_mode(const char **t, int *mask, int *defmode)
{
	if (/*!t ||*/ !*t || **t == '-') {
		*defmode = 1;
		return -1;
	}

	*defmode = 0;

	const char *mod = *t;

	if (*mod == '~') {
		*mask = 1;
		mod++;
		return -1;
	} else
		*mask = 0;

	if (!isnumber(mod)) {
		errno = EINVAL;
		warn("vet_mode(%s)",mod);
		return -1;
	}

	// FIXME this is wrong :-(
	return strtol(mod, NULL, 8);
}

#define LEN 1024
__attribute__((nonnull))
static char *expand_path(char *path)
{
	//if (!path)
	//	return NULL;

	char *buf = calloc(1, LEN+1);
	char *ptr = path;
	const char *cpy;
	char tmp;
	int spos = 0, dpos = 0;

	if (!buf)
		err(1, "malloc");

	while((tmp = ptr[spos]) && dpos < LEN)
	{
		if (tmp != '%') {
			buf[dpos++] = ptr[spos++];
			continue;
		}

		tmp = ptr[++spos];
		if (dpos >= LEN || !tmp) 
			continue;

		switch (tmp)
		{
			case '%':
				buf[dpos++] = ptr[spos];
				break;
			case 'b':
				if ( !(cpy = getbootid()) ) continue;
				strncpy(buf+dpos, cpy, LEN-dpos);
				dpos += strlen(cpy);
				break;
			case 'm':
				if ( !(cpy = getmachineid()) ) continue;
				strncpy(buf+dpos, cpy, LEN-dpos);
				dpos += strlen(cpy);
				break;
			case 'H':
				if ( !(cpy = gethost()) ) continue;
				strncpy(buf+dpos, cpy, LEN-dpos);
				dpos += strlen(cpy);
				break;
			case 'v':
				if ( !(cpy = getkernelrelease()) ) continue;
				strncpy(buf+dpos, cpy, LEN-dpos);
				dpos += strlen(cpy);
				break;
			default:
				warnx("Unhandled expansion %c\n", tmp);
				break;
		}

		spos++;
	}

	free(path);
	return buf;
}
#undef LEN

/*
 * %m - Machine ID (machine-id(5))
 * %b - Boot ID
 * %H - Host name
 * %v - Kernel release (uname -r)
 * %% - %
 */
__attribute__((nonnull))
static char *vet_path(char *path)
{
	if (strchr(path, '%'))
		path = expand_path(path);

	return path;
}

/*
 * If an integer is given without a unit, s is assumed.
 *
 * When 0, cleaning is unconditional.
 *
 * If the age field starts with a tilde character "~", the clean-up is only 
 * applied to files and directories one level inside the directory specified,
 * but not the files and directories immediately inside it.
 */

__attribute__((nonnull))
static struct timeval *vet_age(const char **t, int *subonly)
{
	if (/*!t ||*/ !*t || **t == '-')
		return NULL;

	uint64_t val;
	int read, ret;
	char *tmp = NULL; 
	const char *src = *t;

	if (*src == '~') {
		*subonly = 1;
		src++;
	} else 
		*subonly = 0;

	read = sscanf(src, "%u%ms", &ret, &tmp);

	if (read == 0 || read > 2) {
		if (tmp) free(tmp);
		warnx("invalid age: %s\n", *t);
		return NULL;
	}

	if ( !tmp || !*tmp )
		val = (uint64_t)ret * 1000000;
	else if ( !strcmp(tmp, "ms") )
		val = (uint64_t)ret * 1000;
	else if ( !strcmp(tmp, "s") )
		val = (uint64_t)ret * 1000000;
	else if ( !strcmp(tmp, "m") || !strcmp(tmp, "min") )
		val = (uint64_t)ret * 1000000 * 60;
	else if ( !strcmp(tmp, "h") )
		val = (uint64_t)ret * 1000000 * 60 * 60;
	else if ( !strcmp(tmp, "d") ) {
		val = (uint64_t)ret * 1000000 * 60 * 60 * 24;
	} else if ( !strcmp(tmp, "w") )
		val = (uint64_t)ret * 1000000 * 60 * 60 * 24 * 7;
	else {
		if (tmp) free(tmp);
		warnx("invalid age: %s\n", *t);
		return NULL;
	}

	struct timeval *tv = calloc(1, sizeof(struct timeval));

	if (!tv) {
		warn("calloc");
		if (tmp) free(tmp);
		return NULL;
	}

	tv->tv_sec = (time_t)(val / 1000000);
	tv->tv_usec = (suseconds_t)(val % 1000000);

	if (tmp)
		free(tmp);

	return(tv);
}

__attribute__((nonnull))
static int glob_file(const char *path, char ***matches, size_t *count,
		glob_t **pglob)
{
	int r;

	if (*pglob == NULL) {
		*pglob = calloc(1, sizeof(glob_t));
		if (!*pglob) {
			warn("calloc");
			return -1;
		}
	}

	if ((r = glob(path, GLOB_NOSORT, NULL, *pglob))) {
		if (r != GLOB_NOMATCH) warnx("glob returned %u", r);
		*matches = NULL;
		*count = 0;
		globfree(*pglob);
		*pglob = NULL;
	} else {
		*matches = (**pglob).gl_pathv;
		*count = (**pglob).gl_pathc;
	}

	return r;
}

__attribute__((nonnull))
static int unlink_wrapper(const char *pathname, bool check_ignores)
{
	if (check_ignores)
		for (int i = 0; i < ignores_size; i++)
			if (!strcmp(pathname, ignores[i].path))
				return 0;

	return unlink(pathname);
}

__attribute__((nonnull))
static int rmifold(const char *path, const struct timeval *tv, bool check_ignores)
{
	struct stat sb;
	int fd;

	if ( (fd = open(path, O_RDONLY)) == -1) {
		warn("open(%s)", path);
		return -1;
	}

	if (fstat(fd, &sb) == -1 ) {
		close(fd);
		warn("fstat(%s)", path);
		return -1;
	}

	close(fd);

	time_t now = time(NULL);

	printf("%s mtime=%lu now=%lu age=%lu diff=%lu\n",
			path,
			sb.st_mtime,
			time(0),
			tv->tv_sec,
			time(0) - sb.st_mtime);

	if (S_ISDIR(sb.st_mode)) {
		errno = ENOSYS;
		warn("aged delete folder(%s)", path);
		return -1;
	} else if ((now - sb.st_mtime) > tv->tv_sec) {
		return unlink_wrapper(path, check_ignores);
	}

	return 0;
}

__attribute__((nonnull(1)))
static int rmrf(const char *path, const struct timeval *tv, bool check_ignores)
{
	if (/*!path ||*/ !strcmp("/", path) || !strcmp(".", path) || !strcmp("..", path)) {
		errno = EINVAL;
		return -1;
	}

	char *buf = NULL;
	struct stat sb;
	int fd = -1;

	if ( (fd = open(path, O_RDONLY)) == -1)  {
		warn("rmrf: open");
		return -1;
	}

	if (fstat(fd, &sb) == -1) {
		warn("rmrf: fstat");
		close(fd);
		return -1;
	}

	close(fd);

	if (S_ISDIR(sb.st_mode)) {
		DIR *d = opendir(path);

		if (!d) {
			warn("rmrf: opendir");
			return -1;
		}

		struct dirent *ent;

		while ( (ent = readdir(d)) )
		{
			if (is_dot(ent->d_name))
				continue;

			if ( (buf = pathcat(path, ent->d_name)) ) 
			{
				if (rmrf(buf, tv, check_ignores)) {
					free(buf);
					break;
				}
				free(buf);
			}
		}

		closedir(d);

		if (errno) 
			return -1;
	} else if (tv) {
		return rmifold(path, tv, check_ignores);
	} else {
		return unlink_wrapper(path, check_ignores);
	}

	return 0;
}

__attribute__((nonnull))
static void process_line(const char *line)
{
	char *rawtype = NULL, *tmppath = NULL, *path = NULL; 
	char *modet = NULL, *dest = NULL;
	char *uidt = NULL, *gidt = NULL, *aget = NULL, *arg = NULL;
	char type;
	int boot_only = 0, act = -1, subonly = 0;
	int fields = 0, defmode = 0;
	char **globs = NULL;
	size_t nglobs = 0;
	glob_t *fileglob = NULL;
	int fd = -1;
	int ret;

	uid_t uid = 0; uid_t defuid = 0;
	gid_t gid = 0; gid_t defgid = 0;
	mode_t mode = 0; int mask = 0;
	dev_t dev = 0;
	int mod = 0;

	struct timeval *age = NULL;

	fields = sscanf(line, 
			"%ms %ms %ms %ms %ms %ms %m[^\n]s",
			&rawtype, &tmppath, &modet, &uidt, &gidt, &aget, &arg);

	if ( prefix && strncmp(prefix, tmppath, strlen(prefix)) )
		goto cleanup;

	if ( exclude && !strncmp(exclude, tmppath, strlen(exclude)) )
		goto cleanup;

	if ( fields < 2 ) {
		warnx("bad line: %s\n", line);
		goto cleanup;
		return;
	} else if ( (mod = validate_type(rawtype, &type)) == -1 ) {
		warnx("bad type: %s\n", line);
		goto cleanup;
		return;
	} else {
		switch(type)
		{
			case 'f':	act = CREAT_FILE;	break;
			case 'F':	act = TRUNC_FILE;	break;
			case 'w':	act = WRITE_ARG;	break;
			case 'd':	act = MKDIR;		break;
			case 'D':	act = MKDIR_RMF;	break;
			case 'v':	act = CREATE_SVOL;	break;
			case 'p':	act = CREATE_PIPE;	break;
			case 'L':	act = CREATE_SYM;	break;
			case 'c':	act = CREATE_CHAR;	break;
			case 'b':	act = CREATE_BLK;	break;
			case 'C':	act = COPY;			break;
			case 'x':	act = IGNR;			break;
			case 'X':	act = IGN;			break;
			case 'r':	act = RM;			break;
			case 'R':	act = RMRF;			break;
			case 'z':	act = CHMOD;		break;
			case 'Z':	act = CHMODR;		break;
			case 't':	act = CHATTR;		break;
			case 'T':	act = CHATTRR;		break;
			case 'a':	act = ACL;			break;
			case 'A':	act = ACLR;			break;
			default:
						warnx("unknown type: %s\n", line);
						goto cleanup;
						return;
		}
	}

	path = pathcat(root, tmppath);
	free(tmppath);

	if (uidt) uid = vet_uid((const char **)&uidt, &defuid);
	if (gidt) gid = vet_gid((const char **)&gidt, &defgid);
	if (modet) mode = vet_mode((const char **)&modet, &mask, &defmode);
	// FIXME handle '~'
	if (aget) age = vet_age((const char **)&aget, &subonly);
	if (path) path = vet_path(path);

	if (path == NULL)
		return;

	int i;

	if ( (do_boot && boot_only) || !boot_only ) {
		switch(act)
		{

			/* w - Write the argument parameter to a file
			 *
			 * Argument:
			 * For f, F, and w may be used to specify a short string
			 * that is written to the file, suffixed by a newline
			 */
			case WRITE_ARG:
				glob_file(path, &globs, &nglobs, &fileglob);
				if (do_create || do_clean)
				{
					dest = pathcat(root, arg);
					for (i=0; i<(int)nglobs; i++) {
						/* TODO */
						printf("[%u] write %s=%s %s%s", i, path, dest, 
								do_clean ? "clean " : "",
								do_create ? "create " : "");
						if (do_clean && age)
							printf("age=%lu", age->tv_sec);
						puts("\n");
					}
				}
				break;

				/* r - Remove a file or directory if it exists (empty only)
				 * R - Recursively remove a path and all its subdirectories
				 *
				 * Mode: ignored
				 * UID, GID: ignored
				 * Age: ignored
				 */
			case RM:
			case RMRF:
				if (!do_remove) 
					break;
				
				glob_file(path, &globs, &nglobs, &fileglob);

				for (i = 0; i < (int)nglobs; i++)
				{
					if (act == RMRF) {
						if (rmrf(globs[i], NULL, false))
							warn("rmrf(%s)",globs[i]);
					} else
						unlink_wrapper(globs[i], false);

				}
				break;

				/* x - Ignore a path during cleaning (plus contents)
				 * X - Ignore a path during cleaning (ignores contents)
				 *
				 * Mode: ignored
				 * UID, GID: ignored
				 */
			case IGN:
			case IGNR:
				glob_file(path, &globs, &nglobs, &fileglob);
				for (i=0; i<(int)nglobs; i++)
				{
					ignores = realloc( ignores, (sizeof(ignent_t) * (ignores_size+1)) );
					if (!ignores) {
						warn("realloc");
						break;
					}

					strncpy(ignores[ignores_size].path, globs[i], PATH_MAX - 1);
					ignores[ignores_size].contents = (act == IGN) ? true : false;
					ignores_size++;

					//printf("[%u] ignore/r %s\n", i, globs[i]);
				}
				break;

				/* z - Adjust the access mode, group and user, and restore the 
				 *     SELinux security context (if it exists)
				 * Z - As above, recursively.
				 *
				 * Mode: NULL/- means do not change
				 * UID, GID: NULL/- means do not change
				 */
			case CHMOD:
			case CHMODR:
				glob_file(path, &globs, &nglobs, &fileglob);
				struct stat sb;
				if (do_create) {
					mode_t mmode = mode;

					for (i=0; i<(int)nglobs; i++) {

						if (defmode) {
							if (stat(globs[i], &sb) == -1)
								warn("stat(%s)", globs[i]);
							else {
								if (S_ISDIR(sb.st_mode)) 
									mmode = DEF_FOLD;
								else
									mmode = DEF_FILE;
							}
						} 

						if (mask) {
							errno = ENOSYS;
							warn("chmod(%s,%s)", globs[i], modet);
						} else {
							warnx("chmod(%s,%u)", globs[i], mmode);

							if (chmod(globs[i], mmode))
								warn("chmod(%s,%s)", globs[i], modet);
						}
						/* FIXME is the logic around -1 right here ? */
						if (lchown(globs[i], defuid ? (uid_t)-1 : uid, 
									defgid ? (gid_t)-1 : gid))
							warn("lchown(%s,%s,%s)", globs[i], uidt, gidt);
					}
				}
				break;

				/* t - Set extended attributes
				 * T - Set extended attributes, recursively
				 *
				 * Mode: ignored
				 * UID, GID: ignored
				 * Age: ignored
				 */
			case CHATTR:
			case CHATTRR:
				glob_file(path, &globs, &nglobs, &fileglob);
				if (do_create) {
					dest = pathcat(root, arg);
					for (i=0; i<(int)nglobs; i++) {
						/* TODO */
						warnx("[%u] path=%s dest=%s\n", i, globs[i], dest);
					}
				}
				//printf("chattr/chattrr\n\n");
				break;

				/* a/a+ - Set POSIX ACLs. If suffixed with +, specified entries 
				 *        will be added to the existing set
				 * A/A+ - as above, but recursive.
				 *
				 * Mode: ignored
				 * UID, GID: ignored
				 * Age: ignored
				 */
			case ACL:
			case ACLR:
				glob_file(path, &globs, &nglobs, &fileglob);
				if (do_create) {
					dest = pathcat(root, arg);
					for (i=0; i<(int)nglobs; i++) {
						/* TODO */
						printf("[%u] path=%s dest=%s\n", i, globs[i], dest);
					}
				}
				break;

				/* v - create subvolume, or behave as d if not supported 
				*/
			case CREATE_SVOL:
				//				errno = ENOSYS;
				//				warn("subvol(%s)", path);
				break;

				/* d - create a directory (if does not exist)
				 * D - create a direcotry (delete contents if exists)
				 */
			case MKDIR:
			case MKDIR_RMF:
				if ( (do_clean && age) || (do_remove && act == MKDIR_RMF) ) {
					//printf("mkdir do_clean age=%lu\n", age->tv_sec);
					if (subonly) {
						DIR *dirp = opendir(path);
						struct dirent *dirent;
						char *buf;

						if (!dirp) break;

						while ( (dirent = readdir(dirp)) != NULL )
						{
							if ( is_dot(dirent->d_name) )
								continue;

							if ( (buf = pathcat(path, dirent->d_name)) )
							{
								if (do_clean && age)
									rmrf(buf, age, do_clean);
								else
									unlink_wrapper(buf, do_clean);
								free(buf);
							}

						}

					} else {
						if (do_clean && age)
							rmrf(path, age, do_clean);
						else
							unlink_wrapper(path, false); /* FIXME is false correct? */
					}
				}

				if (do_create) {
					/*
					   printf("MKDIR %s %s %s %s %s\n", path, modet, uidt, gidt, 
					   aget);
					   printf("MKDIR %s [%d] %u %u %u\n", path, defmode, 
					   (defmode ? DEF_FOLD : mode), uid, gid);
					   */
					fd = open(path, O_DIRECTORY|O_RDONLY);
					if (fd == -1 && errno != ENOENT) break;
					else if (fd != -1 && !(act == MKDIR_RMF)) break;
					else if (fd != -1 && rmrf(path, NULL, false))
						warn("rmrf(%s)", path);

					if (fd != -1)
						close(fd);

					fd = mkpath(path, (defmode ? DEF_FOLD : mode));
					if (fd == -1)
						warn("mkpathr(%s)", path);
					else if (chown(path, uid, gid))
						warn("chown(%s)", path);
				}

				break;

				/* f - Create a file if it does not exist
				 * F - Create a file, truncate if exists
				 *
				 * Age: ignored
				 * Argument: written to the file, suffixed by \n
				 */
			case CREAT_FILE:
			case TRUNC_FILE:
				if (do_create) {
					/* TODO this should skip if exists */
					fd = open(path, 
							O_RDWR|O_CREAT|( (act == TRUNC_FILE) ? O_TRUNC:0 ),
							(defmode ? DEF_FILE : mode)
							);
					if (fd == -1) {
						warn("open(%s)", path);
						break;
					} else if (fchown(fd, uid, gid))
						warn("fchown(%s)", path);

					close(fd);
				}
				break;

				/* C - Recursively copy a file or directory, if the destination 
				 *     files or directories do not exist yet
				 *
				 * Argument: specifics the source folder/file. 
				 *           If blank uses /usr/share/factory/$NAME
				 */
			case COPY:
				if (do_create) {
					dest = pathcat(root, arg);
					/* TODO */
					printf("src=%s\n", dest);
				}
				break;

				/* p - Create a pipe (FIFO) if it does not exist
				 * p+ - Remove and create a pipe (FIFO)
				 *
				 * Argument: ignored
				 */
			case CREATE_PIPE:
				if (do_create) {
					fd = open(path, O_RDONLY);
					if (fd == -1 && errno != ENOENT) 
						break;
					else if (fd != -1 && (mod & MOD_PLUS) && unlink_wrapper(path, false)) {
						warn("CREATE_PIPE: unlink_wrapper");
						break;
					}

					if (fd != -1)
						close(fd);

					if ( (fd = mkfifo(path, mode)) )
						warn("mkfifo(%s)", path);
					else if (chown(path, uid, gid))
						warn("chown(%s)", path);
				}
				break;

				/* L - Create a symlink if it does not exist
				 * L+ - Unlink and then create
				 *
				 * Mode: ignored
				 * UID/GID: ignored
				 * Argument: if empty, symlink to /usr/share/factory/$NAME
				 */
			case CREATE_SYM: // FIXME handle NULL dest => /usr/share/factory
				if (do_create) {
					if (strncmp("../", arg, 3) )
						dest = pathcat(root, arg);
					else
						dest = strdup(arg);

					if (dest == NULL) {
						warn("CREATE_SYM: dest");
						break;
					}

					struct stat sb;
					ret = lstat(path, &sb);

					if (ret == -1 && errno != ENOENT) {
						/* failed to stat with a worrying error */
						warn("CREATE_SYM: open");
						break;
					} else if (ret == -1) { 
						/* must be ENOENT, so fine */
					} else if (!S_ISLNK(sb.st_mode) && (mod & MOD_PLUS)) {
						/* if the existing file is NOT a symlink, we have a problem */
						warnx("CREATE_SYM: existing file is not a symlink: %s", path);
						break;
					} else if (!(mod & MOD_PLUS)) {
						/* file exists so ignore */
						break;
					} else if ((mod & MOD_PLUS) && unlink_wrapper(path, false)) {
						/* file exists, but we had a problem removing it first */
						warn("unlink_wrapper(%s)", path);
						break;
					}

					fd = symlink(dest, path);
					if (fd == -1)
						warn("symlink(%s, %s)", dest, path);
					/* we don't chown/chmod symlinks */
					/* else {
						if (lchown(path, uid, gid))
							warn("chown(%s)", path);
						if (chmod(path, (defmode ? DEF_FOLD : mode)))
							warn("chmod(%s)", path);
					}*/
				}
				break;

				/* c - Create a pipe (FIFO) if it does not exist
				 * c+ - Remove and create a pipe (FIFO)
				 *
				 * Argument: ignored
				 */
			case CREATE_CHAR:
				if (do_create) {
					struct stat sb;
					ret = stat(path, &sb);

					if (ret == -1 && errno != ENOENT) {
						/* failed to stat with unknown error */
						warn("CREATE_CHAR: lstat");
						break;
					} else if (ret == -1) {
						/* NOENT: OK */
					} else if (ret != -1 && !(mod & MOD_PLUS)) {
						/* file exists, but not c+ */
						break;
					} else if (ret != -1 && (mod & MOD_PLUS) && unlink_wrapper(path, false)) {
						warn("CREATE_CHAR: unlink_wrapper(%s)", path);
						break;
					}

					if ( (fd = mknod(path, (defmode ? 
										DEF_FILE : mode)|S_IFCHR, dev)) )
						warn("mknod(%s)", path);
					else if (chown(path, uid, gid))
						warn("chown(%s)", path);
				}
				break;

				/* b - Create a pipe (FIFO) if it does not exist
				 * b+ - Remove and create a pipe (FIFO)
				 *
				 * Argument: ignored
				 */
			case CREATE_BLK:
				if (do_create) {
					dest = pathcat(root, arg);
				}
				break;
			default:
				break;
		}
	}

cleanup:

	if (fd != -1) 
		close(fd);
	if (rawtype) 
		free(rawtype);
	if (path) 
		free(path);
	if (modet) 
		free(modet);
	if (uidt) 
		free(uidt);
	if (gidt)
		free(gidt);
	if (aget) 
		free(aget);
	if (arg) 
		free(arg);
	if (dest)
		free(dest);
	if (fileglob) 
		globfree(fileglob);
}

__attribute__((nonnull(1)))
static void process_file(const char *file, const char *folder)
{
	char *in = NULL;
	int len = 0;
	char *line = NULL;
	ssize_t cnt = 0;
	size_t ignore = 0;

	//if (file == NULL) {
	//	warnx("file is NULL");
	//	return;
	//}

	if (folder) {
		if ( !(in = calloc(1, (len = strlen(file) + 
							strlen(folder) + 2))) ) {
			warn("calloc");
			return;
		}
		snprintf(in, len, "%s/%s", folder, file);
	} else {
		in = strdup(file);
	}

	//printf("processing %s\n", in);

	if (ignores) {
		ignores_size = 0;
		free(ignores);
		ignores = NULL;
	}

	FILE *fp;

	if ( (fp = fopen(in, "r")) != NULL) {
		while( (cnt = getline(&line, &ignore, fp)) != -1 )
		{
			if (line == NULL) continue;

			line = trim(line);
			if (cnt != 1 && line[0] != '#')
				process_line(line);

			free(line);
			line = NULL;
		}

		fclose(fp);
	} else
		warn("fopen");

	free(in);
}

#define CFG_EXT ".conf"
#define CFG_EXT_LEN sizeof(CFG_EXT)

__attribute__((nonnull))
static void process_folder(const char *folder)
{
	DIR *dirp;
	struct dirent *dirent;
	int len;

	//printf("checking folder: %s\n", folder);
	if ( !(dirp = opendir(folder)) ) {
		warn("opendir(%s)", folder);
		return;
	}

	while( (dirent = readdir(dirp)) )
	{
		if ( is_dot(dirent->d_name) )
			continue;
		if ( (len = strlen(dirent->d_name)) <= (int)CFG_EXT_LEN ) 
			continue;
		if ( strncmp(dirent->d_name + len - CFG_EXT_LEN + 1, CFG_EXT, 
					CFG_EXT_LEN) ) 
			continue;
		process_file(dirent->d_name, folder);
	}
}

#undef CFG_EXT
#undef CFG_EXT_LEN

static struct option long_options[] = {

	{"create",			no_argument,		&do_create,		true},
	{"clean",			no_argument,		&do_clean,		true},
	{"remove",			no_argument,		&do_remove,		true},
	{"boot",			no_argument,		&do_boot,		true},
	{"prefix",			required_argument,	0,				'p'},
	{"exclude-prefix",	required_argument,	0,				'e'},
	{"root",			required_argument,	0,				'r'},
	{"help",			no_argument,		&do_help,		true},
	{"version",			no_argument,		&do_version,	true},

	{0,0,0,0}
};


int main(int argc, char *argv[])
{
	int c, fail = 0;

	while (1)
	{
		int option_index;

		c = getopt_long(argc, argv, "h", long_options, &option_index);

		if (c == -1)
			break;

		switch (c)
		{
			case 'p':
				prefix = strdup(optarg);
				break;
			case 'e':
				exclude = strdup(optarg);
				break;
			case 'r':
				root = strdup(optarg);
				break;
			case 'h':
				do_help = 1;
				break;
			case '?':
				fail = 1;
				break;
			case 0:
				break;
			default:
				break;
		}
	}

	if (optind < argc) {
		config_files = (char **)calloc(argc - optind, sizeof(char *));

		if (!config_files)
			err(1, "calloc");

		while (optind < argc)
			config_files[num_config_files++] = strdup(argv[optind++]);
	}

	if (fail)
		exit(EXIT_FAILURE);

	if (do_help)
		show_help();

	if (do_version)
		show_version();

	if (!root)
		root = "";


#ifdef DEBUG
	printf("tmpfilesd running\ndo_create=%d,do_clean=%d,"
			"do_remove=%d,do_boot=%d\nroot=%s\n",
			do_create, do_clean, do_remove, do_boot,
			root);
#endif

	process_folder(pathcat(root, "/etc/tmpfiles.d"));
	process_folder(pathcat(root, "/run/tmpfiles.d"));
	process_folder(pathcat(root, "/usr/lib/tmpfiles.d"));

	for (int i = 0; i < num_config_files; i++)
		process_file(pathcat(root, config_files[i]), NULL);

	exit(EXIT_SUCCESS);
}
