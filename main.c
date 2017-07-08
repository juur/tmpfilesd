#define _GNU_SOURCE

#include <stdlib.h>
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

#include "config.h"
#include "util.h"

enum {false = 0, true = 1};

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

static int do_create=0, do_clean=0, do_remove=0, do_boot=0, do_help=0, do_version=0; 
static char *prefix = NULL, *exclude = NULL, *root = NULL;
static char **config_files = NULL;
static int num_config_files = 0;
static char *hostname = NULL;
static char *machineid = NULL;
static char *kernelrel = NULL;
static char *bootid = NULL;


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

static void show_help()
{
	printf("Usage: tmpfilesd [OPTIONS..] [CONFIGURATION FILE...]\n\n");
	exit(EXIT_SUCCESS);
}

static int validate_type(char *raw, char *type, char *suff, int *boot_only)
{
	int l;

	if (!raw || !boot_only || !type || !suff)
		return -1;
	
	l = strlen(raw);

	*boot_only = 0;
	*type = raw[0];

	if (l == 2) {
		if (raw[1] == '+')
			*suff = raw[1];
		else if (raw[1] == '!')
			*boot_only = 1;
		else
			return -1;

	} else if (l == 3) {
		if (raw[1] != '+' || raw[2] != '!') return -1;
		*suff = raw[1];
		*boot_only = 1;

	} else if (l > 3) {
		return -1;

	}

	return 0;
}
static uid_t vet_uid(char **t, int *defuid)
{
	if (!t || !*t || **t == '-') {
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

static gid_t vet_gid(char **t, int *defgid)
{
	if (!t || !*t || **t == '-') {
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


static char *getbootid()
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


static char *getkernelrelease()
{
	if (kernelrel)
		return kernelrel;

	struct utsname *un;

	if( (un = calloc(1, sizeof(struct utsname))) == NULL ) {
		warn("calloc");
		return NULL;
	}

	if( uname(un) ) {
		warn("uname");
	} else {
		kernelrel = strdup(un->release);
	}

	free(un);
	return kernelrel;
}

static char *gethost()
{
	if (hostname)
		return hostname;

	hostname = calloc(1, HOST_NAME_MAX + 1);
	if (gethostname(hostname, HOST_NAME_MAX)) {
		warn("gethostname");
		free(hostname);
		hostname = NULL;
	}

	return hostname;
}

static char *getmachineid()
{
	if (machineid)
		return machineid;

	FILE *fp = NULL;
	size_t ign = 0;

	if( (fp = fopen("/etc/machine-id", "r")) == NULL) {
		warn("getmachineid");
		return NULL;
	}

	if( getline(&machineid, &ign, fp) < 32 ) {
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
static int vet_mode(char **t, int *mask)
{
	if (!t || !*t || **t == '-')
		return -1;

	char *mod = *t;

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

	return 0;
}

#define LEN 1024
static char *expand_path(char *path)
{
	char *buf = calloc(1, LEN+1);
	char *ptr = path;
	char *cpy;
	char tmp;
	int spos = 0, dpos = 0;

	if (!buf)
		err(1, "malloc");

	while((tmp = ptr[spos]) && dpos < LEN)
	{
		if(tmp != '%') {
			buf[dpos++] = ptr[spos++];
			continue;
		}

		tmp = ptr[++spos];
		if(dpos >= LEN || !tmp) continue;

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

static char *vet_path(char *path)
{
	if (strchr(path, '%'))
		path = expand_path(path);

	//	printf("path=%s\n", path);
	return path;
}

static struct timeval *vet_age(char **t, int *subonly)
{
	if (!t || !*t || **t == '-')
		return NULL;

	u_int64_t val;
	int read, ret;
	char *tmp = NULL, *src = *t;

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
		val = (u_int64_t)ret * 1000000;
	else if ( !strcmp(tmp, "ms") )
		val = (u_int64_t)ret * 1000;
	else if ( !strcmp(tmp, "s") )
		val = (u_int64_t)ret * 1000000;
	else if ( !strcmp(tmp, "m") || !strcmp(tmp, "min") )
		val = (u_int64_t)ret * 1000000 * 60;
	else if ( !strcmp(tmp, "h") )
		val = (u_int64_t)ret * 1000000 * 60 * 60;
	else if ( !strcmp(tmp, "d") ) {
		val = (u_int64_t)ret * 1000000 * 60 * 60 * 24;
	} else if ( !strcmp(tmp, "w") )
		val = (u_int64_t)ret * 1000000 * 60 * 60 * 24 * 7;
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

	//	printf("age={%u,%u}\n", tv->tv_sec, tv->tv_usec);

	return(tv);
}

static int glob_file(char *path, char ***matches, size_t *count,
		glob_t **pglob)
{
	int r;

	if (path == NULL)
		return -1;

	if (*pglob == NULL) {
		*pglob = calloc(1, sizeof(glob_t));
		if (!*pglob) {
			warn("calloc");
			return -1;
		}
	}

	r = glob(path, GLOB_NOSORT, NULL, *pglob);

	if (r) {
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

static int unlinkfolder(char *path)
{
	//printf("rm-rf %s\n", path);
	errno = ENOSYS;
	return -1;
}

static int dummyunlink(char *path)
{
	errno = EPERM;
	return -1;
}

static int rmfile(char *path)
{
	if (!path) {
		warnx("path is NULL");
		errno = EINVAL;
		return -1;
	} else if (dummyunlink(path)) {
		warn("unlink(%s)", path);
		return -1;
	} else {
		printf("rmfile(%s)\n", path);
	}

	return 0;
}

static void rmifold(char *path, struct timeval *tv)
{
	if ( !path || !tv || !*path )
		return;

	struct stat sb;
	int fd = open(path, O_RDONLY);

	if (fd == -1) {
		warn("open(%s)", path);
		return;
	}

	if (fstat(fd, &sb) == -1 ) {
		close(fd);
		warn("fstat(%s)", path);
		return;
	}

	if (S_ISDIR(sb.st_mode)) {
		errno = ENOSYS;
		warn("aged delete folder(%s)", path);
		return;
	} else {
		printf("%s mtime=%lu now=%lu age=%lu\n",
				path,
				sb.st_mtime,
				time(0),
				tv->tv_sec);
	}

	printf("rmifold(%s, %ld)\n", path, tv->tv_sec);
}

static int rmrf(char *path)
{
	char *buf;
	struct stat sb;
	int fd = open(path, O_RDONLY);

	if (fd == -1) return fd;

	if (fstat(fd, &sb) == -1) {
		close(fd);
		return -1;
	}

	close(fd);

	DIR *d = opendir(path);
	struct dirent *ent;

	if (S_ISDIR(sb.st_mode)) {
		if (!d) 
			return -1;

		while ( (ent = readdir(d)) )
		{
			if (is_dot(ent->d_name))
				continue;

			if ( (buf = pathcat(path, ent->d_name)) ) 
			{
				if (rmrf(buf)) {
					free(buf);
					break;
				}
				free(buf);
			}
		}

		closedir(d);

		if (errno) 
			return -1;

	} else {
		printf("not a dir\n");
		return rmfile(path);
	}

	return 0;
}

/*
struct action actions = {
	// ?,	mode,		replace?
	{ 'f',	CREAT_FILE,	false,	
};
*/

static void process_line(char *line)
{
	char *rawtype=NULL, *path=NULL, *modet=NULL;
	char *uidt=NULL, *gidt=NULL, *aget=NULL, *arg=NULL;
	char type, suff = '\0';
	int boot_only = 0, act = -1, subonly = 0;
	int fields = 0;
	char **globs = NULL;
	size_t nglobs = 0;
	glob_t *fileglob = NULL;

	uid_t uid = 0; int defuid = 0;
	gid_t gid = 0; int defgid = 0;
	mode_t mode = 0; int mask = 0;
	dev_t dev = 0;
	struct timeval *age = NULL;

	if (line == NULL) return;

	fields = sscanf(line, 
			"%ms %ms %ms %ms %ms %ms %m[^\n]s",
			&rawtype, &path, &modet, &uidt, &gidt, &aget, &arg);

	//	printf("%s\n", line);

	if( (fields < 2) ) {
		warnx("bad line: %s\n", line);
		return;
	} else if( validate_type(rawtype, &type, &suff, &boot_only) ) {
		warnx("bad type: %s\n", line);
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
						return;
		}
	}

	if (uidt) uid = vet_uid(&uidt, &defuid);
	if (gidt) gid = vet_gid(&gidt, &defgid);
	if (modet) mode = vet_mode(&modet,&mask);
	// FIXME handle '~'
	if (aget) age = vet_age(&aget, &subonly);
	if (path) path = vet_path(path);

	int i, fd = -1;
	
	if ( (do_boot && boot_only) || !boot_only ) {
		switch(act)
		{
			case WRITE_ARG:
				glob_file(path, &globs, &nglobs, &fileglob);
				if (do_create || do_clean)
				{
					for (i=0; i<nglobs; i++) {
						printf("[%u] write %s=%s %s%s", i, path, arg, 
								do_clean ? "clean " : "",
								do_create ? "create " : "");
						if (do_clean && age)
							printf("age=%lu", age->tv_sec);
						puts("\n");
					}
				}
				printf("write\n\n");
				break;
			case RM:
			case RMRF:
				if (!do_remove) break;
				glob_file(path, &globs, &nglobs, &fileglob);
				printf("nglobs=%ld\n", nglobs);
				for (i=0;i<nglobs;i++)
				{
					if (act&0x1) {
						if (rmrf(globs[i]))
							warn("rmrf(%s)",globs[i]);
					} else rmfile(globs[i]);

				}
				printf("rm/rmrf\n\n");
				break;
			case IGN:
			case IGNR:
				glob_file(path, &globs, &nglobs, &fileglob);
				for (i=0; i<nglobs; i++)
				{
					printf("[%u] ignore/r %s\n", 
							i, globs[i]);
				}
				printf("ignr/ign\n\n");
				break;
			case CHMOD:
			case CHMODR:
				glob_file(path, &globs, &nglobs, &fileglob);
				if (do_create) {
					for (i=0; i<nglobs; i++) {
						if (mask) {
							errno = ENOSYS;
							warn("chmod(%s,%s)", globs[i], modet);
						} else {
							if (chmod(globs[i], mode))
								warn("chmod(%s,%s)", globs[i], modet);
						}
						if (chown(globs[i], defuid ? -1 : uid, defgid ? -1 : gid))
							warn("chown(%s,%s,%s)", globs[i], uidt, gidt);
					}
				}
				printf("chmod/chmodr\n\n");
				break;
			case CHATTR:
			case CHATTRR:
				glob_file(path, &globs, &nglobs, &fileglob);
				if (do_create) {
					for (i=0; i<nglobs; i++) {
						printf("[%u] path=%s arg=%s\n", i, globs[i], arg);
					}
				}
				printf("chattr/chattrr\n\n");
				break;
			case ACL:
			case ACLR:
				glob_file(path, &globs, &nglobs, &fileglob);
				if (do_create) {
					for (i=0; i<nglobs; i++) {
						printf("[%u] path=%s arg=%s\n", i, globs[i], arg);
					}
				}
				printf("acl/aclr\n\n");
				break;
			case CREATE_SVOL:
				errno = ENOSYS;
				warn("subvol(%s)", path);
			case MKDIR:
			case MKDIR_RMF:
				if (do_clean && age) {
					printf("mkdir do_clean age=%lu\n", age->tv_sec);
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
								rmifold(buf, age);
								free(buf);
							}

						}

					} else {
						rmifold(path, age);
					}
				}

				if (do_create) {
					fd = open(path, O_DIRECTORY|O_RDONLY);
					if (fd == -1 && errno != ENOENT) break;
					else if (fd != -1 && !(act&0x1)) break;
					else if (fd != -1 && rmrf(path))
						warn("rmrf(%s)", path);
					close(fd);

					fd = mkdir(path, mode);
					if (fd == -1)
						warn("mkdir(%s)", path);
					else if (fchown(fd, uid, gid))
						warn("fchown(%s)", path);
				}

				//printf("path=%s\n", path);
				printf("mkdir\n\n");
				break;
			case CREAT_FILE:
			case TRUNC_FILE:
				if (do_create) {
					fd = open(path, O_CREAT|(act&0x1?O_TRUNC:0),mode);
					if (fd == -1) warn("open(%s)", path);
					else if (fchown(fd, uid, gid))
						warn("fchown(%s)", path);
				}
				printf("creat/runc\n\n");
				break;
			case COPY:
				if (do_create) {
					printf("src=%s\n", arg);
				}
				printf("path=%s\n", path);
				printf("copy\n\n");
				break;
			case CREATE_PIPE:
				if (do_create) {
					fd = open(path, O_RDONLY);
					if (fd == -1 && errno != ENOENT) break;
					else if (fd != -1 && suff != '~') break;
					else if (fd != -1) dummyunlink(path);
					close(fd);

					if ( (fd = mkfifo(path, mode)) )
						warn("mkfifo(%s)", path);
					else if (fchown(fd, uid, gid))
						warn("fchown(%s)", path);
				}
				//printf("path=%s %s\n", path, arg);
				printf("pipe\n\n");
				break;
			case CREATE_SYM: // FIXME handle NULL arg => /usr/share/factory
				if (do_create) {
					fd = open(path, O_RDONLY);
					if (fd == -1 && errno != ENOENT) break;
					else if (fd != -1 && suff != '~') break;
					else if (fd != -1 && dummyunlink(path)) 
						warn("unlink(%s)", path);

					close(fd);

					fd = symlink(arg, path);
					if (fd == -1)
						warn("symlink(%s, %s)", arg, path);
					else {
						if(fchown(fd, uid, gid))
							warn("fchown(%s)", path);
						if(fchmod(fd, mode))
							warn("fchmod(%s)", path);
					}
				}
				//printf("path=%s => %s\n", path, arg);
				printf("sym\n\n");
				break;
			case CREATE_CHAR:
				if (do_create) {
					fd = open(path, O_RDONLY);
					if (fd == -1 && errno != ENOENT) break;
					if (fd != -1 && suff != '~') break;
					else if (fd != -1) dummyunlink(path);
					close(fd);

					if ( (fd = mknod(path, mode|S_IFCHR, dev)) )
						warn("mknod(%s)", path);
					else if (fchown(fd, uid, gid))
						warn("fchown(%s)", path);
				}
				//printf("path=%s %s\n", path, arg);
				printf("char\n\n");
				break;
			case CREATE_BLK:
				if (do_create) {
				}
				printf("path=%s %s\n", path, arg);
				printf("blk\n\n");
			default:
				printf("%c fields=%u\n", type, fields);
				break;
		}
	}

	if (fd != -1) close(fd);
	if (rawtype) free(rawtype);
	if (path) free(path);
	if (modet) free(modet);
	if (uidt) free(uidt);
	if (gidt) free(gidt);
	if (aget) free(aget);
	if (arg) free(arg);
	if (fileglob) globfree(fileglob);

}

static void process_file(char *file, char *folder)
{
	char *in = NULL;
	int len = 0;
	char *line = NULL;
	ssize_t cnt = 0;
	size_t ignore = 0;

	if (file == NULL) {
		warnx("file is NULL");
		return;
	}

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

	printf("processing %s\n", in);

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

static void process_folder(char *folder)
{
	DIR *dirp;
	struct dirent *dirent;
	int len;

	printf("checking folder: %s\n", folder);
	if( (dirp = opendir(folder)) == NULL ) {
		warn("opendir");
		return;
	}

	while( (dirent = readdir(dirp)) != NULL )
	{
		if ( is_dot(dirent->d_name) )
			continue;
		if ( (len = strlen(dirent->d_name)) <= CFG_EXT_LEN ) 
			continue;
		if ( strncmp(dirent->d_name + len - CFG_EXT_LEN + 1, CFG_EXT, 
					CFG_EXT_LEN) ) 
			continue;
		process_file(dirent->d_name, folder);
	}
}

#undef CFG_EXT
#undef CFG_EXT_LEN

int main(int argc, char * const argv[])
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

	printf("tmpfilesd running\ndo_create=%d,do_clean=%d,do_remove=%d,do_boot=%d\n",
			do_clean, do_clean, do_remove, do_boot);

	process_folder("/etc/tmpfiles.d");
	process_folder("/run/tmpfiles.d");
	process_folder("/usr/lib/tmpfiles.d");

	for (int i = 0; i < num_config_files; i++)
		process_file(config_files[i], NULL);


	exit(EXIT_SUCCESS);
}
