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
#include <libgen.h>

#ifdef __linux__
# include <sys/sysmacros.h>
#else
# error "No way to define makedev()"
#endif

#include "config.h"

extern int mkpath(char *dir, mode_t mode) __attribute__((nonnull));



/* macros and defines */

#define MOD_BOOT_ONLY    (1<<0)
#define MOD_NO_ERR       (1<<1)
#define MOD_NOMATCH_RM   (1<<2)
#define MOD_BASE64       (1<<3)
#define MOD_SERVICE_CRED (1<<4)
#define MOD_PLUS         (1<<5)

#define MAX(a, b) ((a) < (b) ? (b) : (a))
#define MIN(a, b) ((a) < (b) ? (a) : (b))



/* type defintions */

typedef enum {
    ACT_NULL = 0,
    CREAT_FILE,
    WRITE_ARG,
    MKDIR,
    MKDIR_RMF,
    CREATE_SVOL,
    CREATE_SVOL2,
    CREATE_PIPE,
    CREATE_SYM,
    CREATE_CHAR,
    CREATE_BLK,
    COPY,
    IGN,
    IGNR,
    RM,
    RMRF,
    CHMOD,
    CHMODR,
    CHATTR,
    CHATTRR,
    CHACL,
    CHACLR,
    ADJUST,
    CREATE_SVOL3,
    CHXATTR,
    CHXATTRR
} actions_t;

typedef enum {
    CFG_MODE   = (1<<0),
    CFG_UID    = (1<<1),
    CFG_GID    = (1<<2),
    CFG_STAT   = CFG_MODE|CFG_UID|CFG_GID,
    CFG_AGE    = (1<<3),
    CFG_GLOB   = (1<<4),
    CFG_FOLLOW = (1<<5),
    CFG_PLUS   = (1<<6),
} cfg_options_t;

typedef enum {
    ARG_CONTENT        = 0,
    ARG_SYMLINK_TARGET = 1,
    ARG_NODE           = 2,
    ARG_SOURCE         = 3,
    ARG_XATTR          = 4,
    ARG_ATTR           = 5,
    ARG_ACL            = 6
} cfg_arg_type_t;

struct config_element {
    const actions_t act;
    const int options;
    const cfg_arg_type_t arg_type;
};

typedef struct ignent {
    char path[PATH_MAX];
    size_t length;
    bool contents;
} ignent_t;

/* private global variables */

/* long_opt values */
static int do_create=0, do_clean=0, do_remove=0, do_boot=0;
static int do_help=0, do_version=0, debug=0, debug_unlink=0;

static char *opt_prefix = NULL, *opt_exclude = NULL, *opt_root = NULL;
static char **config_files = NULL;
static const int max_config_files = 64;
static int num_config_files = 0;

/* cache responses to varies system lookups in these */
static char *hostname = NULL;
static char *machineid = NULL;
static char *kernelrel = NULL;
static char *bootid = NULL;

static ignent_t *ignores = NULL;
static int ignores_size = 0;

/* constants */

static const struct config_element configuration[] = {
    [0x00] = { 0, 0, 0 },

    ['f']  = { CREAT_FILE   , CFG_STAT|CFG_PLUS            , ARG_CONTENT        } ,
    /* tmpfiles.d(5) implies [w] is glob in the description, but not the config summary */
    ['w']  = { WRITE_ARG    , CFG_STAT|CFG_FOLLOW|CFG_PLUS|CFG_GLOB , ARG_CONTENT        } ,
    ['d']  = { MKDIR        , CFG_STAT|CFG_AGE             , 0                  } ,
    ['D']  = { MKDIR_RMF    , CFG_STAT|CFG_AGE             , 0                  } ,
    ['e']  = { ADJUST       , CFG_STAT|CFG_AGE             , 0                  } ,
    ['v']  = { CREATE_SVOL  , CFG_STAT|CFG_AGE             , 0                  } ,
    ['q']  = { CREATE_SVOL2 , CFG_STAT|CFG_AGE             , 0                  } ,
    ['Q']  = { CREATE_SVOL3 , CFG_STAT|CFG_AGE             , 0                  } ,
    ['p']  = { CREATE_PIPE  , CFG_STAT|CFG_PLUS            , 0                  } ,
    ['L']  = { CREATE_SYM   , CFG_PLUS                     , ARG_SYMLINK_TARGET } ,
    ['c']  = { CREATE_CHAR  , CFG_STAT|CFG_PLUS            , ARG_NODE           } ,
    ['b']  = { CREATE_BLK   , CFG_STAT|CFG_PLUS            , ARG_NODE           } ,
    ['C']  = { COPY         , CFG_AGE                      , ARG_SOURCE         } ,
    /* tmpfiles.d(5) implies [xX] is glob in the description, but not the config summary */
    ['x']  = { IGN          , CFG_AGE|CFG_GLOB             , 0                  } ,
    ['X']  = { IGNR         , CFG_AGE|CFG_GLOB             , 0                  } ,
    /* tmpfiles.d(5) implies [rR] is glob in the description, but not the config summary */
    ['r']  = { RM           , 0                            , 0                  } ,
    ['R']  = { RMRF         , 0                            , 0                  } ,
    ['z']  = { CHMOD        , CFG_STAT|CFG_GLOB            , 0                  } ,
    ['Z']  = { CHMODR       , CFG_STAT|CFG_GLOB            , 0                  } ,
    ['t']  = { CHXATTR      , CFG_STAT|CFG_GLOB            , ARG_XATTR          } ,
    ['T']  = { CHXATTRR     , CFG_STAT|CFG_GLOB            , ARG_XATTR          } ,
    ['h']  = { CHXATTR      , CFG_STAT|CFG_GLOB            , ARG_ATTR           } ,
    ['H']  = { CHXATTRR     , CFG_STAT|CFG_GLOB            , ARG_ATTR           } ,
    ['a']  = { CHACL        , CFG_STAT|CFG_PLUS            , ARG_ACL            } ,
    ['A']  = { CHACLR       , CFG_STAT|CFG_PLUS            , ARG_ACL            } ,

    [0xff] = { 0, 0, 0 },
};

static const struct option long_options[] = {

    {"create",          no_argument,        &do_create,     true},
    {"clean",           no_argument,        &do_clean,      true},
    {"remove",          no_argument,        &do_remove,     true},
    {"boot",            no_argument,        &do_boot,       true},
    {"prefix",          required_argument,  0,              'p'},
    {"exclude-prefix",  required_argument,  0,              'e'},
    {"root",            required_argument,  0,              'r'},
    {"help",            no_argument,        &do_help,       true},
    {"version",         no_argument,        &do_version,    true},
    {"debug",           no_argument,        &debug,         true},
    {"debug-unlink",    no_argument,        &debug_unlink,  true},

    {0,0,0,0}
};

static const char   cfg_ext[]   = ".conf";
static const size_t cfg_ext_len = sizeof(cfg_ext);

static const mode_t def_file_mode   = S_IRUSR|S_IWUSR|S_IRGRP|S_IROTH;
static const mode_t def_folder_mode = def_file_mode|S_IXUSR|S_IXGRP|S_IXOTH;



/* private functions */

/* TODO refactor to not free(str) */
__attribute__((nonnull))
static char *trim(char *str)
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

__attribute__((nonnull))
static int is_dot(const char *path)
{
	if( !*path )
		return false;

	if( !strcmp(path, ".") || !strcmp(path, ".." ) )
		return true;

	return false;
}

__attribute__((nonnull))
static char *pathcat(const char *a, const char *b)
{
    size_t len_a = strlen(a);
    size_t len_b = strlen(b);
	size_t len = len_a + len_b + 2;
	char *ret;

	if ( (ret = malloc(len)) == NULL ) {
		warn("malloc");
		return NULL;
	}

    if (len_a) {
        strncpy(ret, a, len);

        if (len_b) {
            if (*b != '/' && a[len_a - 1] != '/')
                strncat(ret, "/", len);
            strncat(ret, b, len);
        }
    } else
        strncpy(ret, b, len);


    return ret;
}

__attribute__((nonnull))
static int isnumber(const char *t)
{
    size_t i;

	for (i = 0; i < strlen(t); i++)
		if( !isdigit(t[i]) )
			return false;

	return true;
}

static void show_version(void)
{
    printf("tmpfilesd %s\n", VERSION);
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
}

__attribute__((nonnull, warn_unused_result))
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
                      errno = EINVAL;
                      warnx("validate_type: type modifier '%c' is unsupported", 
                              isprint(*tmp) ? *tmp : '?');
                      return -1;
        }

    return ret;
}

__attribute__((nonnull))
static dev_t vet_dev(const char *t)
{
    unsigned int major, minor;

    if (sscanf(t, "%u:%u", &major, &minor) != 2) {
        warnx("vet_dev: invalid format: <%s>", t);
        return -1;
    }

    return makedev(major, minor);
}

/*
 * If omitted or - use 0 unless z/Z then leave UID alone
 */
__attribute__((nonnull, warn_unused_result))
static uid_t vet_uid(const char *t, bool *defuid)
{
    if (*t == '-') {
        *defuid = true;
        return (uid_t)-1;
    }

    *defuid = false;

    if (isnumber(t))
        return atol(t);

    struct passwd *pw;

    if ((pw = getpwnam(t)) == NULL) {
        warn("vet_uid: getpwnam");
        return -1;
    }

    return pw->pw_uid;
}

/*
 * If omitted or - use 0 unless z/Z then leave GID alone
 */
__attribute__((nonnull, warn_unused_result))
static gid_t vet_gid(const char *t, bool *defgid)
{
    if (*t == '-') {
        *defgid = true;
        return (gid_t)-1;
    }

    *defgid = false;

    if (isnumber(t))
        return atol(t);

    struct group *gr;

    if ((gr = getgrnam(t)) == NULL) {
        warn("vet_gid: getgrnam");
        return -1;
    }

    return gr->gr_gid;
}

__attribute__((warn_unused_result))
static const char *getbootid(void)
{
    if (bootid)
        return bootid;

    FILE *fp = NULL;
    size_t ign = 0;

    if ((fp = fopen("/proc/sys/kernel/random/boot_id", "r")) == NULL) {
        warn("getbootid: fopen");
        return NULL;
    }

    if (getline(&bootid, &ign, fp) < 36) {
        if (bootid) {
            free(bootid);
            bootid = NULL;
        }
        warn("getbootid: getline");
    } else
        bootid = trim(bootid);

    fclose(fp);
    return bootid;
}

__attribute__((warn_unused_result))
static const char *getkernelrelease(void)
{
    if (kernelrel)
        return kernelrel;

    struct utsname *un;

    if ((un = calloc(1, sizeof(struct utsname))) == NULL) {
        warn("getkernelrelease: calloc");
        return NULL;
    }

    if (uname(un)) {
        warn("getkernelrelease: uname");
    } else if ((kernelrel = strdup(un->release)) == NULL) {
        warn("getkernelrelease: strdup");
    }

    free(un);
    return kernelrel;
}

__attribute__((warn_unused_result))
static const char *gethost(void)
{
    if (hostname)
        return hostname;

    if ((hostname = calloc(1, HOST_NAME_MAX + 1)) == NULL) {
        warn("gethost: calloc");
        return NULL;
    }

    if (gethostname(hostname, HOST_NAME_MAX)) {
        warn("gethost: gethostname");
        free(hostname);
        hostname = NULL;
    }

    return hostname;
}

__attribute__((warn_unused_result))
static const char *getmachineid(void)
{
    if (machineid)
        return machineid;

    FILE *fp = NULL;
    size_t ign = 0;

    if ((fp = fopen("/etc/machine-id", "r")) == NULL) {
        warn("getmachineid: fopen");
        return NULL;
    }

    if (getline(&machineid, &ign, fp) < 32) {
        if (machineid) {
            free(machineid);
            machineid = NULL;
        }
        warn("getmachineid: getline");
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
 * If prefixed with ":" then mode is only used on creation.
 */
__attribute__((nonnull, warn_unused_result))
static mode_t vet_mode(const char *t, mode_t *mask, bool *defmode, bool *create_only)
{
    const char *mod = t;

    *mask = 0;
    *create_only = 0;

    if (*t == '-') {
        *defmode = true;
        return 0;
    }

    *defmode = false;

    while (*mod && !isdigit(*mod)) {
        switch (*mod)
        {
            case '~': *mask = true;        break;
            case ':': *create_only = true; break;
            default:
                      errno = EINVAL;
                      warnx("vet_mode: invalid prefix");
                      return -1;
        }
        mod++;
    }

    if (!isnumber(mod)) {
        errno = EINVAL;
        return -1;
    }

    char *endptr;
    long ret;

    errno = 0;
    ret = strtol(mod, &endptr, 8);

    if (errno || endptr == mod) {
        errno = EINVAL;
        return -1;
    }

    return (mode_t) ret;
}

/* TODO stop doing free(path) as pointer may be reused by callers */
__attribute__((nonnull, warn_unused_result))
static char *expand_path(char *path)
{
    const int buf_len = 1024;

    char *buf;
    char *ptr = path;
    const char *cpy;
    char *free_me;
    char tmp;
    int spos = 0, dpos = 0;
    char string[BUFSIZ];

    if (!*path)
        return path;

    if ((buf = calloc(1, buf_len)) == NULL)
        err(EXIT_FAILURE, "expand_path: calloc");

    ptr = path;

    while((tmp = ptr[spos]) && dpos < buf_len)
    {
        if (tmp != '%') {
            buf[dpos++] = ptr[spos++];
            continue;
        }

        tmp = ptr[++spos];
        if (dpos >= buf_len || !tmp)
            continue;

        cpy = NULL;
        free_me = NULL;

        switch (tmp)
        {
            case '%':
                buf[dpos++] = ptr[spos];
                break;

            case 'b': /* Boot ID */
                cpy = getbootid();
                break;

            case 'm': /* Machine ID */
                cpy = getmachineid();
                break;

            case 'H': /* Host name */
                cpy = gethost();
                break;

            case 'v': /* Kernel release */
                cpy = getkernelrelease();
                break;

            case 'g': /* User group */
                {
                    struct group *grp;
                    if ((grp = getgrgid(getgid())) != NULL) {
                        cpy = grp->gr_name;
                    } else {
print_gid:
                        snprintf(string, sizeof(string), "%u", getgid());
                        cpy = string;
                    }
                }
                break;

            case 'G': /* User GID */
                goto print_gid;

            case 'L': /* system or TODO user log */
                cpy = "/var/log";
                break;

            case 'h': /* user home directory */
                {
                    struct passwd *pwd;

                    if ((pwd = getpwuid(getuid())) == NULL) {
                        warn("expand_path: NULL $HOME");
                        continue;
                    }

                    cpy = pwd->pw_dir;
                }
                break;

            case 'u': /* username */
                {
                    struct passwd *pwd;

                    if ((pwd = getpwuid(getuid())) == NULL) {
                        warn("expand_path: NULL $USERNAME");
                        continue;
                    }

                    cpy = pwd->pw_name;
                }
                break;

            case 'U': /* UID */
                snprintf(string, sizeof(string), "%u", getuid());
                cpy = string;
                break;

            case 'C': /* $XDG_CACHE_HOME in --user or /var/cache */
                cpy = "/var/cache";
                break;

            case 'V': /* tmp folder */
                if (       (cpy = getenv("TMPDIR")) == NULL
                        && (cpy = getenv("TEMP"))   == NULL
                        && (cpy = getenv("TMP"))    == NULL
                   ) {
                    cpy = "/var/tmp";
                }
                break;

            default:
                warnx("Unhandled expansion <%c>\n", isprint(tmp) ? tmp : '?');
                break;
        }

        if (cpy) {
            strncpy(buf + dpos, cpy, buf_len - dpos);
            dpos += strlen(cpy);
        }

        if (free_me)
            free(free_me);

        spos++;
    }

    free(path);
    return buf;
}

/*
 * %m - Machine ID (machine-id(5))
 * %b - Boot ID
 * %H - Host name
 * %v - Kernel release (uname -r)
 * %% - %
 */
__attribute__((nonnull, warn_unused_result))
static char *vet_path(const char *path)
{
    char *tmppath;

    if ((tmppath = strdup(path)) == NULL) {
        warn("vet_path: strdup");
        return NULL;
    }

    if (strchr(path, '%')) {
        return(expand_path(tmppath));
    }

    return tmppath;
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

__attribute__((nonnull, warn_unused_result))
static struct timeval *vet_age(const char *t, int *subonly)
{
    if (*t == '-') {
        errno = EINVAL;
        return NULL;
    }

    uint64_t val;
    int len, ret;
    char *tmp = NULL;
    const char *src = t;

    if (*src == '~') {
        *subonly = 1;
        src++;
    } else
        *subonly = 0;

    len = sscanf(src, "%d%ms", &ret, &tmp);

    if (len == 0 || len > 2) {
        if (tmp) 
            free(tmp);
        warnx("vet_age: invalid age: %s\n", t);
        return NULL;
    }

    if (!tmp || !*tmp) {
        val = (uint64_t)ret * 1000000;
    } else if (!strcmp(tmp, "ms")) {
        val = (uint64_t)ret * 1000;
    } else if (!strcmp(tmp, "s")) {
        val = (uint64_t)ret * 1000000;
    } else if (!strcmp(tmp, "m") || !strcmp(tmp, "min")) {
        val = (uint64_t)ret * 1000000 * 60;
    } else if (!strcmp(tmp, "h")) {
        val = (uint64_t)ret * 1000000 * 60 * 60;
    } else if (!strcmp(tmp, "d")) {
        val = (uint64_t)ret * 1000000 * 60 * 60 * 24;
    } else if (!strcmp(tmp, "w")) {
        val = (uint64_t)ret * 1000000 * 60 * 60 * 24 * 7;
    } else {
        if (tmp)
            free(tmp);
        warnx("vet_age: invalid age: %s\n", t);
        return NULL;
    }

    struct timeval *tv;

    if ((tv = malloc(sizeof(struct timeval))) == NULL) {
        warn("vet_age: malloc");
        if (tmp)
            free(tmp);

        return NULL;
    }

    tv->tv_sec  = (time_t)(val / 1000000);
    tv->tv_usec = (suseconds_t)(val % 1000000);

    if (tmp)
        free(tmp);

    return tv;
}

__attribute__((nonnull, warn_unused_result))
static int glob_file(const char *path, char ***matches, size_t *count,
        glob_t **pglob)
{
    int r;

    errno = 0;

    if (*pglob == NULL && (*pglob = calloc(1, sizeof(glob_t))) == NULL) {
        warn("glob_file: calloc");
        return -1;
    }

    if ((r = glob(path, GLOB_NOSORT, NULL, *pglob))) {
        if (r != GLOB_NOMATCH) {
            warnx("glob returned %u", r);
            if (r == GLOB_NOSPACE)
                errno = ENOMEM;
            else if (r == GLOB_ABORTED)
                errno = EIO;
        } else
            errno = ENOENT;

        globfree(*pglob);
        free(*pglob);

        *pglob = NULL;
        *matches = NULL;
        *count = 0;
        r = -1;
    } else {
        *matches = (**pglob).gl_pathv;
        *count = (**pglob).gl_pathc;
        r = 0;
    }

    return r;
}

static int copy_one_file(const char *src, const char *dst)
{
    struct stat sb;
    int rc;
    int fd_src = -1, fd_dst = -1;
    
    if (debug)
        printf("copy_one_file(%s, %s)\n", src, dst);

    rc = stat(dst, &sb);

    if (rc == -1 && errno != ENOENT) {
        /* ??? */
        return -1;
    } else if (rc != -1) {
        if (debug)
            printf("copy_one_file: skip file %s as destination exists\n", src);
        return 0;
    }

    if (dst[strlen(dst) - 1] == '/') {
        /* TODO */
        errno = ENOSYS;
        warn("copy_one_file: trying to create a folder: %s", dst);
        goto fail;
    }

    if ((fd_src = open(src, O_RDONLY)) == -1)
        goto fail;

    if ((fd_dst = open(dst, O_WRONLY|O_CREAT, S_IRUSR|S_IWUSR|S_IRGRP|S_IROTH)) == -1)
        goto fail;

    char buf[BUFSIZ * 4];
    ssize_t len;

    while ((len = read(fd_src, buf, sizeof(buf))) > 0)
    {
        if (write(fd_dst, buf, len) == -1)
            goto fail;
    }

    if (rc == -1)
        goto fail;

    if (debug)
        printf(" cp %s %s\n", src, dst);

    close(fd_src);
    close(fd_dst);

    return 0;

fail:
    if (fd_src != -1)
        close(fd_src);
    if (fd_dst != -1)
        close(fd_dst);
    /* TODO unlink partial files? */

    return -1;
}

static int copy_src_dir(const char *src, const char *dst)
{
    struct stat sb;
    char path_src[PATH_MAX];
    char path_dst[PATH_MAX];
    DIR *dirp;
    int rc;

    if (debug)
        printf("copy_src_dir(%s, %s)\n", src, dst);

    /* check src exists */

    if ((rc = stat(src, &sb)) == -1 && errno == ENOENT) {
        if (debug)
            printf("copy_src_dir: skipping missing source %s\n", src);
        return 0;
    } else if (rc == -1) {
        warn("copy_src_dir: stat(src) %d==%d", errno, ENOENT);
        return -1;
    } 

    /* two scenarios: src is a file, or src is a folder */

    if (!S_ISDIR(sb.st_mode)) { 

        /* src is a file */
        
        if ((rc = stat(dst, &sb)) == -1 && errno != ENOENT) {
            /* ??? */
            return -1;
        } else if (rc == -1) { /* ENOENT */
            return copy_one_file(src, dst);
        } else if (!S_ISDIR(sb.st_mode)) {
            if (debug)
                printf("copy_src_dir: skipping %s as destination already present\n", src);
            return 0;
        } else if (rc != -1) { /* S_ISDIR() == true */
            char *tmp_src;

            if ((tmp_src = strdup(src)) == NULL) {
                warn("copy_src_dir: strdup(src)");
                return -1;
            }

            snprintf(path_dst, sizeof(path_dst), "%s/%s", dst, basename(tmp_src));
            free(tmp_src);

            return copy_one_file(path_dst, src);
        }
    } 

    /* src is a folder */

    if ((dirp = opendir(src)) == NULL) {
        warn("copy_src_dir: opendir(src): %s", src);
        return -1;
    }

    struct dirent *ent;

    while ((ent = readdir(dirp)) != NULL)
    {
        if (!strcmp(ent->d_name, ".")) continue;
        if (!strcmp(ent->d_name, "..")) continue;

        snprintf(path_src, sizeof(path_src), "%s/%s", src, ent->d_name);
        snprintf(path_dst, sizeof(path_dst), "%s/%s", dst, ent->d_name);

        if (stat(path_src, &sb) == -1) {
            if (errno != ENOENT)
                warn("copy_src_dir: stat(path_src): %s", path_src);
            continue;
        }

        const bool cur_src_dir = !!S_ISDIR(sb.st_mode);

        /* dirent is a file */

        if (!cur_src_dir) {
            copy_one_file(path_src, path_dst);
            continue;
        }

        /* dirent is a folder */

        rc = stat(path_dst, &sb);

        if (rc == -1 && errno == ENOENT) {
        } else if (rc == -1) {
            /* ??? */
        } else { /* rc != -1 */
            if (debug)
                printf(" # skip folder %s as destination exists\n", path_src);
            continue;
        }

        if (mkdir(path_dst, S_IRWXU|S_IRGRP|S_IXGRP|S_IROTH|S_IXOTH) == -1) {
            warn("copy_src_dir: mkdir(path_dst): %s", path_dst);
        }

        if (debug) {
            printf(" mkdir %s\n", path_dst);
            printf("recursion into %s\n", path_src);
        }
            
        copy_src_dir(path_src, path_dst);
    }

    closedir(dirp);
    return 0;
}

/* a wrapper function around unlink(3) that checks for ignored paths */
__attribute__((nonnull,warn_unused_result))
static int unlink_wrapper(const char *pathname, bool check_ignores)
{
    if (check_ignores) {
        for (int i = 0; i < ignores_size; i++)
            /* where contents is true, we check as a prefix otherwise the entire path */
            if (ignores[i].contents && !strncmp(pathname, ignores[i].path, ignores[i].length))
                return 0;
            else if (!strcmp(pathname, ignores[i].path))
                return 0;
    }

    if (!strcmp("/", pathname) || !strcmp(".", pathname) || !strcmp("..", pathname))
        errx(EXIT_FAILURE, "unlink: attempt to remove protected file");

    if (debug) {
        printf("DEBUG: unlink(%s)\n", pathname);
        if (debug_unlink)
            return 0;
    }

    return unlink(pathname);
}

__attribute__((nonnull(1),warn_unused_result))
static int rm_if_old(const char *path, const struct timeval *tv, bool check_ignores)
{
    struct stat sb;
    time_t now;

    if (lstat(path, &sb) == -1 ) {
        warn("rm_if_old: lstat(%s)", path);
        return -1;
    }

    now = time(NULL);

#ifdef DEBUG
    printf("%s mtime=%lu now=%lu age=%lu diff=%lu\n",
            path,
            sb.st_mtime,
            now,
            tv ? tv->tv_sec : 0,
            now - sb.st_mtime);
#endif

    if (S_ISDIR(sb.st_mode)) {
        errno = EISDIR;
        warn("rm_if_old: folder(%s)", path);
        return -1;
    } else if ((tv == NULL) || ((now - sb.st_mtime) > tv->tv_sec)) {
        return unlink_wrapper(path, check_ignores);
    }

    return 0;
}

__attribute__((nonnull(1), warn_unused_result))
static int rm_rf(const char *path, const struct timeval *tv,
        bool check_ignores, bool follow_symlinks)
{
    /* protect some obvious errors */
    if (!strcmp("/", path) || !strcmp(".", path) || !strcmp("..", path))
        errx(EXIT_FAILURE, "rm_rf: attempt to remove protected file");

    char *buf = NULL;
    struct stat sb;
    DIR *d;
    struct dirent *ent;
    bool descend;

    if (lstat(path, &sb) == -1) {
        warn("rm_rf: fstat(%s)", path);
        return -1;
    }

    /* if the target is:
     * a directory: opendir & rm_rf() each entry
     * a symlink:   rm_rf() the symlink
     * otherwise:   rm_rf() the file
     */

    if (!S_ISLNK(sb.st_mode) && S_ISDIR(sb.st_mode)) {
        descend = true;
    } else
        descend = false;

    if (descend) {
        if ((d = opendir(path)) == NULL) {
            warn("rm_rf: opendir");
            return -1;
        }

        while ( (ent = readdir(d)) )
        {
            if (is_dot(ent->d_name))
                continue;

            if ((buf = pathcat(path, ent->d_name)) != NULL)
            {
                if (lstat(buf, &sb) == -1) {
                    free(buf);
                    continue;
                }

                if (rm_rf(buf, tv, check_ignores, follow_symlinks))
                    warnx("rm_rf: rm_rf(%s)", buf);

                free(buf);
            } else {
                /* TODO need a warn() here? */
            }
        }

        closedir(d);

        if (errno)
            return -1;
        return 0;
    } else {
        /* is not a folder */
        return rm_if_old(path, tv, check_ignores);
    }

    /* FIXME check how age checking on symbolic links should be handled */
}

/**
 * execute the action against a single path entry
 *
 * @param[in] act action to perform
 * @param[in] path path/glob (modified)
 * @param[in] age age setting
 * @param[in] arg argument
 * @param[in] mode,defmode,mask config settings for file mode
 * @param[in] defuid,uid config settings uid
 * @param[in] defgid,gid config settings gid
 * @param[in] rawpath unmodified path from config
 * @param[in] dev where act type is ARG_NODE, parsed dev_t
 *
 * @return 0 if OK, -1 for error
 */
__attribute__((nonnull(2,14), warn_unused_result))
static int execute_action(
        char act, char *path, const struct timeval *age,
        const char *arg,
        mode_t mode, bool defmode, mode_t mask,
        bool defuid, uid_t uid,
        bool defgid, gid_t gid,
        bool subonly,
        int mod,
        const char *rawpath,
        dev_t dev)
{
    int fd  = -1;
    int ret = 0;
    int open_mode;

    char *dest = NULL;
    char *src  = NULL;

    switch(act)
    {
        /* w - Write the argument parameter to a file
         *
         * Argument: Content to be written including C-style backslash escapes
         * Path: glob
         * Symlinks: followed
         *
         * Write to existing file, w+ append to existing file.
         */
        case WRITE_ARG:
            if (do_create) {
                /* TODO */

                open_mode  = O_NOCTTY|O_WRONLY;
                open_mode |= (mod & MOD_PLUS) ? O_APPEND : O_TRUNC;

                if ((fd = open(path, open_mode)) == -1) {
                    warn("WRITE_ARG: open: <%s>", path);
                    goto fail;
                }

                /* FIXME - escaping */
                if (write(fd, arg, strlen(arg)) == -1) {
                    warn("WRITE_ARG: write: <%s>", path);
                    close(fd);
                    goto fail;
                }

                close(fd);
            }
            break;

            /* r - Remove a file or directory if it exists (empty only) [remove]
             * R - Recursively remove a path and all its subdirectories [remove]
             *
             * Mode: ignored
             * UID, GID: ignored
             * Age: ignored
             */
        case RM:
        case RMRF:
            if (!do_remove)
                break;

            if (act == RMRF) {
                if (rm_rf(path, NULL, false, false))
                    warn("RMRF: rmrf(%s)",path);
            } else
                if (unlink_wrapper(path, false) && errno != ENOENT)
                    warn("RM: unlink(%s):", path);

            break;

            /* x - Ignore a path during cleaning (plus contents)
             * X - Ignore a path during cleaning (ignores contents)
             *
             * Mode: ignored
             * UID, GID: ignored
             */
        case IGN:
        case IGNR:
            {
                ignent_t *new_ignores = realloc( ignores, (sizeof(ignent_t) * (ignores_size+1)) );

                if (new_ignores == NULL) {
                    warn("IGN: realloc");
                    goto fail;
                }

                ignores = new_ignores;

                strncpy(ignores[ignores_size].path, path, PATH_MAX - 1);
                ignores[ignores_size].contents = (act == IGN) ? true : false;
                ignores[ignores_size].length   = strlen(ignores[ignores_size].path);
                ignores_size++;

                if (debug)
                    printf("DEBUG: ignore/r %s\n", path);
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
            {
                struct stat sb;

                if (do_create) {
                    mode_t mmode = mode;

                    if (defmode) {
                        if (stat(path, &sb) == -1)
                            warn("CHMOD: stat(%s)", path);
                        else {
                            if (S_ISDIR(sb.st_mode))
                                mmode = def_folder_mode;
                            else
                                mmode = def_file_mode;
                        }
                    }

                    if (mask) {
                        errno = ENOSYS;
                        warn("chmod(%s,%o|%o)", path, mmode, mask);
                    } else {
                        if (debug)
                            printf("DEBUG: chmod/r %s,%o", path, mmode);

                        if (chmod(path, mmode))
                            warn("CHMOD: chmod(%s,%o)", path, mmode);
                    }
                    /* FIXME is the logic around -1 right here ? */
                    uid_t tmpuid = defuid ? (uid_t)-1 : uid;
                    gid_t tmpgid = defgid ? (gid_t)-1 : gid;
                    if (lchown(path, tmpuid, tmpgid))
                        warn("CHMOD: lchown(%s,%d,%d)", path, tmpuid, tmpgid);
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
            if (do_create) {
                dest = pathcat(opt_root, arg);
                /* TODO */
                if (debug)
                    printf("DEBUG: chattr/r path=%s dest=%s\n", path, dest);
            }
            break;

            /* a/a+ - Set POSIX ACLs. If suffixed with +, specified entries
             *        will be added to the existing set
             * A/A+ - as above, but recursive.
             *
             * Mode: ignored
             * UID, GID: ignored
             * Age: ignored
             */
        case CHACL:
        case CHACLR:
            if (do_create) {
                dest = pathcat(opt_root, arg);
                /* TODO */
                if (debug)
                    printf("DEBUG: acl/r path=%s dest=%s\n", path, dest);
            }
            break;

            /* v - create subvolume, or behave as d if not supported
            */
        case CREATE_SVOL:
            /* TODO */
            break;

            /* d - create a directory (if does not exist)
             * D - create a direcotry (delete contents if exists) [remove]
             */
        case MKDIR:
        case MKDIR_RMF:
            if ( (do_clean && age) || (do_remove && act == MKDIR_RMF) ) {
                if (subonly) {
                    DIR *dirp = opendir(path);
                    struct dirent *dirent;
                    char *buf;

                    if (!dirp)
                        goto mkdir_skip;

                    while ( (dirent = readdir(dirp)) != NULL )
                    {
                        if ( is_dot(dirent->d_name) )
                            continue;

                        if ( (buf = pathcat(path, dirent->d_name)) )
                        {
                            if (do_clean && age) {
                                if (rm_rf(buf, age, do_clean, true))
                                    warn("MKDIR: rm_rf(%s)", buf);
                            } else if (unlink_wrapper(buf, do_clean) && errno != ENOENT)
                                warn("MKDIR: unlink(%s)", buf);
                            free(buf);
                        }

                    }

                    closedir(dirp);

                } else { /* !subonly */
                    if (do_clean && age) {
                        /* tmpfiles.d(5) is ambiguous if d/D follow symlinks */
                        if (rm_rf(path, age, do_clean, false))
                            warn("MKDIR: rm_rf(%s)", path);
                        else if (debug)
                            printf("DEBUG: CLEAN: mkdir/r: %s\n", path);

                    } else if (do_remove) {
                        if (unlink_wrapper(path, false) && errno != ENOENT) /* FIXME is false correct? */
                            warn("MKDIR: unlink(%s)", path);
                        else if (debug)
                            printf("DEBUG: REMOVE: mkdir/r: %s\n", path);
                    }
                }
            }
mkdir_skip:
            if (do_create) {
                /*
                   printf("MKDIR %s %s %s %s %s\n", path, modet, uidt, gidt,
                   aget);
                   printf("MKDIR %s [%d] %u %u %u\n", path, defmode,
                   (defmode ? DEF_FOLD : mode), uid, gid);
                   */
                fd = open(path, O_DIRECTORY|O_RDONLY);

                if (fd == -1 && errno != ENOENT)
                    break;
                else if (fd == -1 && errno == ENOENT) {
                    /* OK */
                } else if (fd != -1 && !(act == MKDIR_RMF)) {
                    if (debug)
                        printf("DEBUG: SKIP:  mkdir/r: %s\n", path);
                    break;
                } else if (fd != -1 && rm_rf(path, NULL, false, false))
                    warn("rmrf(%s)", path);

                if (fd != -1)
                    close(fd);

                /* mkpath performs chmod */
                if (mkpath(path, (defmode ? def_folder_mode : mode)) == -1)
                    warn("MKDIR: mkpath(%s)", path);
                if (lchown(path, uid, gid))
                    warn("MKDIR: lchown(%s,%d,%d)", path, uid, gid);

                if (debug)
                    printf("DEBUG: DONE:  mkdir/r: %s:%d.%d:0%o\n", path, uid, gid, 
                            (defmode ? def_folder_mode : mode));
            }

            break;

            /* f  - Create a file if it does not exist (only write if created)
             * f+ - Create a file, truncate if exists (always write?)
             *
             * Age: ignored
             * Argument: written to the file (with trailing newline?)
             */
        case CREAT_FILE:

            if (do_clean && age) {
                if (rm_if_old(path, age, true))
                    warn("CREATE/TRUNC_FILE: rm_if_old: <%s>", path);
                else if (debug)
                    printf("DEBUG: CLEAN: <%s>\n", path);
            }

            if (do_create) {
                struct stat sb;
                if (stat(path, &sb) == -1) {
                    if (errno != ENOENT) {
                        warn("CREATE/TRUNC_FILE: stat: <%s>", path);
                        break;
                    }
                } else if (!(act & MOD_PLUS)) {
                    if (debug)
                        printf("DEBUG: SKIP:  create/trunc_file: <%s>\n", path);
                    break;
                }

                /* O_TRUNC will do nothing for "f" */
                open_mode  = O_NOCTTY|O_WRONLY|O_CREAT|O_TRUNC;

                if ((fd = open(path, open_mode, (defmode ? def_file_mode : mode))) == -1) {
                    warn("open(%s)", path);
                    break;
                }

                /* if uid or gid is -1 nothing happens */
                if ( (uid != (uid_t)-1 || gid != (gid_t)-1) 
                        && fchown(fd, uid, gid))
                    warn("CREATE/TRUNC_FILE: fchown(%s, %d, %d)", path, uid, gid);

                /* does NOT have C-style escapes */
                if (arg && *arg != '-')
                    if (write(fd, arg, strlen(arg)) == -1)
                        warn("CREATE/TRUNC_FILE: write: <%s>", path);

                close(fd);

                if (debug)
                    printf("DEBUG: DONE:  create/trunc_file: <%s>\n", path);

            }
            break;

            /* C - Recursively copy a file or directory, if the destination
             *     files or directories do not exist yet
             *
             * Argument: specifics the source folder/file.
             *           If blank uses /usr/share/factory/$NAME
             */
        case COPY:
            {
                struct stat sb;
                bool exists;
                bool dest_dir;
                bool factory;
                bool src_dir;
                char buf[PATH_MAX];

                /* check the destination */
                if (stat(path, &sb) == -1) {
                    if (errno != ENOENT)
                        break;

                    exists = false;
                    dest_dir = false;
                } else {
                    exists = true;
                    dest_dir = !!S_ISDIR(sb.st_mode);
                }

                /* check the source */
                if (arg && *arg != '-') {
                    if ((src = pathcat(opt_root, arg)) == NULL) {
                        warn("COPY: pathcat(arg)");
                        break;
                    }
                    factory = false;
                } else {
                    if ((src = pathcat(opt_root, "/usr/share/factory/")) == NULL) {
                        warn("COPY: pathcat(factory)");
                        break;
                    }
                    strcpy(buf, src);
                    free(src);

                    if ((src = pathcat(buf, rawpath)) == NULL) {
                        warn("COPY: pathcat(factory)");
                        break;
                    }
                    factory = true;
                }

                if (stat(src, &sb) == -1) {
                    if (errno != ENOENT)
                        warn("COPY: stat: <%s>", src);
                    free(src);
                    break;
                }

                src_dir = !!S_ISDIR(sb.st_mode);

                /* process actions */

                if (do_clean && age) {
                    /* TODO */
                }

                if (do_create) {
                    if (src_dir && !dest_dir) {
                        warn("COPY: attempt to copy folder(%s) to file(%s)", src, path);
                        break;
                    } 

                    if (copy_src_dir(src, path))
                        warn("COPY: copy_src_dir");
                   
                    /* TODO */
                    if (factory) {
                    } else {
                    }

                    if (debug)
                        printf("COPY: src=%s dest=%s exists=%d dest_dir=%d "
                                "src_dir=%d factory=%d\n",
                                src, path, exists, dest_dir, src_dir, factory);
                }

                free(src);
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
            if (do_clean && age) {
                /* TODO */
            }

            if (do_create) {
                if (strncmp("../", arg, 3) )
                    dest = pathcat(opt_root, arg);
                else
                    dest = strdup(arg);

                if (dest == NULL) {
                    warn("CREATE_SYM: dest is NULL: <%s>", path);
                    break;
                }

                struct stat sb;
                ret = lstat(path, &sb);

                if (ret == -1 && errno != ENOENT) {
                    /* failed to stat with a worrying error */
                    warn("CREATE_SYM: open: <%s> => <%s>", path, dest);
                    break;
                } else if (ret == -1) {
                    /* must be ENOENT, so fine */
                } else if (!S_ISLNK(sb.st_mode) && (mod & MOD_PLUS)) {
                    /* if the existing file is NOT a symlink, we have a problem */
                    warnx("CREATE_SYM: existing file is not a symlink: <%s>", path);
                    break;
                } else if (!(mod & MOD_PLUS)) {
                    /* file exists so ignore */
                    if (debug)
                        printf("DEBUG: SKIP:  symlink dest=%s path=%s\n", dest, path);
                    break;
                } else if ((mod & MOD_PLUS) && unlink_wrapper(path, false)) {
                    /* file exists, but we had a problem removing it first */
                    warn("CREATE_SYM: unlink_wrapper: <%s>", path);
                    break;
                }

                if (symlink(dest, path) == -1) {
                    warn("CREATE_SYM: symlink(%s, %s)", dest, path);
                    break;
                }

                if (debug)
                    printf("DEBUG: DONE:  symlink dest=%s path=%s\n", dest, path);
            }
            break;

            /* c  - Create a character file if it does not exist
             * c+ - Remove and create a character file
             * b  - Create a block device node if it does not exist
             * b+ - Remove and create
             * p  - Create a pipe (FIFO) if it does not exist
             * p+ - Remove and create a pipe (FIFO)
             *
             * Argument: ignored
             */
        case CREATE_CHAR:
        case CREATE_BLK:
        case CREATE_PIPE:
            if (do_clean && age) {
                /* TODO */
            }

            if (do_create) {
                struct stat sb;
                ret = stat(path, &sb);

                if (ret == -1 && errno != ENOENT) {
                    /* failed to stat with unknown error */
                    warn("CREATE_CHAR/BLK/PIPE: lstat");
                    break;
                } else if (ret == -1) {
                    /* NOENT: OK */
                } else if (ret != -1 && !(mod & MOD_PLUS)) {
                    /* file exists, but not c+ */
                    if (debug)
                        printf("DEBUG: SKIP:  create_char/blk %s\n", path);
                    break;
                } else if (ret != -1 && (mod & MOD_PLUS) && unlink_wrapper(path, false)) {
                    warn("CREATE_CHAR/BLK/PIPE: unlink_wrapper(%s)", path);
                    goto fail;
                }

                switch (act) 
                {
                    case CREATE_CHAR:  mode = S_IFCHR; break;
                    case CREATE_BLK:   mode = S_IFBLK; break;
                    case CREATE_PIPE:  mode = 0;       break;
                }

                mode |= (defmode ? def_file_mode : mode);

                switch (act)
                {
                    case CREATE_PIPE:
                        if (mkfifo(path, mode)) {
                            warn("CREATE_PIPE: mkfifo: <%s>", path);
                            goto fail;
                        }
                        break;

                    case CREATE_CHAR:
                    case CREATE_BLK:
                        if (mknod(path, mode, dev)) {
                            warn("CREATE_CHAR/BLK: mknod(%s)", path);
                            goto fail;
                        }
                        break;
                }

                if (lchown(path, uid, gid))
                    warn("chown(%s)", path);

                if (debug)
                    printf("DEBUG: create_char/blk %s\n", path);
            }
            break;

        default:
            break;
    }

done:
    if (dest)
        free(dest);
    if (fd != -1)  {
        close(fd);
    }
    return ret;
fail:
    ret = -1;
    goto done;
}

__attribute__((nonnull))
static void process_line(const char *line)
{
    char *raw_type = NULL, *raw_path = NULL, *raw_mode = NULL;
    char *raw_uid  = NULL,  *raw_gid = NULL,  *raw_age = NULL;
    char *arg      = NULL,  *raw_arg = NULL;

    char *dest = NULL, *src = NULL, *path = NULL;

    char type;

    int subonly = 0;
    int fields = 0;
    int i = 0;

    char  **globs    = NULL;
    size_t  nglobs   = 0;
    glob_t *fileglob = NULL;

    actions_t act;
    uid_t uid = -1; bool defuid = true;
    gid_t gid = -1; bool defgid = true;
    mode_t mode = -1; bool defmode = true; mode_t mask = 0; bool mode_create_only = false;
    dev_t dev = 0;
    int mod = 0;

    struct timeval *age = NULL;

    const struct config_element *cfg_elem = NULL;

    errno = 0;
    /* Type Path Mode User Group Age Argument */
    fields = sscanf(line,
            "%ms %ms %ms %ms %ms %ms %m[^\n]s",
            &raw_type, &raw_path, &raw_mode, &raw_uid, &raw_gid, &raw_age, &raw_arg);

    /* Type and Path are mandatory for all types */
    if (fields == EOF || fields < 2) {
        if (errno)
            warn("process_line: sscanf");
        else
            warnx("process_line: bad line: %s\n", line);
        goto cleanup;
    }

    if (opt_prefix && strncmp(opt_prefix, raw_path, strlen(opt_prefix)))
        goto cleanup;

    if (opt_exclude && !strncmp(opt_exclude, raw_path, strlen(opt_exclude)))
        goto cleanup;

    if ((mod = validate_type(raw_type, &type)) == -1) {
        warn("process_line: bad type format: %s", line);
        goto cleanup;
    }

    if (configuration[(uint8_t)type].act == ACT_NULL) {
        warnx("process_line: invalid type: %s", line);
        goto cleanup;
    }

    cfg_elem = &configuration[(uint8_t)type];
    act = cfg_elem->act;

    /* ensure an argument is present for those that require it */
    if (cfg_elem->arg_type && raw_arg == NULL) {
        warnx("process_line: argument is mandaotry for type: %s", line);
        goto cleanup;
    }

    /* validate & tidy up fields */


    if (raw_uid) uid   = vet_uid(raw_uid, &defuid);
    if (raw_gid) gid   = vet_gid(raw_gid, &defgid);
    if (raw_mode) mode = vet_mode(raw_mode, &mask, &defmode, &mode_create_only);
    // FIXME handle '~'
    if (raw_age) age   = vet_age(raw_age, &subonly);

    /* perform tmpfiles.d specific expansions */
    if (raw_path) dest = vet_path(raw_path);
    if (raw_arg)  arg  = vet_path(raw_arg);

    if (dest == NULL)
        goto cleanup;

    path = pathcat(opt_root, dest);
    free(dest);
    dest = NULL;

    if (path == NULL)
        goto cleanup;

    /* skip if not applicable due to boot mode & settings */
    if ((do_boot && !(mod & MOD_BOOT_ONLY)) 
            || (!do_boot && (mod & MOD_BOOT_ONLY)))
        goto cleanup;

    /* TODO process ARG_NODE */
    if (cfg_elem->arg_type == ARG_NODE) {
        if (arg == NULL) {
            warn("process_line: missing argument for device node");
            goto cleanup;
        }

        if ((dev = vet_dev(arg)) == (dev_t)-1)
            goto cleanup;
    } else
        dev = -1;

    if ((cfg_elem->options & CFG_GLOB)) {
        if (glob_file(path, &globs, &nglobs, &fileglob)) {
            if (errno != ENOENT)
                warn("process_line: glob_file: <%s>", path);
            goto cleanup;
        }

        for (i = 0; i < (int)nglobs; i++) {
            if (execute_action(
                        act, globs[i], age, arg,
                        mode, defmode, mask,
                        defuid, uid,
                        defgid, gid,
                        subonly,
                        mod,
                        raw_path,
                        dev
                        )) {
                /* failed */ ;
            }
        }
    } else {
        if (execute_action(
                    act, path, age, arg,
                    mode, defmode, mask,
                    defuid, uid,
                    defgid, gid,
                    subonly,
                    mod,
                    raw_path,
                    dev
                    )) {
            /* failed */ ;
        }
    }

cleanup:

    if (src)
        free(src);
    if (raw_type)
        free(raw_type);
    if (path)
        free(path);
    if (raw_mode)
        free(raw_mode);
    if (raw_uid)
        free(raw_uid);
    if (raw_gid)
        free(raw_gid);
    if (raw_age)
        free(raw_age);
    if (raw_path)
        free(raw_path);
    if (raw_arg)
        free(raw_arg);
    if (arg)
        free(arg);
    if (dest)
        free(dest);
    if (age)
        free(age);
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

    if (folder) {
        len = strlen(file) + strlen(folder) + 2;
        if ((in = calloc(1, len)) == NULL) {
            warn("process_file: calloc");
            return;
        }
        snprintf(in, len, "%s/%s", folder, file);
    } else {
        if ((in = strdup(file)) == NULL) {
            warn("process_file: strdup");
            return;
        }
    }

    if (ignores) {
        ignores_size = 0;
        free(ignores);
        ignores = NULL;
    }

    FILE *fp;

    if ((fp = fopen(in, "r")) != NULL) {
        while( (cnt = getline(&line, &ignore, fp)) != -1 )
        {
            if (line == NULL)
                break;

            line = trim(line);
            if (line == NULL)
                break;

            if (cnt != 1 && line[0] != '#' && line[0] != '\n' && line[0])
                process_line(line);

            free(line);
            line = NULL;
        }

        if (line)
            free(line);

        fclose(fp);
    } else
        warn("process_file: fopen: <%s>", in);

    free(in);
}

__attribute__((nonnull))
static void process_folder(const char *folder)
{
    DIR *dirp;
    struct dirent *dirent;
    int len;

    if ((dirp = opendir(folder)) == NULL) {
        warn("process_folder: opendir: <%s>", folder);
        return;
    }

    while( (dirent = readdir(dirp)) )
    {
        if (is_dot(dirent->d_name))
            continue;
        if ((len = strlen(dirent->d_name)) <= (int)cfg_ext_len)
            continue;
        if (strncmp(dirent->d_name + len - cfg_ext_len + 1, cfg_ext, cfg_ext_len))
            continue;

        process_file(dirent->d_name, folder);
    }

    closedir(dirp);
}

static void clean_config_files(void)
{
    if (config_files == NULL)
        return;

    for (int i = 0; i < num_config_files; i++)
        if (config_files[i]) {
            free (config_files[i]);
            config_files[i] = NULL;
        }

    free(config_files);
}

static void clean_constants(void)
{
    if (hostname)
        free(hostname);
    if (machineid)
        free(machineid);
    if (kernelrel)
        free(kernelrel);
    if (bootid)
        free(bootid);

    if (ignores)
        free(ignores);

    if (opt_prefix)
        free(opt_prefix);
    if (opt_exclude)
        free(opt_exclude);
    if (opt_root)
        free(opt_root);
}




/* public functions */

int main(int argc, char *argv[])
{
    int c, fail = 0;

    while (true)
    {
        int option_index;

        if ((c = getopt_long(argc, argv, "h", long_options, &option_index)) == -1)
            break;

        switch (c)
        {
            case 'p': opt_prefix  = strdup(optarg); break;
            case 'e': opt_exclude = strdup(optarg); break;
            case 'r': opt_root    = strdup(optarg); break;
            case 'h': do_help = 1; break;
            case '?': fail    = 1; break;

            case 0:
            default:
                      break;
        }
    }

    atexit(clean_constants);
    atexit(clean_config_files);

    if (fail) {
        show_help();
        exit(EXIT_FAILURE);
    }

    if (do_help) {
        show_help();
        exit(EXIT_SUCCESS);
    }

    if (do_version) {
        show_version();
        exit(EXIT_SUCCESS);
    }

    if (optind < argc) {
        if ((config_files = (char **)calloc(argc - optind + 1, sizeof(char *))) == NULL)
            err(EXIT_FAILURE, "main: calloc");

        while ( (optind < argc) && (num_config_files < max_config_files) )
        {
            if ((config_files[num_config_files++] = strdup(argv[optind++])) == NULL) {
                err(EXIT_FAILURE, "main: strdup");
            }
        }

        if (num_config_files == max_config_files)
            warnx("main: too many config files (max %d)", max_config_files);
    }

    if (!opt_root)
        opt_root = "";

#ifdef DEBUG
    printf("tmpfilesd running\ndo_create=%d,do_clean=%d,"
            "do_remove=%d,do_boot=%d\nroot=%s\n",
            do_create, do_clean, do_remove, do_boot,
            root);
#endif

    char *tmppath;

    /* TODO move these to constants somewhere e.g. config.h */
    if ((tmppath = pathcat(opt_root, "/etc/tmpfiles.d")) == NULL)
        err(EXIT_FAILURE, "main: pathcat");
    process_folder(tmppath);
    free(tmppath);

    if ((tmppath = pathcat(opt_root, "/run/tmpfiles.d")) == NULL)
        err(EXIT_FAILURE, "main: pathcat");
    process_folder(tmppath);
    free(tmppath);

    if ((tmppath = pathcat(opt_root, "/usr/lib/tmpfiles.d")) == NULL)
        err(EXIT_FAILURE, "main: pathcat");
    process_folder(tmppath);
    free(tmppath);

    for (int i = 0; i < num_config_files; i++) {
        if (config_files[i] == NULL) /* should not happen? */
            continue;

        char *tmp;
        if ((tmp = pathcat(opt_root, config_files[i])) == NULL) {
            warn("main: pathcat");
        } else {
            process_file(tmp, NULL);
            free(tmp);
        }
    }

    /* TODO should this be EXIT_FAILURE if any single error/warning occured? */
    exit(EXIT_SUCCESS);
}
