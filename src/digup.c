/*****************************************************************************
 * digup.c - Digest File Updating Program                                    *
 *                                                                           *
 * Copyright (C) 2010-2020 Timo Bingmann                                     *
 *                                                                           *
 * This program is free software; you can redistribute it and/or modify it   *
 * under the terms of the GNU General Public License as published by the     *
 * Free Software Foundation; either version 3, or (at your option) any       *
 * later version.                                                            *
 *                                                                           *
 * This program is distributed in the hope that it will be useful,           *
 * but WITHOUT ANY WARRANTY; without even the implied warranty of            *
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the             *
 * GNU General Public License for more details.                              *
 *                                                                           *
 * You should have received a copy of the GNU General Public License         *
 * along with this program; if not, write to the Free Software Foundation,   *
 * Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.        *
 *****************************************************************************/

#include <assert.h>
#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include "digest.h"
#include "rbtree.h"

/**************************
 * Basic Type Definitions *
 **************************/

typedef enum { FALSE, TRUE } bool;

enum DigestType { DT_NONE, DT_MD5, DT_SHA1, DT_SHA256, DT_SHA512 };

enum FileStatus
{
    FS_UNSEEN,	/* in digest file but not seen on fs yet. */
    FS_SEEN,    /* in digest file and seen on fs with equal mtime. */
    FS_NEW,	/* newly seen file on fs. */
    FS_TOUCHED,	/* identical in digest file and fs but with different mtime. */
    FS_CHANGED,	/* in digest file but modified on fs. */
    FS_ERROR,   /* error while reading file. */
    FS_COPIED,  /* copied within tree. */
    FS_RENAMED, /* renamed within tree. */
    FS_OLDPATH, /* original entry of a renamed file */
    FS_SKIPPED  /* skipped due to --restrict */
};

struct FileInfo
{
    enum FileStatus	status;
    time_t		mtime;
    long long		size;
    char*		error;
    digest_result*	digest;
    char*               symlink; /* target actually */
    char*               oldpath; /* for renamed or copied files. */
};

/********************************
 * Global Variables and Options *
 ********************************/

const char* g_progname = NULL;

/* various parameters set by the command line parameters */

int gopt_verbose = 2;
bool gopt_batch = FALSE;
bool gopt_fullcheck = FALSE;
bool gopt_followsymlinks = FALSE;
bool gopt_onlymodified = FALSE;
bool gopt_update = FALSE;
char* gopt_digestfile = NULL;
enum DigestType gopt_digesttype = DT_NONE;
unsigned int gopt_modify_window = 0;
const char* gopt_exclude_marker = NULL;
const char* gopt_matchpattern = NULL;

/* red-black tree mapping filename string -> struct FileInfo */

struct rb_tree* g_filelist = NULL;

/* red-black tree mapping digest_result -> filename string */

struct rb_tree* g_filedigestmap = NULL;

/* file status counters */

unsigned int g_filelist_seen = 0;
unsigned int g_filelist_new = 0;
unsigned int g_filelist_touched = 0;
unsigned int g_filelist_changed = 0;
unsigned int g_filelist_error = 0;
unsigned int g_filelist_copied = 0;
unsigned int g_filelist_renamed = 0;
unsigned int g_filelist_oldpath = 0;
unsigned int g_filelist_skipped = 0;

/**********************************
 * Helper Functions and Utilities *
 **********************************/

/* functional for the g_filelist red-black tree */
void rbtree_string_free(void *a)
{
    free((char*)a);
}

/* functional for the g_filelist red-black tree */
void rbtree_fileinfo_free(void *a)
{
    struct FileInfo* fileinfo = a;

    if (fileinfo->error)
	free(fileinfo->error);

    if (fileinfo->digest)
	free(fileinfo->digest);

    if (fileinfo->symlink)
	free(fileinfo->symlink);

    if (fileinfo->oldpath)
	free(fileinfo->oldpath);

    free(fileinfo);
}

/* functional for the g_filelist red-black tree */
void rbtree_digest_result_free(void *a)
{
    free((digest_result*)a);
}

/* functional for the g_filelist red-black tree */
void rbtree_null_free(void *a)
{
    (void)a;
}

/* functional for the g_filelist red-black tree */
int rbtree_string_cmp(const void *a, const void *b)
{
    return strcmp((const char*)a, (const char*)b);
}

/* functional for the g_filelist red-black tree */
int rbtree_digest_result_cmp(const void *a, const void *b)
{
    return digest_cmp((const digest_result*)a,	
		      (const digest_result*)b);
}

/* functional for qsort() on a char* array */
static int strcmpptr(const void *p1, const void *p2)
{
    return strcmp(*(char**)p1, *(char**)p2);
}

/* simple strndup() replacement if not in standard library. */
#if !HAVE_STRNDUP
static char *strndup(const char *str, size_t len)
{
    char* out = malloc(len + 1);
    strncpy(out, str, len);
    out[len] = 0;
    return out;
}
#endif

/* simple asprintf() replacement if not in standard library. */
#if !HAVE_ASPRINTF
static int asprintf(char **strp, const char *fmt, ...)
{
    va_list ap;
    ssize_t len;
    char *out;

    va_start(ap, fmt);
    len = vsnprintf(NULL, 0, fmt, ap) + 1;
    va_end (ap);

    out = malloc(len);
    if (out == NULL) return -1;

    va_start(ap, fmt);
    len = vsnprintf(out, len, fmt, ap);
    va_end (ap);
    *strp = out;

    return len;
}
#endif

/* wrapper to abort if out of memory */
static int my_asprintf(char **strp, const char *fmt, ...)
{
    va_list ap;
    int r;

    va_start(ap, fmt);
    r = vasprintf(strp, fmt, ap);
    va_end(ap);

    if (r < 0) {
        fprintf(stderr, "asprintf(): out of memory\n");
        exit(EXIT_FAILURE);
    }

    return r;
}

/* select correct struct stat and functions for 64-bit file sizes in mingw */
#if ON_WIN32

typedef struct __stat64	mystatst;

#define mystat		_stat64
#define mylstat		_stat64

#else /* for sane systems */

typedef struct stat	mystatst;

#define mystat 		stat

#if !HAVE_LSTAT
#define mylstat 	stat
#else
#define mylstat 	lstat
#endif

#endif

/* not so simple getline() replacement from xine-ui code. */
#if !HAVE_GETLINE

#define GETLINE_BLOCK_SIZE 128

static ssize_t getdelims(char **lineptr, size_t *n, const char *delims, FILE *stream)
{
    void *tmp;
    const char *d;
    int c;
    size_t i;

    if (!lineptr || !n || !delims || !stream) {
	errno = EINVAL;
	return -1;
    }
    if (!*lineptr) *n = 0;
    i = 0;

    while ((c = fgetc(stream)) != EOF)
    {
	if (i + 1 >= *n) {
	    if ((tmp = realloc(*lineptr, *n + GETLINE_BLOCK_SIZE)) == NULL) {
		errno = ENOMEM;
		return -1;
	    }
	    *lineptr = tmp;
	    *n += GETLINE_BLOCK_SIZE;
	}

	(*lineptr)[i++] = (unsigned char)c;

	d = delims;
	while (*d) {
	    if ((unsigned char)c == *d++) break;
	}
	if (*d != '\0') break;
    }
    if (i != 0) (*lineptr)[i] = '\0';

    return (i == 0) ? -1 : (ssize_t)i;
}

static ssize_t getline(char **lineptr, size_t *n, FILE *stream)
{
    return getdelims(lineptr, n, "\n\r", stream);
}
#endif

/**
 * Call readlink() as often as needed to return the complete symlink
 * target in a malloc()ed buffer.
 */
char* readlink_dup(const char *filename)
{
#if HAVE_READLINK
    ssize_t size = 128;
    char *buffer = NULL, *tmp;
    int nchars;

    while (1)
    {
        tmp = realloc(buffer, size);
        if (!tmp) {
            /* out of memory */
            free(buffer);
            return NULL;
        }
        buffer = tmp;
	nchars = readlink(filename, buffer, size);
	if (nchars < 0) {
	    free(buffer);
	    return NULL;
	}
	if (nchars + 1 < size) {
	    buffer[nchars] = 0;
	    return buffer;
	}
	size *= 2;
    }
#else
    (void)filename;
    errno = EINVAL;
    return NULL;
#endif
}

/**
 * fprintf() variant which also updates a CRC32 value.
 */
int fprintfcrc(uint32_t *crc, FILE* fp, const char *fmt, ...)
{
    va_list ap;
    ssize_t len;

    static char *out = NULL;
    static ssize_t outlen = 0;
    char *tmp;

    va_start(ap, fmt);
    len = vsnprintf(NULL, 0, fmt, ap) + 1;
    va_end (ap);

    if (outlen < len)
    {
	while (outlen < len)
	{
	    outlen = 2 * outlen;
	    if (outlen < 128) outlen = 128;
	}

	tmp = realloc(out, outlen);
	if (tmp == NULL)
            return -1;
        out = tmp;
    }

    va_start(ap, fmt);
    len = vsnprintf(out, len, fmt, ap);
    va_end (ap);

    *crc = crc32(*crc, (unsigned char*)out, len);
    len = fwrite(out, len, 1, fp);

    return len;
}

/**
 * Transform each \n to a new line and each \\ back to a slash. no
 * other escapes characters are allowed.
 */
bool unescape_filename(char *str)
{
    size_t i, j = 0;

    for (i = 0; str[i]; ++i, ++j)
    {
	if (str[i] == '\\')
	{
	    if (str[i+1] == 0)
	    {
		/* illegal filename finishes with single backslash */
		return 0;
	    }
	    ++i;
	    switch (str[i])
	    {
	    case 'n':
		str[j] = '\n';
		break;
	    case '\\':
		str[j] = '\\';
		break;
	    default:
		/* invalid escape sequence. */
		return FALSE;
	    }
	}
	else if (i != j)
	{
	    str[j] = str[i];
	}
    }

    str[j] = 0;

    return TRUE;
}

/**
 * Reverse transform each \n and \. into the escaped form and signal
 * to main function whether escaping is needed. The function will
 * replaced the malloc()ed parameter string in str.
 */
bool needescape_filename(char** str)
{
    int needescape = 0;
    char *s, *t, *newstr;

    s = *str;
    while(*s != 0)
    {
	if (*s == '\\' || *s == '\n')
	    ++needescape;
	++s;
    }

    if (needescape == 0)
	return FALSE;

    newstr = malloc(s - *str + needescape + 1);
    t = newstr;
    s = *str;

    while(*s != 0)
    {
	if (*s == '\\')
	{
	    *t++ = '\\';
	    *t++ = '\\';
	}
	else if (*s == '\n')
	{
	    *t++ = '\\';
	    *t++ = 'n';
	}
	else
	{
	    *t++ = *s;
	}
	++s;
    }

    *t = 0;

    free(*str);
    *str = newstr;

    return (needescape != 0);
}

#if ON_WIN32

/**
 * Replace all backslashes with forward slashes. Used only on Windows.
 */
void replace_backslahes_with_slashes(char* s)
{
    while(*s != 0)
    {
	if (*s == '\\')
	    *s = '/';
	++s;
    }
}

#endif

/***************************************
 * Functions to calculate file digests *
 ***************************************/

/**
 * Called from digest_file() with a struct digest_ctx. If there is an
 * error while calculating the digest, the function returns FALSE and
 * outerror is filled with an error message string.
 */
bool digest_file2(const char* filepath,
		  long long filesize,
		  digest_ctx* digctx,
		  digest_result** outdigest,
		  char** outerror)
{
    char buffer[1024*1024];
    ssize_t rb;
    long long totalread = 0;

#if ON_WIN32
    int openflags = O_RDONLY | O_BINARY;
#else
    int openflags = O_RDONLY;
#endif

#ifdef O_NOATIME
    int fd = open(filepath, openflags | O_NOATIME);

    if (fd < 0 && errno == EPERM)
    {
	/* try without O_NOATIME for files not owned by the user */
	fd = open(filepath, openflags);
    }
#else
    int fd = open(filepath, openflags);
#endif

    if (fd < 0)
    {
	if (gopt_verbose >= 2) {
	    fprintf(stdout, "ERROR. Could not open file: %s.\n",
		    strerror(errno));
	}
	else if (gopt_verbose >= 1) {
	    fprintf(stdout, "%s ERROR. Could not open file: %s.\n",
		    filepath, strerror(errno));
	}
	else if (gopt_verbose >= 0) {
	    fprintf(stderr, "%s: could not open file \"%s\": %s.\n",
		    g_progname, filepath, strerror(errno));
	}
	my_asprintf(outerror, "Could not open file: %s.", strerror(errno));
	return FALSE;
    }

    while( (rb = read(fd, &buffer, sizeof(buffer))) > 0 )
    {
	if (gopt_verbose >= 2) {
	    fprintf(stdout, ".");
	    fflush(stdout);
	}

	digctx->process(digctx, buffer, rb);

	totalread += rb;
    }

    if (rb != 0)
    {
	if (gopt_verbose >= 2) {
	    fprintf(stdout, "ERROR. Could not read file: %s.\n",
		    strerror(errno));
	}
	else if (gopt_verbose >= 1) {
	    fprintf(stdout, "%s ERROR. Could not read file: %s.\n",
		    filepath, strerror(errno));
	}
	else if (gopt_verbose >= 0) {
	    fprintf(stderr, "%s: could not read file \"%s\": %s.\n",
		    g_progname, filepath, strerror(errno));
	}
	my_asprintf(outerror, "Could not read file: %s.", strerror(errno));
	close(fd);
	return FALSE;
    }

    close(fd);

    if (totalread != filesize)
    {
	if (gopt_verbose >= 2) {
	    fprintf(stdout, "ERROR. Could not read complete file.\n");
	}
	else if (gopt_verbose >= 1) {
	    fprintf(stdout, "%s ERROR. Could not read complete file.\n",
		    filepath);
	}
	else if (gopt_verbose >= 0) {
	    fprintf(stderr, "%s: Could not read complete file \"%s\".\n",
		    g_progname, filepath);
	}
	my_asprintf(outerror, "Could not read complete file.");
	return FALSE;
    }

    assert(!*outdigest);
    *outdigest = digctx->finish(digctx);

    return TRUE;
}

/**
 * Read a filepath and calucate the digest over all data. Returns it
 * as a malloc()ed hex string in outdigest, or returns FALSE if there
 * was a read error.
 */
bool digest_file(const char* filepath, long long filesize,
                 digest_result** outdigest, char** outerror)
{
    digest_ctx digctx;

    switch (gopt_digesttype)
    {
    case DT_MD5:
	digest_init_md5(&digctx);
	break;

    case DT_SHA1:
	digest_init_sha1(&digctx);
	break;

    case DT_SHA256:
	digest_init_sha256(&digctx);
	break;

    case DT_SHA512:
	digest_init_sha512(&digctx);
	break;

    default:
	assert(0);
	my_asprintf(outerror, "Invalid digest algorithm.");
	return FALSE;
    }

    return digest_file2(filepath, filesize, &digctx, outdigest, outerror);
}

/************************************
 * Functions to parse a digest file *
 ************************************/

/**
 * Parse one digest line and fill in tempinfo according or add a new
 * file to g_filelist. The return value is -1 for an unknown line, 0
 * for a correct digest or symlink line, +1 for a comment line
 * providing additional file info and -2 for and eof flagged line.
 */
int parse_digestline(const char* line, const unsigned int linenum,
                     struct FileInfo* tempinfo, uint32_t crc)
{
    /*** parse line from digest file ***/
    size_t p = 0;

    /* skip initial whitespace */
    while (isspace(line[p])) ++p;

    if (line[p] == '#')
    {
	/* if first character is a hash then the line might be a
	   comment or our custom mtime indicator. */

	size_t p_word, p_arg;

	++p;
	if (line[p] != ':')
	{
	    /* usual comment */
	    return 0;
	}

	++p;

	while (line[p])
	{
	    while (isspace(line[p])) ++p;

	    p_word = p;
	    while (isalpha(line[p]) || line[p] == '\\') ++p;

	    if (!isspace(line[p]) && line[p] != 0)
	    {
		fprintf(stderr, "%s: \"%s\" line %d: unparseable digest comment line.\n",
			g_progname, gopt_digestfile, linenum);

		return -1;
	    }

	    if (strncmp(line+p_word, "option", p - p_word) == 0)
	    {
		/* read persistent option following */

		while (isspace(line[p])) ++p;

		p_arg = p;
		while (line[p] != 0 && line[p] != '=') ++p;

		if (strncmp(line+p_arg, "--exclude-marker", p - p_arg) == 0 &&
                    line[p] == '=')
		{
		    ++p; /* skip over '=' */

		    p_arg = p;
		    while (line[p] != 0) ++p;

		    if (gopt_exclude_marker) free((void*)gopt_exclude_marker);

		    gopt_exclude_marker = strndup(line+p_arg, p - p_arg);

		    if (gopt_verbose >= 2) {
			fprintf(stderr, "%s: \"%s\" line %d: persistent option --exclude-marker=%s\n",
				g_progname, gopt_digestfile, linenum, gopt_exclude_marker);
		    }
		}
		else
		{
		    fprintf(stderr, "%s: \"%s\" line %d: unknown persistent option line.\n",
			    g_progname, gopt_digestfile, linenum);

		    return -1;
		}
	    }
	    else if (strncmp(line+p_word, "mtime", p - p_word) == 0)
	    {
		/* read number following mtime */

		while (isspace(line[p])) ++p;

		p_arg = p;
		while (isdigit(line[p])) ++p;

		if (!isspace(line[p]) && line[p] != 0)
		{
		    fprintf(stderr, "%s: \"%s\" line %d: unparseable digest comment line.\n",
			    g_progname, gopt_digestfile, linenum);

		    return -1;
		}

		tempinfo->mtime = strtoul(line + p_arg, NULL, 10);
	    }
	    else if (strncmp(line+p_word, "size", p - p_word) == 0)
	    {
		/* read number following size */

		while (isspace(line[p])) ++p;

		p_arg = p;
		while (isdigit(line[p])) ++p;

		if (!isspace(line[p]) && line[p] != 0)
		{
		    fprintf(stderr, "%s: \"%s\" line %d: unparseable digest comment line.\n",
			    g_progname, gopt_digestfile, linenum);

		    return -1;
		}

		tempinfo->size = strtoull(line + p_arg, NULL, 10);
	    }
	    else if (strncmp(line+p_word, "target", p - p_word) == 0)
	    {
		/* read the complete following line (after the current
		 * white space) as the symlink target */

		if (!isspace(line[p]))
		{
		    fprintf(stderr, "%s: \"%s\" line %d: unparseable digest comment line.\n",
			    g_progname, gopt_digestfile, linenum);

		    return -1;
		}
		++p;

		p_arg = p;
		while (line[p] != 0) ++p;

		tempinfo->symlink = strndup(line+p_arg, p - p_arg);
	    }
	    else if (strncmp(line+p_word, "target\\", p - p_word) == 0)
	    {
		/* read the complete following line (after the current
		 * white space) as the escaped symlink target */

		if (!isspace(line[p]))
		{
		    fprintf(stderr, "%s: \"%s\" line %d: unparseable digest comment line.\n",
			    g_progname, gopt_digestfile, linenum);

		    return -1;
		}
		++p;

		p_arg = p;
		while (line[p] != 0) ++p;

		tempinfo->symlink = strndup(line+p_arg, p - p_arg);

		if (!unescape_filename(tempinfo->symlink))
		{
		    fprintf(stderr, "%s: \"%s\" line %d: improperly escaped symlink target.\n",
			    g_progname, gopt_digestfile, linenum);
		    free(tempinfo->symlink);
		    return -1;
		}
	    }
	    else if (strncmp(line+p_word, "symlink", p - p_word) == 0)
	    {
		/* read the complete following line (after the current
		 * white space) as the symlink source file name. */

		char* filename;
		struct FileInfo* fileinfo;

		if (!isspace(line[p]))
		{
		    fprintf(stderr, "%s: \"%s\" line %d: unparseable digest comment line.\n",
			    g_progname, gopt_digestfile, linenum);

		    return -1;
		}
		++p;

		p_arg = p;
		while (line[p] != 0) ++p;

		filename = strndup(line+p_arg, p - p_arg);

		fileinfo = malloc(sizeof(struct FileInfo));
		memcpy(fileinfo, tempinfo, sizeof(struct FileInfo));
		if (fileinfo->symlink) /* tempinfo's copy will be freed */
		    fileinfo->symlink = strdup(fileinfo->symlink);

		/* insert fileinfo into filelist */

		if (rb_find(g_filelist, filename) != NULL)
		{
		    fprintf(stderr, "%s: \"%s\" line %d: duplicate symlink file name.\n",
			    g_progname, gopt_digestfile, linenum);

		    free(fileinfo->symlink);
		    free(fileinfo);
		    return -1;
		}

		rb_insert(g_filelist, filename, fileinfo);

		/* return +1 here to clear tempinfo. */
		return 1;
	    }
	    else if (strncmp(line+p_word, "symlink\\", p - p_word) == 0)
	    {
		/* read the complete following line (after the current
		 * white space) as the escaped symlink source file name. */

		char* filename;
		struct FileInfo* fileinfo;

		if (!isspace(line[p]))
		{
		    fprintf(stderr, "%s: \"%s\" line %d: unparseable digest comment line.\n",
			    g_progname, gopt_digestfile, linenum);

		    return -1;
		}
		++p;

		p_arg = p;
		while (line[p] != 0) ++p;

		filename = strndup(line+p_arg, p - p_arg);

		if (!unescape_filename(filename))
		{
		    fprintf(stderr, "%s: \"%s\" line %d: improperly escaped symlink filename.\n",
			    g_progname, gopt_digestfile, linenum);
		    free(filename);
		    return -1;
		}

		fileinfo = malloc(sizeof(struct FileInfo));
		memcpy(fileinfo, tempinfo, sizeof(struct FileInfo));
		if (fileinfo->symlink) /* tempinfo's copy will be freed */
		    fileinfo->symlink = strdup(fileinfo->symlink);

		/* insert fileinfo into filelist */

		if (rb_find(g_filelist, filename) != NULL)
		{
		    fprintf(stderr, "%s: \"%s\" line %d: duplicate symlink file name.\n",
			    g_progname, gopt_digestfile, linenum);

		    free(fileinfo->symlink);
		    free(fileinfo);
		    return -1;
		}

		rb_insert(g_filelist, filename, fileinfo);

		/* return +1 here to clear tempinfo. */
		return 1;
	    }
	    else if (strncmp(line+p_word, "crc", p - p_word) == 0)
	    {
		/* read hex crc32 value following the word */

		char *crchex;

		while (isspace(line[p])) ++p;

		if (line[p] != '0' || line[++p] != 'x')
		{
		    fprintf(stderr, "%s: \"%s\" line %d: unparseable crc line.\n",
			    g_progname, gopt_digestfile, linenum);
		    return 0;
		}
		++p;

		p_arg = p;
		while (isxdigit(line[p])) ++p;

		if (p - p_arg != 8)
		{
		    fprintf(stderr, "%s: \"%s\" line %d: unparseable sdfsdcrc line.\n",
			    g_progname, gopt_digestfile, linenum);
		    return 0;
		}

		my_asprintf(&crchex, "%08x", crc);
		
		if (strncmp(crchex, line+p_arg, p - p_arg) != 0)
		{
		    free(crchex);

		    fprintf(stderr, "%s: \"%s\" line %d: crc32 value saved in file does not match!\n",
			    g_progname, gopt_digestfile, linenum);

		    if (gopt_batch)
		    {
			exit(-1); /* fail badly */
		    }
		    else
		    {
			char input[256], *r;

			fprintf(stderr, "This indicates an unintentional or intentional modification of the digest file.\n");
			fprintf(stderr, "Continue despite change (y/n)? ");

			r = fgets(input, sizeof(input), stdin);

			if (r == NULL || input[0] != 'y')
			{
			    exit(-1);
			}
		    }
		}
		else
		{
		    free(crchex);
		}
	    }
	    else if (strncmp(line+p_word, "eof", p - p_word) == 0)
	    {
		return -2;
	    }
	    else
	    {
		fprintf(stderr, "%s: \"%s\" line %d: unparseable digest comment line.\n",
			g_progname, gopt_digestfile, linenum);

		return -1;
	    }
	}

	return 0;
    }
    else
    {
	/* a usual digest line. */

	size_t p_hex1;
	struct FileInfo* fileinfo;

	enum DigestType this_digesttype = DT_NONE;
	char* filename = NULL;

	bool escaped_filename = FALSE;

	if (line[p] == '\\')
	{
	    ++p;
	    escaped_filename = TRUE;
	}

	p_hex1 = p;
	while (isxdigit(line[p])) ++p;

	if (!isspace(line[p]))
	{
	    /* digest is not followed by a space -> error. */
	    return -1;
	}

	fileinfo = malloc(sizeof(struct FileInfo));
	memcpy(fileinfo, tempinfo, sizeof(struct FileInfo));
	if (fileinfo->symlink) /* tempinfo's copy will be freed */
	    fileinfo->symlink = strdup(fileinfo->symlink);

	if (p_hex1 + 2 * MD5_DIGEST_SIZE == p)
	{
	    fileinfo->digest = digest_hex2bin( line+p_hex1, p - p_hex1 );
	    this_digesttype = DT_MD5;
	}
	else if (p_hex1 + 2 * SHA1_DIGEST_SIZE == p)
	{
	    fileinfo->digest = digest_hex2bin( line+p_hex1, p - p_hex1 );
	    this_digesttype = DT_SHA1;
	}
	else if (p_hex1 + 2 * SHA256_DIGEST_SIZE == p)
	{
	    fileinfo->digest = digest_hex2bin( line+p_hex1, p - p_hex1 );
	    this_digesttype = DT_SHA256;
	}
	else if (p_hex1 + 2 * SHA512_DIGEST_SIZE == p)
	{
	    fileinfo->digest = digest_hex2bin( line+p_hex1, p - p_hex1 );
	    this_digesttype = DT_SHA512;
	}
	else
	{
	    fprintf(stderr, "%s: \"%s\" line %d: no proper hex digest detected on line.\n",
		    g_progname, gopt_digestfile, linenum);

	    free(fileinfo);
	    return -1;
	}

	if (!fileinfo->digest)
	{
	    assert(fileinfo->digest);
	    fprintf(stderr, "%s: \"%s\" line %d: no proper hex digest detected on line.\n",
		    g_progname, gopt_digestfile, linenum);

	    free(fileinfo);
	    return -1;
	}

	if (gopt_digesttype != DT_NONE && this_digesttype != gopt_digesttype)
	{
	    fprintf(stderr, "%s: \"%s\" line %d: different digest types in file.\n",
		    g_progname, gopt_digestfile, linenum);

	    free(fileinfo);
	    exit(0);
	}

	++p;

	/* after digest terminating white space follows a "type
	   indicator": text or binary. We always use binary. */

	if (line[p] != ' ' && line[p] != '*')
	{
	    fprintf(stderr, "%s: \"%s\" line %d: improper type indicator.\n",
		    g_progname, gopt_digestfile, linenum);

	    return -1;
	}

	++p;

	/* all non-null character after type indicator and \n are relevant. */

	filename = strdup(line + p);

	if (escaped_filename)
	{
	    if (!unescape_filename(filename))
	    {
		fprintf(stderr, "%s: \"%s\" line %d: improperly escaped file name.\n",
			g_progname, gopt_digestfile, linenum);

		return -1;
	    }
	}

#if ON_WIN32
        /* on Windows: replace backslashes in filename with forward slashes */
        replace_backslahes_with_slashes(filename);
#endif

	/* insert fileinfo into filelist */

	if (rb_find(g_filelist, filename) != NULL)
	{
	    fprintf(stderr, "%s: \"%s\" line %d: duplicate file name.\n",
		    g_progname, gopt_digestfile, linenum);

	    return -1;
	}

	rb_insert(g_filelist, filename, fileinfo);

	gopt_digesttype = this_digesttype;

	/* return +1 here to clear tempinfo. */
	return 1;
    }
}

bool select_digestfile(void)
{
    /*
      Check for existing standard digest file names. However, if
      multiple exist, failed with an error message.
    */

    if (access("md5sum.txt", F_OK) == 0)
    {
	gopt_digesttype = DT_MD5;
	gopt_digestfile = "md5sum.txt";
    }

    if (access("sha1sum.txt", F_OK) == 0)
    {
	if (gopt_digestfile != NULL)
	{
	    fprintf(stderr, "%s: multiple digest files found in current directory. Select one using --file.\n",
		    g_progname);
	    return FALSE;
	}

	gopt_digesttype = DT_SHA1;
	gopt_digestfile = "sha1sum.txt";
    }

    if (access("sha128sum.txt", F_OK) == 0)
    {
	if (gopt_digestfile != NULL)
	{
	    fprintf(stderr, "%s: multiple digest files found in current directory. Select one using --file.\n",
		    g_progname);
	    return FALSE;
	}

	gopt_digesttype = DT_SHA1;
	gopt_digestfile = "sha128sum.txt";
    }

    if (access("sha256sum.txt", F_OK) == 0)
    {
	if (gopt_digestfile != NULL)
	{
	    fprintf(stderr, "%s: multiple digest files found in current directory. Select one using --file.\n",
		    g_progname);
	    return FALSE;
	}

	gopt_digesttype = DT_SHA256;
	gopt_digestfile = "sha256sum.txt";
    }

    if (access("sha512sum.txt", F_OK) == 0)
    {
	if (gopt_digestfile != NULL)
	{
	    fprintf(stderr, "%s: multiple digest files found in current directory. Select one using --file.\n",
		    g_progname);
	    return FALSE;
	}

	gopt_digesttype = DT_SHA512;
	gopt_digestfile = "sha512sum.txt";
    }

    return TRUE;
}

bool read_digestfile(void)
{
    FILE* sumfile;
    struct FileInfo tempinfo;

    char *line = NULL;
    size_t linemax = 0;
    ssize_t linelen;
    unsigned int linenum = 0;

    int res = 0;
    uint32_t crc = 0, nextcrc;

    if (gopt_digestfile == NULL)
    {
	if (!select_digestfile())
	    return FALSE;

	if (gopt_digestfile == NULL)
	{
	    fprintf(stderr, "%s: no digest file found. Creating \"sha1sum.txt\" from full scan.\n",
		    g_progname);

	    gopt_digesttype = DT_SHA1;
	    gopt_digestfile = "sha1sum.txt";
	    return TRUE;
	}
    }


    sumfile = fopen(gopt_digestfile, "rb");
    if (sumfile == NULL)
    {
	if (errno == ENOENT)
	{
	    fprintf(stderr, "%s: could not open digest file \"%s\": performing full scan.\n",
		    g_progname, gopt_digestfile);

	    if (gopt_digesttype == DT_NONE)
	    {
		fprintf(stderr, "%s: to create a new digest file specify the digest --type (see --help).\n",
			g_progname);
		return FALSE;
	    }

	    return TRUE;
	}
	else
	{
	    fprintf(stderr, "%s: could not open digest file \"%s\": %s\n",
		    g_progname, gopt_digestfile, strerror(errno));
	    return FALSE;
	}
    }

    memset(&tempinfo, 0, sizeof(struct FileInfo));
    tempinfo.status = FS_UNSEEN;

    while ( (linelen = getline(&line, &linemax, sumfile)) >= 0 )
    {
	++linenum;

	if (res == -2) /* last line indicated eof */
	{
	    fprintf(stderr, "%s: \"%s\" line %d: superfluous line after eof.\n",
		    g_progname, gopt_digestfile, linenum);
	}

	nextcrc = crc32(crc, (unsigned char*)line, linelen);

	/* remove trailing newline */
	if (linelen > 0 && line[linelen-1] == '\n')
	    line[linelen-1] = 0;

	res = parse_digestline(line, linenum, &tempinfo, crc);

	if (res != 0)
	{
	    /* Illegal or valid digest line found. Clear fileinfo. */

	    if (tempinfo.symlink)
		free(tempinfo.symlink);

	    memset(&tempinfo, 0, sizeof(struct FileInfo));
	    tempinfo.status = FS_UNSEEN;
	}

	crc = nextcrc;
    }

    if (line) free(line);

    if (rb_isempty(g_filelist))
    {
	fprintf(stderr, "%s: %s: no digests found in file.\n",
		g_progname, gopt_digestfile);

	if (gopt_digesttype == DT_NONE)
	{
	    fprintf(stderr, "%s: to create a new digest file specify the digest --type (see --help).\n",
		    g_progname);
	    return FALSE;
	}
    }
    else
    {
	/* Insert all file digests into the map for fast lookup. */
	/* Simulanteously mark files as skipped that don't match --restrict */

	struct rb_node* node;

	for (node = rb_begin(g_filelist); node != rb_end(g_filelist); node = rb_successor(g_filelist, node))
	{
	    struct FileInfo* fileinfo = node->value;

	    if (gopt_matchpattern && strstr(node->key, gopt_matchpattern) == NULL)
	    {
		fileinfo->status = FS_SKIPPED;
		++g_filelist_skipped;
	    }

	    if (fileinfo->digest)
	    {
		rb_insert(g_filedigestmap, digest_dup(fileinfo->digest), node->key);
	    }
	}
    }

    fclose(sumfile);

    return TRUE;
}

/*************************************************************
 * Functions to recursively scan directories and process file *
 *************************************************************/

bool process_file(const char* filepath, const mystatst* st)
{
    struct rb_node* fileiter;
    struct rb_node* digestiter;

    if (filepath[0] == '.' && filepath[1] == '/')
	filepath += 2;

    /* skip over the digestfile */
    if (strcmp(filepath, gopt_digestfile) == 0)
	return TRUE;

    /* silently skip over ignored filepaths */
    if (gopt_matchpattern && strstr(filepath, gopt_matchpattern) == NULL)
	return TRUE;

    if (gopt_verbose >= 2) {
	fprintf(stdout, "%s ", filepath);
    }

    /* lookup file info for mtime */

    fileiter = rb_find(g_filelist, filepath);

    if (fileiter != NULL)
    {
	struct FileInfo* fileinfo = fileiter->value;
	digest_result* filedigest = NULL;

	if (fileinfo->status != FS_UNSEEN)
	{
	    if (gopt_verbose >= 2) {
		fprintf(stdout, " same file processed twice??? This should never occur.\n");
	    }
	    else {
		fprintf(stdout, "%s same file processed twice??? This should never occur.\n", filepath);
	    }
	    return TRUE;
	}

	if (gopt_fullcheck)
	{
	    if (gopt_verbose >= 2) {
		fprintf(stdout, "check ");
	    }
	}
	else if ((unsigned int)labs(st->st_mtime - fileinfo->mtime) > gopt_modify_window ||
		 st->st_size != fileinfo->size)
	{
	    if (gopt_verbose >= 2) {
		fprintf(stdout, "touched ");
	    }
	}
	else
	{
	    if (gopt_verbose >= 2) {
		fprintf(stdout, "untouched.\n");
	    }
	    else if (gopt_verbose == 1 && !gopt_onlymodified) {
		fprintf(stdout, "%s untouched.\n", filepath);
	    }

	    fileinfo->status = FS_SEEN;
	    ++g_filelist_seen;

	    return TRUE;
	}

	/* calculate file digest */

	if (!digest_file(filepath, st->st_size, &filedigest, &fileinfo->error))
	{
	    fileinfo->status = FS_ERROR;
	    fileinfo->mtime = st->st_mtime;
	    fileinfo->size = st->st_size;

	    ++g_filelist_error;
	    return FALSE;
	}

	if (fileinfo->digest && digest_equal(filedigest, fileinfo->digest))
	{
	    if (gopt_verbose >= 2) {
		fprintf(stdout, " matched.\n");
	    }
	    else if (gopt_verbose == 1 && !gopt_onlymodified) {
		fprintf(stdout, "%s matched.\n", filepath);
	    }

	    fileinfo->status = FS_TOUCHED;
	    fileinfo->mtime = st->st_mtime;
	    fileinfo->size = st->st_size;
	    free(filedigest);

	    ++g_filelist_touched;
	}
	else
	{
	    if (gopt_verbose >= 2) {
		fprintf(stdout, " CHANGED.\n");
	    }
	    else if (gopt_verbose == 1) {
		fprintf(stdout, "%s CHANGED.\n", filepath);
	    }

	    fileinfo->status = FS_CHANGED;
	    fileinfo->mtime = st->st_mtime;
	    fileinfo->size = st->st_size;

	    if (fileinfo->digest)
		free(fileinfo->digest);

	    fileinfo->digest = filedigest;

	    ++g_filelist_changed;
	}

	return TRUE;
    }
    else
    {
	struct FileInfo* fileinfo = malloc(sizeof(struct FileInfo));
	memset(fileinfo, 0, sizeof(struct FileInfo));

	fileinfo->status = FS_NEW;
	fileinfo->mtime = st->st_mtime;
	fileinfo->size = st->st_size;

	if (!digest_file(filepath, st->st_size, &fileinfo->digest, &fileinfo->error))
	{
	    fileinfo->status = FS_ERROR;

	    rb_insert(g_filelist, strdup(filepath), fileinfo);

	    ++g_filelist_error;

	    return FALSE;
	}

	/* look for existing file with equal digest */
	digestiter = rb_find(g_filedigestmap, fileinfo->digest);
	if (digestiter != NULL)
	{
	    bool copied = FALSE;
	    struct rb_node* nodecopy = digestiter;

	    /* test if the oldfile still exists. */
	    while (nodecopy != rb_end(g_filedigestmap) &&
		   digest_equal((digest_result*)nodecopy->key, fileinfo->digest))
	    {
		if (access((char*)nodecopy->value, F_OK) == 0)
		{
		    copied = TRUE;
		    digestiter = nodecopy;
		}
		else
		{
		    /* lookup FileInfo of matching file and set oldpath flags */
		    struct rb_node* filenode = rb_find(g_filelist, nodecopy->value);

		    if (filenode == NULL)
		    {
			fprintf(stderr, "\n%s: internal error. Cannot find entry for matching file.\n",
				g_progname);
		    }
		    else if (((struct FileInfo*)filenode->value)->status == FS_UNSEEN)
		    {
			((struct FileInfo*)filenode->value)->status = FS_OLDPATH;
			++g_filelist_oldpath;
		    }
		    else if (((struct FileInfo*)filenode->value)->status == FS_OLDPATH)
		    {
		    }
		    else
		    {
			fprintf(stderr, "\n%s: renamed original file still existed when scanning.\n",
				g_progname);
		    }
		}

		nodecopy = rb_successor(g_filedigestmap, nodecopy);
	    }

	    if (copied)
	    {
		fileinfo->status = FS_COPIED;
		++g_filelist_copied;
		if (gopt_verbose >= 2) {
		    fprintf(stdout, " copied.\n");
		}
		else if (gopt_verbose == 1) {
		    fprintf(stdout, "%s copied.\n", filepath);
		}
	    }
	    else
	    {
 		fileinfo->status = FS_RENAMED;
		++g_filelist_renamed;
		if (gopt_verbose >= 2) {
		    fprintf(stdout, " renamed.\n");
		}
		else if (gopt_verbose == 1) {
		    fprintf(stdout, "%s renamed.\n", filepath);
		}
	    }

	    if (gopt_verbose >= 1) {
		fprintf(stdout, "<-- %s", (char*)digestiter->value);
	    }

	    fileinfo->oldpath = strdup((char*)digestiter->value);
	}

	rb_insert(g_filelist, strdup(filepath), fileinfo);

	if (fileinfo->status == FS_NEW)
	{
	    if (gopt_verbose >= 2) {
		fprintf(stdout, " new.");
	    }
	    else if (gopt_verbose == 1) {
		fprintf(stdout, "%s new.", filepath);
	    }

	    ++g_filelist_new;
	}

	if (gopt_verbose >= 1) {
	    fprintf(stdout, "\n");
	}
	return TRUE;
    }
}

bool process_symlink(const char* filepath, const mystatst* st)
{
    struct rb_node* fileiter;

    if (filepath[0] == '.' && filepath[1] == '/')
	filepath += 2;

    /* skip over the digestfile */
    if (strcmp(filepath, gopt_digestfile) == 0)
	return TRUE;

    /* silently skip over ignored filepaths */
    if (gopt_matchpattern && strstr(filepath, gopt_matchpattern) == NULL)
	return TRUE;

    if (gopt_verbose >= 2) {
	fprintf(stdout, "%s ", filepath);
    }

    /* lookup file info */

    fileiter = rb_find(g_filelist, filepath);

    if (fileiter != NULL)
    {
	struct FileInfo* fileinfo = fileiter->value;
	char* linktarget = NULL;

	if (fileinfo->status != FS_UNSEEN)
	{
	    if (gopt_verbose >= 2) {
		fprintf(stdout, " same symlink processed twice??? This should never occur.\n");
	    }
	    else {
		fprintf(stdout, "%s same symlink processed twice??? This should never occur.\n", filepath);
	    }
	    return TRUE;
	}

	/* mimic method used for regular files even though reading a
	 * symlink is no expensive operation. */
	if (gopt_fullcheck)
	{
	    if (gopt_verbose >= 2) {
		fprintf(stdout, "check ");
	    }
	}
	else if (st->st_mtime != fileinfo->mtime ||
		 st->st_size != fileinfo->size)
	{
	    if (gopt_verbose >= 2) {
		fprintf(stdout, "touched ");
	    }
	}
	else
	{
	    if (gopt_verbose >= 2) {
		fprintf(stdout, "untouched.\n");
	    }
	    else if (gopt_verbose == 1 && !gopt_onlymodified) {
		fprintf(stdout, "%s untouched.\n", filepath);
	    }

	    fileinfo->status = FS_SEEN;
	    ++g_filelist_seen;

	    return TRUE;
	}

	linktarget = readlink_dup(filepath);

	if (!linktarget)
	{
	    if (gopt_verbose >= 2) {
		fprintf(stdout, " ERROR. Could not read symlink: %s.\n", strerror(errno));
	    }
	    else if (gopt_verbose >= 1) {
		fprintf(stdout, "%s ERROR. Could not read symlink: %s.\n", filepath, strerror(errno));
	    }
	    else if (gopt_verbose >= 0) {
		fprintf(stderr, "%s: could not read symlink \"%s\": %s.\n",
			g_progname, filepath, strerror(errno));
	    }

	    my_asprintf(&fileinfo->error, "Could not read symlink: %s.",
                        strerror(errno));

	    fileinfo->status = FS_ERROR;
	    fileinfo->mtime = st->st_mtime;
	    fileinfo->size = st->st_size;

	    ++g_filelist_error;
	    return FALSE;
	}

	if (fileinfo->symlink && strcmp(linktarget, fileinfo->symlink) == 0)
	{
	    if (gopt_verbose >= 2) {
		fprintf(stdout, "matched.\n");
	    }
	    else if (gopt_verbose == 1 && !gopt_onlymodified) {
		fprintf(stdout, "%s matched.\n", filepath);
	    }

	    fileinfo->status = FS_TOUCHED;
	    fileinfo->mtime = st->st_mtime;
	    fileinfo->size = st->st_size;
	    free(linktarget);

	    ++g_filelist_touched;
	}
	else
	{
	    if (gopt_verbose >= 2) {
		fprintf(stdout, "CHANGED.\n");
	    }
	    else if (gopt_verbose == 1) {
		fprintf(stdout, "%s CHANGED.\n", filepath);
	    }

	    fileinfo->status = FS_CHANGED;
	    fileinfo->mtime = st->st_mtime;
	    fileinfo->size = st->st_size;

	    if (fileinfo->symlink)
		free(fileinfo->symlink);

	    fileinfo->symlink = linktarget;

	    ++g_filelist_changed;
	}

	return TRUE;
    }
    else
    {
	struct FileInfo* fileinfo = malloc(sizeof(struct FileInfo));
	memset(fileinfo, 0, sizeof(struct FileInfo));

	fileinfo->status = FS_NEW;
	fileinfo->mtime = st->st_mtime;
	fileinfo->size = st->st_size;
	fileinfo->symlink = readlink_dup(filepath);

	if (!fileinfo->symlink)
	{
	    if (gopt_verbose >= 2) {
		fprintf(stdout, " ERROR. Could not read symlink: %s.\n", strerror(errno));
	    }
	    else if (gopt_verbose >= 1) {
		fprintf(stdout, "%s ERROR. Could not read symlink: %s.\n", filepath, strerror(errno));
	    }
	    else if (gopt_verbose >= 0) {
		fprintf(stderr, "%s: could not read symlink \"%s\": %s.\n",
			g_progname, filepath, strerror(errno));
	    }

	    my_asprintf(&fileinfo->error, "Could not read symlink: %s.",
                        strerror(errno));

	    fileinfo->status = FS_ERROR;

	    rb_insert(g_filelist, strdup(filepath), fileinfo);

	    ++g_filelist_error;

	    return FALSE;
	}

	rb_insert(g_filelist, strdup(filepath), fileinfo);

	if (gopt_verbose >= 2) {
	    fprintf(stdout, "new.\n");
	}
	else if (gopt_verbose == 1) {
	    fprintf(stdout, "%s new.\n", filepath);
	}

	++g_filelist_new;

	return TRUE;
    }
}

/**
 * Dynamically growing array of (dev_t, ino_t) pairs to test for
 * symlink loops while scanning.
 */

struct DirLevel
{
    dev_t	dev;
    ino_t	ino;
};

struct DirLevel* dirstack = NULL;
size_t dirstackmax = 0;
size_t dirstacklen = 0;

bool dirstack_push(const mystatst* st)
{
#if !ON_WIN32 /* win32 under mingw has no inode numbers. */

    size_t i;

    /* first search in the current stack for the new level */
    for (i = 0; i < dirstacklen; ++i)
    {
	if (dirstack[i].dev == st->st_dev &&
	    dirstack[i].ino == st->st_ino)
	{
	    return FALSE;
	}
    }

#endif

    /* add new entry */
    if (dirstacklen >= dirstackmax)
    {
        struct DirLevel* tmp;

	dirstackmax = dirstackmax * 2;
	if (dirstackmax < 16) dirstackmax = 16;

	tmp = realloc(dirstack, sizeof(struct DirLevel) * dirstackmax);
        if (!tmp) {
            return FALSE;
        }
        dirstack = tmp;
    }

    dirstack[dirstacklen].dev = st->st_dev;
    dirstack[dirstacklen].ino = st->st_ino;

    ++dirstacklen;

    return TRUE;
}

void dirstack_pop(const mystatst* st)
{
    assert( dirstacklen > 0 );

    assert( dirstack[dirstacklen-1].dev == st->st_dev );
    assert( dirstack[dirstacklen-1].ino == st->st_ino );
    (void)st;

    if (dirstacklen > 0)
	--dirstacklen;
}

bool scan_directory(const char* path, const mystatst* st)
{
    DIR* dirp;

    struct dirent* de;

    char **filenames = NULL;
    unsigned int filenamepos = 0;
    unsigned int filenamemax = 0;

    bool exclude_marker_found = FALSE;

    if (!dirstack_push(st))
    {
	fprintf(stderr, "%s: filesystem loop detected at \"%s\".\n",
		g_progname, path);
	return TRUE;
    }

    dirp = opendir(path);

    if (dirp == NULL)
    {
	dirstack_pop(st);
	fprintf(stderr, "%s: could not open directory \"%s\": %s\n",
		g_progname, path, strerror(errno));
	return FALSE;
    }

    while ((de = readdir(dirp)))
    {
	if (de->d_name[0] == '.' && de->d_name[1] == 0) continue;
	if (de->d_name[0] == '.' && de->d_name[1] == '.' && de->d_name[2] == 0) continue;

	if (filenamepos >= filenamemax)
	{
	    filenamemax *= 2;
	    if (filenamemax == 0) filenamemax = 8;
	    filenames = realloc(filenames, sizeof(char*) * filenamemax);
	}

	filenames[filenamepos++] = strdup( de->d_name );

	if (gopt_exclude_marker)
	{
	    if (strcmp(de->d_name, gopt_exclude_marker) == 0)
		exclude_marker_found = TRUE;
	}
    }

    closedir(dirp);

    if (exclude_marker_found)
    {
	if (gopt_verbose >= 2) {
	    fprintf(stderr, "%s: exclude marker found in \"%s\": skipping.\n",
		    g_progname, path);
	}

	free(filenames);
	dirstack_pop(st);
	return TRUE;
    }

    qsort(filenames, filenamepos, sizeof(char*), strcmpptr);

    {
	mystatst st;
	unsigned int fi;

	for (fi = 0; fi < filenamepos; ++fi)
	{
	    char* filepath;
	    my_asprintf(&filepath, "%s/%s", path, filenames[fi]);

	    free(filenames[fi]);

#ifndef S_ISSOCK
#define S_ISSOCK(x) 0
#endif
#ifndef S_ISLNK
#define S_ISLNK(x) 0
#endif

	    if (mylstat(filepath, &st) != 0)
	    {
		fprintf(stderr, "%s: could not stat file \"%s\": %s\n",
			g_progname, filepath, strerror(errno));
	    }
	    else if (S_ISLNK(st.st_mode))
	    {
		if (!gopt_followsymlinks)
		{
		    process_symlink(filepath, &st);
		}
		else
		{
		    if (mystat(filepath, &st) != 0)
		    {
			fprintf(stderr, "%s: could not stat symlink \"%s\": %s\n",
				g_progname, filepath, strerror(errno));
		    }
		    else if (S_ISCHR(st.st_mode) || S_ISBLK(st.st_mode))
		    {
			fprintf(stderr, "%s: skipping special device symlink \"%s\"\n",
				g_progname, filepath);
		    }
		    else if (S_ISFIFO(st.st_mode))
		    {
			fprintf(stderr, "%s: skipping named pipe symlink \"%s\"\n",
				g_progname, filepath);
		    }
		    else if (S_ISSOCK(st.st_mode))
		    {
			fprintf(stderr, "%s: skipping unix socket symlink \"%s\"\n",
				g_progname, filepath);
		    }
		    else if (S_ISDIR(st.st_mode))
		    {
			scan_directory(filepath, &st);
		    }
		    else if (!S_ISREG(st.st_mode))
		    {
			fprintf(stderr, "%s: skipping special symlink \"%s\"\n",
				g_progname, filepath);
		    }
		    else
		    {
			process_file(filepath, &st);
		    }
		}
	    }
	    else if (S_ISCHR(st.st_mode) || S_ISBLK(st.st_mode))
	    {
		fprintf(stderr, "%s: skipping special device file \"%s\"\n",
			g_progname, filepath);
	    }
	    else if (S_ISFIFO(st.st_mode))
	    {
		fprintf(stderr, "%s: skipping named pipe \"%s\"\n",
			g_progname, filepath);
	    }
	    else if (S_ISSOCK(st.st_mode))
	    {
		fprintf(stderr, "%s: skipping unix socket \"%s\"\n",
			g_progname, filepath);
	    }
	    else if (S_ISDIR(st.st_mode))
	    {
		scan_directory(filepath, &st);
	    }
	    else if (!S_ISREG(st.st_mode))
	    {
		fprintf(stderr, "%s: skipping special file \"%s\"\n",
			g_progname, filepath);
	    }
	    else
	    {
		process_file(filepath, &st);
	    }

	    free(filepath);
	}
    }

    free(filenames);
    dirstack_pop(st);

    return TRUE;
}

bool start_scan(const char* path)
{
    mystatst st;

    if (mylstat(path, &st) != 0)
    {
	fprintf(stderr, "%s: could not stat path \"%s\": %s\n",
		g_progname, path, strerror(errno));
    }
    else if (S_ISDIR(st.st_mode))
    {
	return scan_directory(path, &st);
    }
    else if (!S_ISREG(st.st_mode))
    {
	fprintf(stderr, "%s: skipping special path \"%s\"\n",
		g_progname, path);
    }
    else
    {
	return process_file(path, &st);
    }

    return FALSE;
}

/*************************************************
 * Functions for interactive scan result review  *
 *************************************************/

struct CommandEntry
{
    const char* name;
    bool	(*func)(void);
    const char*	help;
};

static struct CommandEntry cmdlist[16];

bool filelist_clean(void)
{
    return ( rb_size(g_filelist) == g_filelist_seen + g_filelist_touched );
}

unsigned int filelist_deleted(void)
{
    return rb_size(g_filelist) - (g_filelist_new + g_filelist_seen + g_filelist_touched + g_filelist_changed + g_filelist_error + g_filelist_renamed + g_filelist_copied + g_filelist_oldpath + g_filelist_skipped);
}

void print_summary(void)
{
    fprintf(stdout, "File scan summary:\n");

    if (g_filelist_new)
	fprintf(stdout, "        New: %d\n", g_filelist_new);

    if (g_filelist_seen)
	fprintf(stdout, "  Untouched: %d\n", g_filelist_seen);

    if (g_filelist_touched)
	fprintf(stdout, "    Touched: %d\n", g_filelist_touched);

    if (g_filelist_changed)
	fprintf(stdout, "    Changed: %d\n", g_filelist_changed);

    if (g_filelist_error)
	fprintf(stdout, "     Errors: %d\n", g_filelist_error);

    if (g_filelist_renamed)
	fprintf(stdout, "    Renamed: %d\n", g_filelist_renamed);

    if (g_filelist_copied)
	fprintf(stdout, "     Copied: %d\n", g_filelist_copied);

    if (g_filelist_skipped)
	fprintf(stdout, "    Skipped: %d\n", g_filelist_skipped);

    if (filelist_deleted())
	fprintf(stdout, "    Deleted: %d\n", filelist_deleted());

    fprintf(stdout, "      Total: %d\n", rb_size(g_filelist));
}

bool cmd_help(void)
{
    int i;

    fprintf(stdout, "Commands: (can be abbreviated)\n");

    for (i = 0; cmdlist[i].name; ++i)
    {
	if (!cmdlist[i].help) continue;

	fprintf(stdout, "  %-10s %s\n", cmdlist[i].name, cmdlist[i].help);
    }

    return TRUE;
}

bool cmd_new(void)
{
    struct rb_node* node;
    unsigned int count = 0;

    for (node = rb_begin(g_filelist); node != rb_end(g_filelist); node = rb_successor(g_filelist, node))
    {
	const struct FileInfo* fileinfo = node->value;

	if (fileinfo->status != FS_NEW) continue;

	fprintf(stdout, "%s new.\n", (char*)node->key);
	++count;
    }

    if (count == 0) {
	fprintf(stdout, "%s: no new files encountered during scan.\n",
		g_progname);
    }

    return TRUE;
}

bool cmd_untouched(void)
{
    struct rb_node* node;
    unsigned int count = 0;

    for (node = rb_begin(g_filelist); node != rb_end(g_filelist); node = rb_successor(g_filelist, node))
    {
	const struct FileInfo* fileinfo = node->value;

	if (fileinfo->status != FS_SEEN) continue;

	fprintf(stdout, "%s untouched.\n", (char*)node->key);
	++count;
    }

    if (count == 0) {
	fprintf(stdout, "%s: no untouched files encountered during scan.\n",
		g_progname);
    }

    return TRUE;
}

bool cmd_touched(void)
{
    struct rb_node* node;
    unsigned int count = 0;

    for (node = rb_begin(g_filelist); node != rb_end(g_filelist);
         node = rb_successor(g_filelist, node))
    {
	const struct FileInfo* fileinfo = node->value;

	if (fileinfo->status != FS_TOUCHED) continue;

	fprintf(stdout, "%s touched.\n", (char*)node->key);
	++count;
    }

    if (count == 0) {
	fprintf(stdout, "%s: no touched but unchanged files encountered during scan.\n",
		g_progname);
    }

    return TRUE;
}

bool cmd_changed(void)
{
    struct rb_node* node;
    unsigned int count = 0;

    for (node = rb_begin(g_filelist); node != rb_end(g_filelist);
         node = rb_successor(g_filelist, node))
    {
	const struct FileInfo* fileinfo = node->value;

	if (fileinfo->status != FS_CHANGED) continue;

	fprintf(stdout, "%s CHANGED.\n", (char*)node->key);
	++count;
    }

    if (count == 0) {
	fprintf(stdout, "%s: no changed files encountered during scan.\n",
		g_progname);
    }

    return TRUE;
}

bool cmd_deleted(void)
{
    struct rb_node* node;
    unsigned int count = 0;

    for (node = rb_begin(g_filelist); node != rb_end(g_filelist);
         node = rb_successor(g_filelist, node))
    {
	const struct FileInfo* fileinfo = node->value;

	if (fileinfo->status != FS_UNSEEN) continue;

	fprintf(stdout, "%s DELETED.\n", (char*)node->key);
	++count;
    }

    if (count == 0) {
	fprintf(stdout, "%s: no deleted files detected during scan.\n",
		g_progname);
    }

    return TRUE;
}

bool cmd_error(void)
{
    struct rb_node* node;
    unsigned int count = 0;

    for (node = rb_begin(g_filelist); node != rb_end(g_filelist);
         node = rb_successor(g_filelist, node))
    {
	const struct FileInfo* fileinfo = node->value;

	if (fileinfo->status != FS_ERROR) continue;

	fprintf(stdout, "%s ERROR. %s\n", (char*)node->key, fileinfo->error);
	++count;
    }

    if (count == 0) {
	fprintf(stdout, "%s: no errors encountered during scan.\n",
		g_progname);
    }

    return TRUE;
}

bool cmd_copied(void)
{
    struct rb_node* node;
    unsigned int count = 0;

    for (node = rb_begin(g_filelist); node != rb_end(g_filelist);
         node = rb_successor(g_filelist, node))
    {
	const struct FileInfo* fileinfo = node->value;

	if (fileinfo->status != FS_COPIED) continue;

	fprintf(stdout, "%s copied.\n<-- %s\n", (char*)node->key, fileinfo->oldpath);
	++count;
    }

    if (count == 0) {
	fprintf(stdout, "%s: no copied files detected during scan.\n",
		g_progname);
    }

    return TRUE;
}

bool cmd_renamed(void)
{
    struct rb_node* node;
    unsigned int count = 0;

    for (node = rb_begin(g_filelist); node != rb_end(g_filelist);
         node = rb_successor(g_filelist, node))
    {
	const struct FileInfo* fileinfo = node->value;

	if (fileinfo->status != FS_RENAMED) continue;

	fprintf(stdout, "%s renamed.\n<-- %s\n", (char*)node->key, fileinfo->oldpath);
	++count;
    }

    if (count == 0) {
	fprintf(stdout, "%s: no renamed files detected during scan.\n",
		g_progname);
    }

    return TRUE;
}

bool cmd_skipped(void)
{
    struct rb_node* node;
    unsigned int count = 0;

    for (node = rb_begin(g_filelist); node != rb_end(g_filelist);
         node = rb_successor(g_filelist, node))
    {
	const struct FileInfo* fileinfo = node->value;

	if (fileinfo->status != FS_SKIPPED) continue;

	fprintf(stdout, "%s SKIPPED.\n", (char*)node->key);
	++count;
    }

    if (count == 0) {
	fprintf(stdout, "%s: no files skipped during scan.\n",
		g_progname);
    }

    return TRUE;
}

bool cmd_write(void)
{
    FILE *sumfile = fopen(gopt_digestfile, "wb");

    uint32_t crc = 0;
    char digeststr[128];
    unsigned int digestcount = 0;
    struct rb_node* node;

    if (sumfile == NULL)
    {
	fprintf(stderr, "%s: could not open %s: %s\n",
		g_progname, gopt_digestfile, strerror(errno));
	return TRUE;
    }

    /* add a small note current date at the beginning */
    {
	time_t tnow = time(NULL);
	char datenow[64];
	strftime(datenow, sizeof(datenow), "%Y-%m-%d %H:%M:%S %Z", localtime(&tnow));

	fprintfcrc(&crc, sumfile, "# %s last update: %s\n", g_progname, datenow);
    }

    /* add persisent options to digest file */

    if (gopt_exclude_marker) {
	fprintfcrc(&crc, sumfile, "#: option --exclude-marker=%s\n", gopt_exclude_marker);
    }

    /* list files with properties and digests */

    for (node = rb_begin(g_filelist); node != rb_end(g_filelist);
         node = rb_successor(g_filelist, node))
    {
	struct FileInfo* fileinfo = node->value;
	char* filename;

	if (fileinfo->status == FS_UNSEEN) continue;
	if (fileinfo->status == FS_ERROR) continue;
	if (fileinfo->status == FS_OLDPATH) continue;

	filename = strdup((char*)node->key);

	if (fileinfo->symlink)
	{
#if ON_WIN32 /* mingw uses msvcrt which uses %I64d or %I64u for long long formatting. */

	    if (needescape_filename(&fileinfo->symlink)) /* may replace the symlink string */
		fprintfcrc(&crc, sumfile, "#: mtime %ld size %I64d target\\ %s\n", fileinfo->mtime, fileinfo->size, fileinfo->symlink);
	    else
		fprintfcrc(&crc, sumfile, "#: mtime %ld size %I64d target %s\n", fileinfo->mtime, fileinfo->size, fileinfo->symlink);

#else

	    if (needescape_filename(&fileinfo->symlink)) /* may replace the symlink string */
		fprintfcrc(&crc, sumfile, "#: mtime %ld size %lld target\\ %s\n", fileinfo->mtime, fileinfo->size, fileinfo->symlink);
	    else
		fprintfcrc(&crc, sumfile, "#: mtime %ld size %lld target %s\n", fileinfo->mtime, fileinfo->size, fileinfo->symlink);

#endif
	    if (needescape_filename(&filename)) /* may replace the filename string */
		fprintfcrc(&crc, sumfile, "#: symlink\\ %s\n", filename);
	    else
		fprintfcrc(&crc, sumfile, "#: symlink %s\n", filename);
	}
	else
	{
#if ON_WIN32 /* mingw uses msvcrt which uses %I64d or %I64u for long long formatting. */

	    fprintfcrc(&crc, sumfile, "#: mtime %ld size %I64d\n", fileinfo->mtime, fileinfo->size);

#else

	    fprintfcrc(&crc, sumfile, "#: mtime %ld size %lld\n", fileinfo->mtime, fileinfo->size);

#endif
	    if (needescape_filename(&filename)) /* may replace the filename string */
		fprintfcrc(&crc, sumfile, "\\");

	    fprintfcrc(&crc, sumfile, "%s  %s\n", digest_bin2hex(fileinfo->digest, digeststr), filename);
	}

	++digestcount;

	free(filename);
    }

    fprintf(sumfile, "#: crc 0x%08x eof\n", crc);

    fclose(sumfile);

    fprintf(stderr, "%s: wrote %d digests to %s\n",
	    g_progname, digestcount, gopt_digestfile);

    return FALSE;
}

bool cmd_quit(void)
{
    return FALSE;
}

static struct CommandEntry cmdlist[16] =
{
    { "help",		&cmd_help,	"See this help text." },
    { "new",		&cmd_new,	"Print newly seen files not in digest file." },
    { "untouched",	&cmd_untouched,	"Print all untouched files." },
    { "touched",	&cmd_touched,	"Print all files with changed modification time." },
    { "changed",	&cmd_changed,	"Print files with changed contents." },
    { "modified",	&cmd_changed,	NULL },
    { "copied",		&cmd_copied,	"Print files copied from a different path." },
    { "renamed",	&cmd_renamed,	"Print files renamed from a different path." },
    { "deleted",	&cmd_deleted,	"Print deleted files." },
    { "error",		&cmd_error,	"Print files with read errors." },
    { "skipped",	&cmd_skipped,	"Print files skipped during scan." },
    { "save",		&cmd_write,	"Write updates to digest file and exit program." },
    { "write",		&cmd_write,	NULL },
    { "exit",		&cmd_quit,	"Exit program without saving updates." },
    { "quit",		&cmd_quit,	NULL },
    { NULL,             NULL,		NULL },
};

/**********
 * main() *
 **********/

void print_usage(void)
{
/*          xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
 */

    printf("Usage: %s [OPTIONS...]\n"
	   "\n"
	   "Tool to read, verify and update MD5 or SHA digest files.\n"
	   "\n", g_progname);

    printf("Looks for a digest file (defaults to \"md5sum.txt\", \"sha1sum.txt\",\n"
	   "\"sha256sum.txt\" or \"sha512sum.txt\") in the current directory. If one exists\n"
	   "it is parsed and loaded. Then all files in the directory are recursively\n"
	   "checked. Their status (new, unmodified, touched and matching, changed) is\n"
	   "determined from modification time and the stored file digest. After the scan\n"
	   "a manual review of the status can be done and a new digest file written.\n"
	   "\n");

    printf("Options:\n");
    printf("  -b, --batch           enable non-interactive batch processing mode.\n");
    printf("  -c, --check           perform full digest check ignoring modification times.\n");
    printf("  -d, --directory=PATH  change into this directory before any operations.\n");
    printf("      --exclude-marker=FILE  skip all directories contain this marker file.\n");
    printf("  -f, --file=FILE       check FILE for existing digests and writing updates.\n");
    printf("  -l, --links           follow symlinks instead of saving their destination.\n");
    printf("  -m, --modified        suppressing printing of unchanged files.\n");
    printf("      --modify-window=NUM  allow higher delta window for modification times.\n");
    printf("  -q, --quiet           reduce status printing while scanning.\n");
    printf("  -r, --restrict=PAT    run full digest check restricted to files matching PAT.\n");
    printf("  -t, --type=TYPE       select digest type for newly created digest files.\n");
    printf("                          TYPE = md5, sha1, sha256 or sha512.\n");
    printf("  -u, --update          automatically update digest file in batch mode.\n");
    printf("  -v, --verbose         increase status printing during scanning.\n");
    printf("  -V, --version         print digup version and exit.\n");
    printf("  -w, --windows         allow a --modify-window of 1 (for FAT filesystems).\n");
    printf("\n");

    printf("See \"man 1 digup\" for further explanations. This is digup " VERSION "\n");
    printf("\n");
}

int main(int argc, char* argv[])
{
    int retcode = 0;

    g_progname = argv[0];

    while (1)
    {
	static struct option long_options[] =
	    {
		{ "batch",   	no_argument,       0, 'b' },
		{ "check",   	no_argument,       0, 'c' },
		{ "directory",	required_argument, 0, 'd' },
		{ "file",   	required_argument, 0, 'f' },
		{ "help",   	no_argument,       0, 'h' },
		{ "links",      no_argument,       0, 'l' },
		{ "modified",  	no_argument,       0, 'm' },
		{ "quiet",      no_argument,       0, 'q' },
		{ "restrict",   required_argument, 0, 'r' },
		{ "type",   	required_argument, 0, 't' },
		{ "update",     no_argument,       0, 'u' },
		{ "verbose",    no_argument,       0, 'v' },
		{ "version",    no_argument,       0, 'V' },
		{ "windows",    no_argument,       0, 'w' },
		{ "modify-window", required_argument, 0, 1 },
		{ "exclude-marker", required_argument, 0, 2 },
		{ NULL,	    	0,                 0, 0 }
	    };

	/* getgopt_long stores the option index here. */
	int option_index = 0;

	int c = getopt_long(argc, argv, "bcd:f:hlmqr:t:uvVw",
			    long_options, &option_index);

     	if (c == -1) break;

	switch (c)
	{
	case 1:
	{
	    char *endp;
	    gopt_modify_window = strtoul(optarg, &endp, 10);
	    if (!endp || *endp) {
		fprintf(stderr, "%s: invalid valid for modify window: use an unsigned integer\n",
			g_progname);
		return -1;
	    }
	    break;
	}

	case 2:
	    gopt_exclude_marker = strdup(optarg);
	    break;

	case 'b':
	    gopt_batch = TRUE;
	    --gopt_verbose;
	    break;

	case 'c':
	    gopt_fullcheck = TRUE;
	    break;

	case 'd':
	    if (chdir(optarg) != 0)
	    {
		fprintf(stderr, "%s: could not chdir to \"%s\": %s\n",
			g_progname, optarg, strerror(errno));
		return -1;
	    }
	    break;

	case 'f':
	    gopt_digestfile = optarg;
	    break;

	case 'h':
	    print_usage();
	    return -1;

	case 'l':
	    gopt_followsymlinks = TRUE;
	    break;

	case 'm':
	    gopt_onlymodified = TRUE;
	    break;

	case 'q':
	    --gopt_verbose;
	    break;

	case 'r':
	    gopt_matchpattern = optarg;
	    fprintf(stdout, "Checking only paths matching: \"%s\".\n", gopt_matchpattern);
	    break;

	case 't':
	    if (strcasecmp(optarg, "md5") == 0)
	    {
		gopt_digesttype = DT_MD5;

		if (gopt_digestfile == NULL)
		    gopt_digestfile = "md5sum.txt";
	    }
	    else if (strcasecmp(optarg, "sha1") == 0)
	    {
		gopt_digesttype = DT_SHA1;

		if (gopt_digestfile == NULL)
		    gopt_digestfile = "sha1sum.txt";
	    }
	    else if (strcasecmp(optarg, "sha128") == 0)
	    {
		gopt_digesttype = DT_SHA1;

		if (gopt_digestfile == NULL)
		    gopt_digestfile = "sha128sum.txt";
	    }
	    else if (strcasecmp(optarg, "sha256") == 0)
	    {
		gopt_digesttype = DT_SHA256;

		if (gopt_digestfile == NULL)
		    gopt_digestfile = "sha256sum.txt";
	    }
	    else if (strcasecmp(optarg, "sha512") == 0)
	    {
		gopt_digesttype = DT_SHA512;

		if (gopt_digestfile == NULL)
		    gopt_digestfile = "sha512sum.txt";
	    }
	    else
	    {
		fprintf(stderr, "%s: unknown digest type: \"%s\". See --help.\n",
			g_progname, optarg);
		return -1;
	    }
	    break;

	case 'u':
	    gopt_update = TRUE;
	    break;

	case 'v':
	    ++gopt_verbose;
	    break;

	case 'V':
	    printf("digup " VERSION "\n");
            return 0;

	case 'w':
	    gopt_modify_window = 1;
	    break;

	case '?':
	    /* getgopt_long already printed an error message. */
	    fprintf(stderr, "Try \"%s --help\" for more information on program usage.\n", g_progname);
	    return -1;

	default:
	    assert(0);
	}
    }

    /* print any remaining unknown command line arguments. */

    if (optind < argc)
    {
	while (optind < argc)
	{
	    fprintf(stderr, "%s: superfluous argument \"%s\"\n", g_progname, argv[optind++]);
	}
	return -1;
    }

    /* reduce level for only-modified printing */

    if (gopt_onlymodified && gopt_verbose >= 2)
	gopt_verbose = 1;

    if (gopt_update && !gopt_batch)
    {
	fprintf(stderr, "%s: automaticcaly updating the digest file requires --batch mode.\n", g_progname);
	return -1;
    }

    /* initialize red-black trees */

    g_filelist = rb_create(rbtree_string_cmp, rbtree_string_free, rbtree_fileinfo_free, NULL, NULL);

    g_filedigestmap = rb_create(rbtree_digest_result_cmp, rbtree_digest_result_free, rbtree_null_free, NULL, NULL);

    /* read digest file if it exists */

    if (!read_digestfile())
	return -1;

    /* recursively scan current directory */

    start_scan(".");

    if (filelist_deleted() != 0 || !gopt_onlymodified)
    {
	/* always print deleted files, otherwise they may be silently ignored. */
	cmd_deleted();
    }

    /* batch processing */

    if (gopt_batch)
    {
	if (!filelist_clean() || !gopt_onlymodified)
	    print_summary();

	if (gopt_update)
	{
	    cmd_write();
	}

	if (filelist_clean())
	    retcode = 0;
	else
	    retcode = 1; /* changes, renames, moves, deletes or read errors detected. */
    }
    /* interactive processing */
    else
    {
	char input[256];

	fprintf(stdout, "Scan finished. ");

	/* print scan summary */

	while ( print_summary(),
		fprintf(stdout, "Command (see help)? "),
		fgets(input, sizeof(input), stdin) )
	{
	    /* Run through command table and determine entry by prefix matching */
	    int cmd = -1;
	    unsigned int i;

	    if (strlen(input) > 0 && input[strlen(input)-1] == '\n')
		input[strlen(input)-1] = 0;

	    for (i = 0; cmdlist[i].name; ++i)
	    {
		if (strncmp(input, cmdlist[i].name, strlen(input)) == 0)
		{
		    if (cmd == -1) cmd = i;
		    else cmd = -2;
		}
	    }

	    if (cmd >= 0)
	    {
		if (!cmdlist[cmd].func())
		    break;
	    }
	    else if (cmd == -2)
	    {
		fprintf(stdout, "%s: Ambiguous command. See \"help\".\n",
			g_progname);
	    }
	    else
	    {
		fprintf(stdout, "%s: Unknown command. See \"help\".\n",
			g_progname);
	    }
	}
    }

    rb_destroy(g_filelist);
    rb_destroy(g_filedigestmap);

    if (dirstack) free(dirstack);

    if (gopt_exclude_marker) free((void*)gopt_exclude_marker);

    return retcode;
}

/*****************************************************************************/
