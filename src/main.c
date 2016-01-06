/*
 * =====================================================================================
 *
 *       Filename:  main.c
 *
 *    Description:  Program 'packaging' - real work is done in pkfile.c
 *
 *        Version:  1.0
 *        Created:  23/12/2015 12:48:35
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  Sébastien Millet (smt), milletseb@laposte.net
 *
 * =====================================================================================
 */

#define PACKAGE_NAME "pkfile"
#define PACKAGE_STRING "pkfile 0.1"

#include <stdio.h>
#include <assert.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <errno.h>
#include <string.h>

#include "common.h"
#include "pkfile.h"

static const char *tree_strings[] = {
	"└── ", /* T_NORTH_EAST */
	"    ", /* T_BLANK */
	"├── ", /* T_NORTH_SOUTH_EAST */
	"│   ", /* T_NORTH_SOUTH */
	"",     /* T_EMPTY */
};

	/*
	 * The der "SEQUENCE" or "SET OF" provide a hierarchical
	 * structure where we have a straightforward "level" notion
	 * (= number of hops to the chain head).
	 *
	 * A value of -1 means there is no limit.
	 * */
int max_depth = -1;
char *file_in = NULL;
char *file_out = NULL;

int out_level = L_NORMAL;

	/*
	 * Needed by FATAL_ERROR macro
	 * */
void fatalln(const char *file, int line, const char *fmt, ...)
{
	va_list args;
	va_start(args, fmt);
	fprintf(stderr, "File %s line %d: ", file, line);
	vfprintf(stderr, fmt, args);
	fprintf(stderr, "\n");
	va_end(args);
	exit(1);
}

	/*
	 * Output a formatted string. "ln" means, a new line gets printed in the end.
	 * */
int outln(int level, const char *fmt, ...)
{
	if (level <= out_level || level == L_ENFORCE) {
		va_list args;
		va_start(args, fmt);
		int r;
		if (level == L_ERROR || level == L_WARNING) {
			r = vfprintf(stderr, fmt, args);
			fprintf(stderr, "\n");
		} else {
			r = vprintf(fmt, args);
			printf("\n");
		}
		va_end(args);
		return r;
	} else {
		return -1;
	}
}

int out(int level, const char *fmt, ...)
{
	if (level <= out_level || level == L_ENFORCE) {
		va_list args;
		va_start(args, fmt);
		int r;
		if (level == L_ERROR || level == L_WARNING) {
			r = vfprintf(stderr, fmt, args);
		} else {
			r = vprintf(fmt, args);
		}
		va_end(args);
		return r;
	} else {
		return -1;
	}
}

int dbg_core(const char *filename, int line, const char *fmt, ...)
{
	if (out_level >= L_DEBUG) {
		out(L_DEBUG, "%s:%d\t", filename, line);
		va_list args;
		va_start(args, fmt);
		int r = vprintf(fmt, args);
		va_end(args);
		return r;
	} else
		return -1;
}

int outln_error(const char *fmt, ...)
{
	va_list args;
	va_start(args, fmt);
	fprintf(stderr, "Error: ");
	int r = vfprintf(stderr, fmt, args);
	fprintf(stderr, "\n");
	va_end(args);
	return r;
}

int outln_warning(const char *fmt, ...)
{
	va_list args;
	va_start(args, fmt);
	fprintf(stderr, "Warning: ");
	int r = vfprintf(stderr, fmt, args);
	fprintf(stderr, "\n");
	va_end(args);
	return r;
}

int outln_errno(int e)
{
	return outln_error("%s", strerror(e));
}

char *s_strncpy(char *dest, const char *src, size_t n)
{
		strncpy(dest, src, n);
		dest[n - 1] = '\0';
		return dest;
}
	/* The define below triggers an error if usual strncpy is used */
#define strncpy(a, b, c) ErrorDontUse_strncpy_Use_s_strncpy_Instead

char *s_strncat(char *dest, const char *src, size_t n)
{
	strncat(dest, src, n - 1);
	dest[n - 1] = '\0';
	return dest;
}
	/* The define below triggers an error if usual strncat is used */
#define strncat(a, b, c) ErrorDontUse_strncat_Use_s_strncat_Instead

ssize_t file_get_size(const char* filename)
{
	struct stat st;
	stat(filename, &st);
	return st.st_size;
}

static void usage()
{
	fprintf(stderr, "Usage: %s [options] [FILE]\n", PACKAGE_NAME);
	fprintf(stderr, "Extract sequences of PKCS files.\n");
	fprintf(stderr, "  -h  --help     print this usage and exit\n");
	fprintf(stderr, "  -V  --verbose  verbose output\n");
	fprintf(stderr, "  -D  --debug    debug output\n");
	fprintf(stderr, "  -v  --version  print version information and exit\n");
	fprintf(stderr, "  -d  --depth n  set max depth to n (default: -1)\n");
	fprintf(stderr, "                 -1 = no maximum depth\n");
	fprintf(stderr, "  -o  --out      output to file\n");
	fprintf(stderr, "  --             end of parameters, next option is file name\n");
	fprintf(stderr, "If FILE is not specified, read standard input.\n");
	exit(-1);
}

static void version()
{
#ifdef DEBUG
	printf("%sd\n", PACKAGE_STRING);
#else
	printf("%s\n", PACKAGE_STRING);
#endif
	printf("Copyright 2015 Sébastien Millet.\n");
	printf("This is free software with ABSOLUTELY NO WARRANTY.\n");
}

static void opt_check(unsigned int n, const char *opt)
{
	static int defined_options[4] = {0, 0, 0, 0};

	assert(n < sizeof(defined_options) / sizeof(*defined_options));

	if (defined_options[n]) {
		fprintf(stderr, "Option %s already set\n", opt);
		exit(-2);
	} else
		defined_options[n] = TRUE;
}

static void parse_options(int argc, char **argv)
{
#define OPT_WITH_VALUE_CHECK \
if (shortopt_nb >= 1 && shortopt_i < shortopt_nb - 1) { \
	missing_option_value = argv_a_short + 1; \
	a = -1; \
	break; \
} \
if (++a >= argc) { \
	missing_option_value = argv[a - 1] + 1; \
	a = -1; \
	break; \
}

	int optset_debug = FALSE;

	char *missing_option_value = NULL;

	int a = 1;
	char *argv_a_short;
	char shortopt[3];
	int shortopt_nb = 0;
	int shortopt_i = -1;
	while (a < argc) {
		if (shortopt_nb == 0) {
			if (strlen(argv[a]) >= 2 && argv[a][0] == '-' && argv[a][1] != '-') {
				shortopt_nb = strlen(argv[a]) - 1;
				shortopt_i = 0;
			}
		}
		if (shortopt_nb >= 1) {

			assert(shortopt_i <= shortopt_nb);
			shortopt[0] = '-';
			shortopt[1] = argv[a][shortopt_i + 1];
			shortopt[2] = '\0';
			argv_a_short = shortopt;
		} else {
			argv_a_short = argv[a];
		}

		if (!strcmp(argv[a], "--help") || !strcmp(argv_a_short, "-h")) {
			usage();
		} else if (!strcmp(argv[a], "--version") || !strcmp(argv_a_short, "-v")) {
			version();
			exit(0);
		} else if (!strcmp(argv[a], "--verbose") || !strcmp(argv_a_short, "-V")) {
			opt_check(0, argv[a]);
			out_level = L_VERBOSE;
		} else if (!strcmp(argv[a], "--debug") || !strcmp(argv_a_short, "-D")) {
			opt_check(1, argv[a]);
			optset_debug = TRUE;
		} else if (!strcmp(argv[a], "--out") || !strcmp(argv_a_short, "-o")) {
			opt_check(2, argv[a]);
			OPT_WITH_VALUE_CHECK
			file_out = argv[a];
		} else if (!strcmp(argv[a], "--depth") || !strcmp(argv_a_short, "-d")) {
			opt_check(3, argv[a]);
			OPT_WITH_VALUE_CHECK
			max_depth = atoi(argv[a]);
		} else if (argv[a][0] == '-') {
			if (strcmp(argv[a], "--")) {
				fprintf(stderr, "%s: invalid option -- '%s'\n", PACKAGE_NAME, argv[a]);
				a = -1;
				break;
			} else {
				++a;
				break;
			}
		} else {
			if (file_in == NULL) {
				file_in = argv[a];
			} else {
				fprintf(stderr, "%s: invalid argument -- '%s'\n", PACKAGE_NAME, argv[a]);
				a = -1;
				break;
			}
		}
		if (shortopt_nb >= 1) {
			if (++shortopt_i >= shortopt_nb)
				shortopt_nb = 0;
		}
		if (shortopt_nb == 0)
			++a;
	}
	if ((a >= 1 && a < argc - 1) || (a >= 1 && a == argc - 1 && file_in != NULL)) {
		fprintf(stderr, "%s: trailing options.\n", PACKAGE_NAME);
		a = -1;
	} else if (a >= 1 && a == argc - 1) {
		file_in = argv[a];
	} else if (missing_option_value != NULL) {
		fprintf(stderr, "%s: option '%s' requires one argument\n", PACKAGE_NAME, missing_option_value);
	}
	if (a < 0)
		usage();

	if (optset_debug)
		out_level = L_DEBUG;
}

int main(int argc, char **argv)
{
	parse_options(argc, argv);

	FILE *fin;
	ssize_t size;
	if (file_in == NULL) {
		DBG("Reading from stdin\n")
		fin = stdin;
		size = -1;
	} else {
		DBG("Reading from file %s\n", file_in)
		if ((size = file_get_size(file_in)) < 0) {
			outln_errno(errno);
			exit(-2);
		}
		if ((fin = fopen(file_in, "rb")) == NULL) {
			outln_errno(errno);
			exit(-3);
		}
	}
	pkctrl_t *ctrl = pkctrl_construct(fin, size);

	FILE *fout;
	if (file_out == NULL) {
		DBG("Output to stdout\n")
		fout = stdout;
	} else {
		DBG("Output to file %s\n", file_out)
		if ((fout = fopen(file_out, "wb")) == NULL) {
			outln_errno(errno);
			exit(-4);
		}
	}
	fprintf(fout, "%06X  ", 0);
	fprintf(fout, "%17s", "");
	if (file_in != NULL)
		fprintf(fout, "%s\n", file_in);
	else
		fprintf(fout, "(stdin)\n");

	seq_t *seq;
	for (seq = seq_next(ctrl); seq != NULL && seq->type != E_ERROR; seq = seq_next(ctrl)) {

		if (max_depth >= 0 && seq->level > max_depth) continue;

		fprintf(fout, "%06X  ", (unsigned int)seq->offset);

		int n = 0;
		seq_t *s;

		char buf1[100];
		buf1[0] = '\0';
		char buf2[10];
		for (s = pkctrl_head(ctrl); s != NULL && s->child != NULL; s = s->child) {
			assert(n == s->level);
			++n;

			if (n == 1) {
				snprintf(buf2, sizeof(buf2), "%d", s->index);
			} else {
				snprintf(buf2, sizeof(buf2), ".%d", s->index);
			}
			s_strncat(buf1, buf2, sizeof(buf1));
		}
		fprintf(fout, "%-15s  ", buf1);

		for (s = pkctrl_head(ctrl); s != NULL; s = s->child) {
			assert(s->tree >= 0 && s->tree < sizeof(tree_strings) / sizeof(*tree_strings));
			fputs(tree_strings[s->tree], fout);
		}
		fprintf(fout, "%s: %s, len: %li (%li+%li)\n", seq->tag_type, seq->tag_name, seq->total_len, seq->header_len, seq->data_len);
		if (seq->type == E_DATA) {
			int i;
			for (i = 0; i < seq->header_len + seq->data_len; ++i) {
				if (!(i % 16)) {
					fprintf(fout, "%25s", " ");
					for (s = pkctrl_head(ctrl); s != NULL; s = s->child) {
						tree_t t = s->tree;
						assert(t >= 0 && t < sizeof(tree_strings) / sizeof(*tree_strings));
						if (t == T_NORTH_EAST)
							t = T_BLANK;
						else if (t == T_NORTH_SOUTH_EAST)
							t = T_NORTH_SOUTH;
						fputs(tree_strings[t], fout);
					}
					fputs("      ", fout);
				}
				unsigned char c;
				if (i < seq->header_len)
					c = seq->header[i];
				else
					c = seq->data[i - seq->header_len];
				fprintf(fout, "%02X", c);
				if (!((i + 1) % 16))
					fprintf(fout, "\n");
				else if (!((i + 1) % 4))
					fprintf(fout, "  ");
			}
			fputs("\n", fout);
		}
	}
	if (seq != NULL && seq->type == E_ERROR) {
		outln_error(seq->errmsg);
		seq_clear_error(seq);
	}
	pkctrl_destruct(ctrl);
	if (file_out != NULL)
		fclose(fout);
	if (file_in != NULL)
		fclose(fin);
}

