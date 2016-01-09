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

/*#define VSAFE*/

#define PACKAGE_NAME "pkfile"
#define PACKAGE_STRING "pkfile 0.1"

#include <stdio.h>
#include <unistd.h>
#include <assert.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <errno.h>
#include <string.h>

#include "common.h"
#include "pkfile.h"
#include "ppem.h"

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
int opt_max_depth = -1;
char *file_in = NULL;
char *file_out = NULL;

int out_level = L_NORMAL;

const char *opt_password = NULL;

const char *opt_inform = NULL;
int assume_pem = FALSE;
int assume_der = FALSE;

int opt_tree = FALSE;

int opt_force_no_interactive = FALSE;

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

	/*
	 * Returns a copied, allocated string. Uses s_strncpy for the string
	 * copy (see comment above).
	 * dst can be null, in which case the new string is to be retrieved
	 * by the function return value.
	 */
char *s_alloc_and_copy(char **dst, const char *src)
{
	unsigned int s = strlen(src) + 1;
	char *target = (char *)malloc(s);
	s_strncpy(target, src, s);
	if (dst)
		*dst = target;
	return target;
}

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
	fprintf(stderr, "This program will automatically detect whether PEM format\n");
	fprintf(stderr, "is being used, or DER, unless started with --inform.\n");
	fprintf(stderr, "  -h  --help          print this usage and exit\n");
	fprintf(stderr, "  -V  --verbose       verbose output\n");
	fprintf(stderr, "  -D  --debug         debug output\n");
	fprintf(stderr, "  -v  --version       print version information and exit\n");
	fprintf(stderr, "  -d  --depth n       set max depth to n (default: -1)\n");
	fprintf(stderr, "                      -1 = no maximum depth\n");
	fprintf(stderr, "  -p  --password pwd  Set password\n");
	fprintf(stderr, "  -i  --inform format Set format. Either pem or der\n");
	fprintf(stderr, "  -t  --tree          Outputs in hierarchical format\n");
	fprintf(stderr, "  -o  --out           output to file\n");
	fprintf(stderr, "  --                  end of parameters, next option is file name\n");
	fprintf(stderr, "If FILE is not specified, read standard input.\n");
	exit(0);
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
	static int defined_options[8] = {0, 0, 0, 0, 0, 0, 0, 0};

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
		} else if (!strcmp(argv[a], "--password") || !strcmp(argv_a_short, "-p")) {
			opt_check(3, argv[a]);
			OPT_WITH_VALUE_CHECK
			opt_password = argv[a];
		} else if (!strcmp(argv[a], "--inform") || !strcmp(argv_a_short, "-i")) {
			opt_check(4, argv[a]);
			OPT_WITH_VALUE_CHECK
			opt_inform = argv[a];
		} else if (!strcmp(argv[a], "--depth") || !strcmp(argv_a_short, "-d")) {
			opt_check(5, argv[a]);
			OPT_WITH_VALUE_CHECK
			opt_max_depth = atoi(argv[a]);
		} else if (!strcmp(argv[a], "--tree") || !strcmp(argv_a_short, "-t")) {
			opt_check(6, argv[a]);
			opt_tree = TRUE;
		} else if (!strcmp(argv[a], "--no-interactive") || !strcmp(argv_a_short, "-i")) {
			opt_check(7, argv[a]);
			opt_force_no_interactive = TRUE;
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
			if (!file_in) {
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
	if ((a >= 1 && a < argc - 1) || (a >= 1 && a == argc - 1 && file_in)) {
		fprintf(stderr, "%s: trailing options.\n", PACKAGE_NAME);
		a = -1;
	} else if (a >= 1 && a == argc - 1) {
		file_in = argv[a];
	} else if (missing_option_value) {
		fprintf(stderr, "%s: option '%s' requires one argument\n", PACKAGE_NAME, missing_option_value);
	}
	if (opt_inform) {
		if (!strcmp(opt_inform, "PEM") || !strcmp(opt_inform, "pem"))
			assume_pem = TRUE;
		else if (!strcmp(opt_inform, "DER") || !strcmp(opt_inform, "der"))
			assume_der = TRUE;
		else {
			fprintf(stderr, "%s: unknown input format, allowed values are pem and der\n", PACKAGE_NAME);
		}
	}

	if (a < 0)
		usage();

	if (optset_debug)
		out_level = L_DEBUG;
}

char *cb_password_pre()
{
	char *password;

	char *readpwd;
	if (!opt_password) {
		fprintf(stderr, "Please type in the password:\n");
		readpwd = NULL;
		size_t s = 0;
		if (getline(&readpwd, &s, stdin) < 0) {
			if (readpwd)
				free(readpwd);
			return NULL;
		}
		password = readpwd;
	} else {
		password = s_alloc_and_copy(NULL, opt_password);
	}

	int i;
	for (i = 0; i < 2; ++i) {
		int n = strlen(password);
		if (n >= 1 && (password[n - 1] == '\n' || password[n - 1] == '\r'))
			password[n - 1] = '\0';
	}

	DBG("Password: '%s'", password)

	return password;
}

void cb_password_post(char *password)
{
	if (password)
		free(password);
}

void cb_loop_top(const pem_ctrl_t *ctrl)
{
	void print_hexa(int level, const unsigned char *buf, int buf_len) {
		int i; for (i = 0; i < buf_len; ++i) out(level, "%02X", (unsigned char)buf[i]);
	}

	if (!pem_has_data(ctrl)) {
		outln(L_VERBOSE, "PEM block: [%s] (skipped: %s)", pem_header(ctrl), pem_errorstring(pem_status(ctrl)));
		return;
	}

	if (pem_has_encrypted_data(ctrl)) {
		out(L_VERBOSE, "PEM block: [%s] (encrypted with %s", pem_header(ctrl), pem_cipher(ctrl));
		if (!pem_salt(ctrl))
			outln(L_VERBOSE, ", no salt)");
		else {
			out(L_VERBOSE, ", salt: ");
			print_hexa(L_VERBOSE, pem_salt(ctrl), pem_salt_len(ctrl));
			outln(L_VERBOSE, ")");
		}
	} else {
		outln(L_VERBOSE, "PEM block: [%s]", pem_header(ctrl));
	}
}

void cb_loop_decrypt(int decrypt_ok, const char *errmsg)
{
	if (!decrypt_ok)
		outln_error("%s", errmsg);
}

void print_tree(const seq_t *seq, const seq_t *seq_head, FILE *fout)
{
	if (!seq) {
		fprintf(fout, "%26s\n", ".");
		return;
	}

	if (opt_max_depth >= 0 && seq->level > opt_max_depth) return;

	fprintf(fout, "%06X  ", (unsigned int)seq->offset);

	int n = 0;
	const seq_t *s;

	char buf1[100];
	buf1[0] = '\0';
	char buf2[10];
	for (s = seq_head; s && s->child; s = s->child) {
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

	for (s = seq_head; s; s = s->child) {
		assert(s->tree >= 0 && s->tree < sizeof(tree_strings) / sizeof(*tree_strings));
		fputs(tree_strings[s->tree], fout);
	}
	fprintf(fout, "%s: %s, len: %li (%li+%li)\n",
			seq->tag_type_str, seq->tag_name, seq->total_len, seq->header_len, seq->data_len);
	if (seq->type == E_DATA) {
		int i, period1, period2;
		int is_string = seq_has_string_data(seq);
		if (is_string) {
			period1 = 38;
			period2 = 0;
		} else {
			period1 = 16;
			period2 = 4;
		}
		for (i = 0; i < seq->data_len; ++i) {
			if (!(i % period1)) {
				fprintf(fout, "%25s", " ");
				for (s = seq_head; s; s = s->child) {
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
			unsigned char c = seq->data[i];
			if (is_string) {
				if (c < 32 || c == 127)
					c = '.';
				fprintf(fout, "%c", (char)c);
			} else {
				fprintf(fout, "%02X", c);
			}
			if (!((i + 1) % period1))
				fprintf(fout, "\n");
			else if (period2 && !((i + 1) % period2))
				fprintf(fout, "  ");
		}
		fputs("\n", fout);
	}
}

void print_der(const seq_t *seq, FILE *fout)
{
	if (!seq)
		return;

	int i;
	for (i = 0; i < seq->header_len + (seq->data ? seq->data_len : 0); ++i) {
		char c;
		if (i < seq->header_len)
			c = seq->header[i];
		else if (seq->data)
			c = seq->data[i - seq->header_len];
		else
			FATAL_ERROR("Stop");
		fputc(c, fout);
	}
}

int main(int argc, char **argv)
{
const size_t STDIN_BUFSIZE = 8;

	parse_options(argc, argv);

	int is_interactive = isatty(fileno(stdout));
	DBG("is_interactive = %i\n", is_interactive);

#ifdef VSAFE
	if (!file_out && is_interactive && !opt_force_no_interactive && !opt_tree) {
		outln_error("der-encoded data not output to a terminal, use '-o FILENAME' or '-i' options to avoid this error");
		exit(-7);
	}
#endif

	unsigned char *data_in = NULL;
	ssize_t size;
	if (!file_in) {
		outln(L_VERBOSE, "Reading from stdin");
		size = 0;
		while (!feof(stdin)) {
			size_t next_size = size + STDIN_BUFSIZE;
			data_in = realloc(data_in, next_size);
			size_t nr = fread(&data_in[size], 1, STDIN_BUFSIZE, stdin);
			if (nr != STDIN_BUFSIZE) {
				if (ferror(stdin) || !feof(stdin)) {
					outln_error("reading input");
					exit(-6);
				}
			}
			size += nr;
		}
		data_in = realloc(data_in, size);
	} else {
		outln(L_VERBOSE, "Reading from file %s", file_in);
		FILE *fin;
		if ((size = file_get_size(file_in)) < 0) {
			outln_errno(errno);
			exit(-2);
		}
		if (!(fin = fopen(file_in, "rb"))) {
			outln_errno(errno);
			exit(-3);
		}
		data_in = malloc(size + 1);
		if ((ssize_t)fread(data_in, 1, size, fin) != size) {
			outln_errno(errno);
			exit(-4);
		}
		fclose(fin);
	}
	outln(L_VERBOSE, "Parsing input of %li byte(s)", size);

		/* *VERY IMPORTANT* */
		/* WARNING
		 * This character is used to mark end of buffer in the case the input
		 * is PEM format. */
	data_in[size] = '\0';

	int data_in_is_pem = FALSE;
	unsigned char *data_out = NULL;
	size_t data_out_len = 0;
	if (!assume_der) {
		outln(L_VERBOSE, "Trying to parse input data against PEM rules");
		pem_ctrl_t *pem = pem_construct_pem_ctrl(data_in);
		pem_regcb_password(pem, cb_password_pre, cb_password_post);
		pem_regcb_loop_top(pem, cb_loop_top);
		pem_regcb_loop_decrypt(pem, cb_loop_decrypt);
		data_in_is_pem = pem_walker(pem, &data_out, &data_out_len);
		pem_destruct_pem_ctrl(pem);
	}

	const unsigned char *pkdata;
	size_t pkdata_len;
	if (assume_der || (!data_in_is_pem && !assume_pem)) {
		outln(L_VERBOSE, "Will use original data as pk input (assuming der-encoded content)");
		pkdata = data_in;
		pkdata_len = size;
	} else {
		outln(L_VERBOSE, "Will use pem decoded/decrypted data as pk input");
		pkdata = data_out;
		pkdata_len = data_out_len;
		if (!pkdata || data_out_len == 0) {
			outln_error("No PEM data available");
			exit(-8);
		}
	}

	pkctrl_t *ctrl = pkctrl_construct(pkdata, pkdata_len);

	FILE *fout;
	if (!file_out) {
		DBG("Output to stdout\n")
		fout = stdout;
	} else {
		DBG("Output to file %s\n", file_out)
		if (!(fout = fopen(file_out, "wb"))) {
			outln_errno(errno);
			exit(-5);
		}
	}

	if (opt_tree)
		print_tree(NULL, NULL, fout);

	seq_t *seq;
	for (seq = seq_next(ctrl); seq && seq->type != E_ERROR; seq = seq_next(ctrl)) {
		if (opt_tree) {
			print_tree(seq, pkctrl_head(ctrl), fout);
		} else {
			print_der(seq, fout);
		}
	}
	if (seq && seq->type == E_ERROR) {
		outln_error(seq->errmsg);
		seq_clear_error(seq);
	}

	pkctrl_destruct(ctrl);

	if (file_out)
		fclose(fout);

	if (data_out)
		free(data_out);
	if (data_in)
		free(data_in);

}

