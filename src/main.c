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

/*#define HAS_LIB_OPENSSL*/
/*#define VSAFE*/

#define PACKAGE_NAME "pkfile"
#define PACKAGE_STRING "pkfile 0.1"

#include <stdio.h>

#ifndef _MSC_VER
#include <unistd.h>
#endif

#include <assert.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <errno.h>
#include <ctype.h>

#ifdef HAS_LIB_OPENSSL
#include <openssl/objects.h>
#include "ppem.h"
#endif

#include "common.h"
#include "pkfile.h"

#if defined(_WIN32) || defined(_WIN64)
static const char *tree_strings[] = {
	"`-- ", /* T_NORTH_EAST */
	"    ", /* T_BLANK */
	"+-- ", /* T_NORTH_SOUTH_EAST */
	"|   ", /* T_NORTH_SOUTH */
	"",     /* T_EMPTY */
};
#else
static const char *tree_strings[] = {
	"└── ", /* T_NORTH_EAST */
	"    ", /* T_BLANK */
	"├── ", /* T_NORTH_SOUTH_EAST */
	"│   ", /* T_NORTH_SOUTH */
	"",     /* T_EMPTY */
};
#endif

	/*
	 * The der "SEQUENCE" or "SET OF" provide a hierarchical
	 * structure where we have a straightforward "level" notion
	 * (= number of hops to the chain head).
	 *
	 * A value of -1 means there is no limit.
	 * */
int opt_max_level = -1;
char *opt_file_in = NULL;
char *opt_file_out = NULL;

int out_level = L_NORMAL;

const char *opt_password = NULL;

const char *opt_inform = NULL;
int assume_pem = FALSE;
int assume_der = FALSE;

int opt_bin = FALSE;
char *opt_node = NULL;
char *opt_node_open = NULL;

int opt_print_offset = FALSE;

int opt_flat = FALSE;

typedef struct nodes_t nodes_t;
struct nodes_t {
	int index;
	nodes_t *child;
};

#define UNUSED(x) (void)(x)

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
	fprintf(stderr, "Display or extract sequences inside PKCS files.\n");
	fprintf(stderr, "This program will automatically detect whether PEM format\n");
	fprintf(stderr, "is being used, or DER, unless started with --inform.\n");
	fprintf(stderr, "  -h  --help           print this usage and exit\n");
	fprintf(stderr, "  -v  --version        print version information and exit\n");
	fprintf(stderr, "  -V  --verbose        verbose output\n");
	fprintf(stderr, "  -l  --level n        set max depth level to n (default: -1)\n");
	fprintf(stderr, "                       -1 = no maximum depth level\n");
	fprintf(stderr, "      --offset         print file offset before node numbers\n");
	fprintf(stderr, "      --flat           print data structure without hierarchical information\n");
	fprintf(stderr, "  -p  --password pwd   set password\n");
	fprintf(stderr, "  -x  --extract        output binary data\n");
	fprintf(stderr, "  -f  --inform format  set format. Either pem or der\n");
	fprintf(stderr, "  -n  --node NODE      output only node NODE. NODE name is a sequence of\n");
	fprintf(stderr, "                       integers separated by dots, like 1.3.1\n");
	fprintf(stderr, "  -N  --node-open NODE for a NODE of type BIT STRING or OCTET STRING, work\n");
	fprintf(stderr, "                       on NODE data assuming it is der-encoded.\n");
	fprintf(stderr, "  -o  --out            output to file\n");
	fprintf(stderr, "  --                   end of parameters, next option is file name\n");
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
	static int defined_options[11] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};

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
			opt_file_out = argv[a];
		} else if (!strcmp(argv[a], "--password") || !strcmp(argv_a_short, "-p")) {
			opt_check(3, argv[a]);
			OPT_WITH_VALUE_CHECK
			opt_password = argv[a];
		} else if (!strcmp(argv[a], "--inform") || !strcmp(argv_a_short, "-f")) {
			opt_check(4, argv[a]);
			OPT_WITH_VALUE_CHECK
			opt_inform = argv[a];
		} else if (!strcmp(argv[a], "--level") || !strcmp(argv_a_short, "-l")) {
			opt_check(5, argv[a]);
			OPT_WITH_VALUE_CHECK
			opt_max_level = atoi(argv[a]);
		} else if (!strcmp(argv[a], "--extract") || !strcmp(argv_a_short, "-x")) {
			opt_check(6, argv[a]);
			opt_bin = TRUE;
		} else if (!strcmp(argv[a], "--node") || !strcmp(argv_a_short, "-n")) {
			opt_check(7, argv[a]);
			OPT_WITH_VALUE_CHECK
			opt_node = argv[a];
		} else if (!strcmp(argv[a], "--offset")) {
			opt_check(8, argv[a]);
			opt_print_offset = TRUE;
		} else if (!strcmp(argv[a], "--node-open") || !strcmp(argv_a_short, "-N")) {
			opt_check(9, argv[a]);
			OPT_WITH_VALUE_CHECK
			opt_node_open = argv[a];
		} else if (!strcmp(argv[a], "--flat")) {
			opt_check(10, argv[a]);
			opt_flat = TRUE;
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
			if (!opt_file_in) {
				opt_file_in = argv[a];
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
	if ((a >= 1 && a < argc - 1) || (a >= 1 && a == argc - 1 && opt_file_in)) {
		fprintf(stderr, "%s: trailing options.\n", PACKAGE_NAME);
		a = -1;
	} else if (a >= 1 && a == argc - 1) {
		opt_file_in = argv[a];
	} else if (missing_option_value) {
		fprintf(stderr, "%s: option '%s' requires one argument\n", PACKAGE_NAME, missing_option_value);
	}
	if (opt_inform) {
		if (!strcmp(opt_inform, "PEM") || !strcmp(opt_inform, "pem")) {
			assume_pem = TRUE;

#ifndef HAS_LIB_OPENSSL
			fprintf(stderr, "%s: this version does not support PEM format\n", PACKAGE_NAME);
			exit(-9);
#endif

		} else if (!strcmp(opt_inform, "DER") || !strcmp(opt_inform, "der")) {
			assume_der = TRUE;
		} else {
			fprintf(stderr, "%s: unknown input format, allowed values are pem and der\n", PACKAGE_NAME);
			a = -1;
		}
	}

	if (a < 0)
		usage();

#ifndef HAS_LIB_OPENSSL
	assume_der = TRUE;
#endif

	if (optset_debug)
		out_level = L_DEBUG;
}

#ifdef HAS_LIB_OPENSSL

char *cb_password_pre()
{
/* FIXME */
#define PASSWORD_MAX_BYTES 200

	char *password;

	if (!opt_password) {
		fprintf(stderr, "Please type in the password:\n");
		char *readpwd = malloc(PASSWORD_MAX_BYTES);
		if (!fgets(readpwd, PASSWORD_MAX_BYTES, stdin)) {
			free(readpwd);
			return NULL;
		}
		readpwd[PASSWORD_MAX_BYTES - 1] = '\0';
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

void print_hexa(int level, const unsigned char *buf, int buf_len) {
	int i; for (i = 0; i < buf_len; ++i) out(level, "%02X", (unsigned char)buf[i]);
}

void cb_loop_top(const pem_ctrl_t *ctrl)
{
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

#endif /* #ifdef HAS_LIB_OPENSSL */

int decode_oid(char *p, const size_t plen, const char *buf, const size_t buflen)
{
	char tmp[20];
	int pos = 0;
	while ((unsigned)pos < buflen) {
		int old_pos = pos;
		for (; (buf[pos] & 0x80) && (unsigned)pos < buflen; ++pos)
			;
		if ((unsigned)pos >= buflen) {
			return 0;
		}
		int rev;
		long unsigned multi = 1;
		int shift = 0;
		unsigned rmask;
		unsigned lmask;
		unsigned bm1;
		unsigned v0;
		long unsigned value = 0;
		for (rev = pos; rev >= old_pos; --rev) {
			if (rev == old_pos)
				bm1 = 0;
			else
				bm1 = (unsigned)buf[rev - 1];
			rmask = (0x7Fu >> shift);
			lmask = (0xFFu << (7 - shift)) & 0xFFu;
			v0 = (long unsigned)(((bm1 << (7 - shift)) & lmask) | (((unsigned)buf[rev] >> shift) & rmask));

			value += v0 * multi;
			multi *= 256;   /* Can be written <<8, but... */
			++shift;
		}

		if (!old_pos) {
			int x = (int)value / 40;
			if (x > 2)
				x = 2;
			int y = (int)value - 40 * x;
			snprintf(p, plen, "%i.%i", x, y);
		} else {
			snprintf(tmp, sizeof(tmp), ".%lu", value);
			s_strncat(p, tmp, plen);
		}
		++pos;
	}
	return 1;
}

void print_oid(const char *header, ssize_t header_len, const char *data, ssize_t data_len, FILE *fout)
{
/* FIXME */
#define STR_OID_MAX_SIZE 200
	char str_oid[STR_OID_MAX_SIZE];

#ifdef HAS_LIB_OPENSSL
	unsigned char *tmp = malloc(header_len + data_len);
	memcpy(tmp, header, header_len);
	memcpy(tmp + header_len, data, data_len);
	ASN1_OBJECT *oid = NULL;
	const unsigned char *tt = tmp;
	const char *sn = "";
	if (d2i_ASN1_OBJECT(&oid, &tt, header_len + data_len) != NULL) {
		const char *soid;
		soid = OBJ_nid2sn(OBJ_obj2nid(oid));
		sn = (const char *)soid;
		ASN1_OBJECT_free(oid);
	}
	free(tmp);
#endif

	if (!decode_oid(str_oid, sizeof(str_oid), data, data_len)) {
		fprintf(fout, "bad OID");
	} else {
#ifdef HAS_LIB_OPENSSL
		fprintf(fout, "%s (%s)", str_oid, sn);
#else
		fprintf(fout, "%s", str_oid);
#endif
	}
}

void node2str(char *buf, size_t buf_len, const seq_t *seq_head, int is_data)
{
	buf[0] = '\0';
	char buf2[10];
	const seq_t *s;
	int n = 0;
	for (s = seq_head; s && (is_data || s->child); s = s->child) {
		assert(n++ == s->level);

		if (n == 1) {
			snprintf(buf2, sizeof(buf2), "%d", s->index);
		} else {
			snprintf(buf2, sizeof(buf2), ".%d", s->index);
		}
		s_strncat(buf, buf2, buf_len);
	}
}

void print_tree(const seq_t *seq, const seq_t *seq_head, FILE *fout, int terminal, int *callctrl)
{
/* FIXME */
#define NODES_STR_MAX_LEN 100

	if (opt_max_level >= 0 && seq->level > opt_max_level) return;

	if (!terminal) {
		if (!*callctrl) {
			if (!opt_flat) {
				if (opt_print_offset)
					fprintf(fout, "%6s  ", "");
				fprintf(fout, "%17s.\n", "");
			}
			*callctrl = TRUE;
		}

		if (opt_print_offset)
			fprintf(fout, "%06X  ", (unsigned int)seq->offset);

		char buf1[NODES_STR_MAX_LEN];
		node2str(buf1, sizeof(buf1), seq_head, FALSE);
		if (!opt_flat)
			fprintf(fout, "%-15s  ", buf1);
		else
			fprintf(fout, "%s: ", buf1);

		if (!opt_flat) {
			const seq_t *s;
			for (s = seq_head; s; s = s->child) {
				assert(s->tree >= 0 && s->tree < sizeof(tree_strings) / sizeof(*tree_strings));
				fputs(tree_strings[s->tree], fout);
			}
		}

		fprintf(fout, "%s: %s, len: %li",
			seq->tag_type_str, seq->tag_name, seq->total_len);
		if (seq->type == E_DATA && seq_has_bit_string(seq))
			fprintf(fout, " (%li+1+%li)\n", seq->header_len, seq->data_len - 1);
		else if (seq->tag_indefinite)
			fprintf(fout, " (indefinite)\n");
		else
			fprintf(fout, " (%li+%li)\n", seq->header_len, seq->data_len);
	}

	if (seq->type == E_DATA) {
		int i;
		int period1 = 0;
		int period2 = 0;
		int is_string = seq_has_string_data(seq);
		int is_oid = seq_has_oid(seq);
		int is_integer = seq_has_integer(seq);
		int is_bit_string = seq_has_bit_string(seq);
		int loop_once = FALSE;
		int shift1 = (is_bit_string ? 1 : 0);
		if (is_oid)
			loop_once = TRUE;
		if (is_string) {
			period1 = (opt_flat ? 76 : 38);
			period2 = 0;
		} else if (is_integer) {
			period1 = (opt_flat ? 0 : 19);
			period2 = 0;
		} else {
			period1 = (opt_flat ? 32 : 16);
			period2 = 4;
		}
		int has_looped_at_least_once = FALSE;
		for (i = 0; loop_once || i < seq->data_len - shift1; ++i) {
			if (!has_looped_at_least_once) {
				char bf1[NODES_STR_MAX_LEN];
				node2str(bf1, sizeof(bf1), seq_head, TRUE);
				if (opt_print_offset)
					fprintf(fout, "%6s  ", "");
				if (!opt_flat)
					fprintf(fout, "%-15s  ", bf1);
				else
					fprintf(fout, "%s: ", bf1);
			} else if (loop_once || (period1 && !(i % period1))) {
					if (!opt_flat) {
						if (opt_print_offset)
							fprintf(fout, "%6s  ", "");
						fprintf(fout, "%15s  ", "");
					}
			}
			if (loop_once || (period1 && !(i % period1))) {
				if (!opt_flat) {
					const seq_t *s;
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
			}
			has_looped_at_least_once = TRUE;

			unsigned char c = seq->data[i + shift1];
			if (is_string) {
				if (c < 32 || c == 127)
					c = '.';
				fprintf(fout, "%c", (char)c);
			} else if (!loop_once) {
				fprintf(fout, "%02X", c);
			} else if (is_oid) {
				print_oid(seq->header, seq->header_len, seq->data, seq->data_len, fout);
			} else
				FATAL_ERROR("%s", "Hey man, tu fais quoi ?");

			if (period1 && !((i + 1) % period1) && i + 1 < seq->data_len)
				fprintf(fout, "\n");
			else if (period2 && !((i + 1) % period2))
				fprintf(fout, "  ");

			if (loop_once)
				break;
		}
		if (has_looped_at_least_once)
			fputs("\n", fout);
	}
}

void write_der(const seq_t *seq, FILE *fout, int terminal)
{
	DBG("write_der() enter\n")
	if (!seq)
		return;

	int i;
	int shift1 = (terminal && seq_has_bit_string(seq) ? 1 : 0);
	for (i = (terminal ? seq->header_len : 0); i < seq->header_len + (seq->data ? seq->data_len : 0) - shift1; ++i) {
		char c = '\0';
		if (i < seq->header_len)
			c = seq->header[i];
		else if (seq->data)
			c = seq->data[i - seq->header_len + shift1];
		else
			FATAL_ERROR("Stop");
		fputc(c, fout);
	}
	DBG("write_der() leave\n")
}

void destruct_nodes(nodes_t *nodes)
{
	while (nodes) {
		nodes_t *next = nodes->child;
		free(nodes);
		nodes = next;
	}
}

nodes_t *parse_opt_node(const char *sarg)
{
	nodes_t *nhead = NULL;
	nodes_t *ntail = NULL;

	char *scopy = s_alloc_and_copy(NULL, sarg);

		/*
		 * Trim spaces from beginning and end of string.
		 * I should create a function for that, yes...
		 *
		 * */
	char *s = scopy;
	while (isblank(*s))
		++s;
	char *e = s + strlen(s) - 1;
	while (e > s && isblank(*e))
		--e;
	*(e + 1) = '\0';

	DBG("Nodes string: '%s'\n", s)

	char *p = s;
	char *pstart = p;
	int all_good = FALSE;
	while (TRUE) {
		if (isdigit(*p))
			++p;
		else if (*p == '.' || *p == '\0') {
			if (*p != '\0') {
				*p = '\0';
				++p;
			}

			int n = atoi(pstart);
			if (n <= 0)
				goto parse_opt_node_error;

			pstart = p;

			nodes_t *nnew = malloc(sizeof(nodes_t));
			nnew->index = n;
			DBG("Node: %d\n", n)
			if (!nhead) {
				assert(!ntail);
				nnew->child = NULL;
				nhead = nnew;
			} else {
				ntail->child = nnew;
			}
			ntail = nnew;

			if (*p == '\0')
				break;

		} else {
			goto parse_opt_node_error;
		}
	}
	all_good = TRUE;

parse_opt_node_error:
	if (!all_good) {
		destruct_nodes(nhead);
		nhead = NULL;
	}
	free(scopy);
	return nhead;
}

int manage_pkdata(const unsigned char *pkdata, size_t pkdata_len, const nodes_t *nodes, int analyze_embedded_data, FILE *fout)
{
	DBG("manage_pkdata() start\n")
	pkctrl_t *ctrl = pkctrl_construct(pkdata, pkdata_len);

	int matched_at_least_once = FALSE;
	seq_t *seq;
	int callctrl = FALSE;
	int r = 1;
	for (seq = seq_next(ctrl); seq && seq->type != E_ERROR; seq = seq_next(ctrl)) {

		const nodes_t *nd = nodes;
		int is_in_nodes_path = TRUE;
		seq_t *s;
		for (s = pkctrl_head(ctrl); s && nd; s = s->child) {
			if (nd->index != s->index)
				is_in_nodes_path = FALSE;
			nd = nd->child;
		}
		if (!is_in_nodes_path || nd)
			continue;

		matched_at_least_once = TRUE;

		if (analyze_embedded_data) {
			if (s) {
				outln_error("Bad node type, should be of type prim: BIT STRING or OCTET STRING");
				r = 0;
				break;
			} else if (seq->type != E_DATA || (!seq_has_bit_string(seq) && !seq_has_octet_string(seq))) {
				outln_error("Bad node type, should be of type prim: BIT STRING or OCTET STRING");
				r = 0;
				break;
			} else {
				int shift1 = (seq_has_bit_string(seq) ? 1 : 0);
				r = manage_pkdata((const unsigned char *)seq->data + shift1, seq->data_len - shift1, NULL, FALSE, fout);
			}
		} else {
			if (!opt_bin) {
				print_tree(seq, pkctrl_head(ctrl), fout, !s, &callctrl);
			} else {
				write_der(seq, fout, !s);
			}
		}
	}
	if (r == 1) {
		if (seq && seq->type == E_ERROR) {
			outln_error(seq->errmsg);
			seq_clear_error(seq);
			r = 0;
		} else if (!matched_at_least_once) {
			outln_error("Non-existent node");
			r = 0;
		}
	}

	pkctrl_destruct(ctrl, r != 1);

	DBG("manage_pkdata() end\n")

	return r;
}

int main(int argc, char **argv)
{
const size_t STDIN_BUFSIZE = 1024;

	unsigned char *data_in = NULL;
	unsigned char *data_out = NULL;
	nodes_t *nodes = NULL;
	FILE *fout = NULL;
	int retval = -999;

	parse_options(argc, argv);

	if (opt_node && opt_node_open) {
		outln_error("Only one of -n and -N can be used at a time");
		usage();
	}
	char *opt_n = (opt_node ? opt_node : opt_node_open);
	int analyze_embedded_data = (opt_node_open != NULL);
	if (opt_n) {
		if (!(nodes = parse_opt_node(opt_n))) {
			outln_error("bad nodes list");
			usage();
		}
	}
	if (opt_bin && opt_print_offset) {
		outln_error("--offset cannot be used with option -b");
		usage();
	}

	ssize_t size;
	if (!opt_file_in) {
		outln(L_VERBOSE, "Reading from stdin");
		size = 0;
		while (!feof(stdin)) {
			size_t next_size = size + STDIN_BUFSIZE;
			data_in = realloc(data_in, next_size);
			size_t nr = fread(&data_in[size], 1, STDIN_BUFSIZE, stdin);
			if (nr != STDIN_BUFSIZE) {
				if (ferror(stdin) || !feof(stdin)) {
					outln_error("reading input");
					goto main_error;
				}
			}
			size += nr;
		}
		data_in = realloc(data_in, size);
	} else {
		outln(L_VERBOSE, "Reading from file %s", opt_file_in);
		FILE *fin;
		if ((size = file_get_size(opt_file_in)) < 0) {
			outln_errno(errno);
			goto main_error;
		}
		if (!(fin = fopen(opt_file_in, "rb"))) {
			outln_errno(errno);
			goto main_error;
		}
		data_in = malloc(size + 1);
		if ((ssize_t)fread(data_in, 1, size, fin) != size) {
			outln_errno(errno);
			goto main_error;
		}
		fclose(fin);
	}
	outln(L_VERBOSE, "Parsing input of %li byte(s)", size);

	if (data_in) {
			/* *VERY IMPORTANT* */
			/* WARNING
			 * This character is used to mark end of buffer in the case the input
			 * is PEM format. */
		data_in[size] = '\0';
	}

	int data_in_is_pem = FALSE;
	size_t data_out_len = 0;

#ifdef HAS_LIB_OPENSSL
	if (!assume_der) {
		outln(L_VERBOSE, "Trying to parse input data against PEM rules");
		pem_ctrl_t *pem = pem_construct_pem_ctrl(data_in);
		pem_regcb_password(pem, cb_password_pre, cb_password_post);
		pem_regcb_loop_top(pem, cb_loop_top);
		pem_regcb_loop_decrypt(pem, cb_loop_decrypt);
		data_in_is_pem = pem_walker(pem, &data_out, &data_out_len);
		pem_destruct_pem_ctrl(pem);
	}
#endif

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
			goto main_error;
		}
	}

	if (!opt_file_out) {
		DBG("Output to stdout\n")
		fout = stdout;
	} else {
		DBG("Output to file %s\n", opt_file_out)
		if (!(fout = fopen(opt_file_out, "wb"))) {
			outln_errno(errno);
			goto main_error;
		}
	}

	retval = (manage_pkdata(pkdata, pkdata_len, nodes, analyze_embedded_data, fout) == 1 ? 0 : -999);

main_error:

	if (opt_file_out && fout)
		fclose(fout);

	if (data_out)
		free(data_out);
	if (data_in)
		free(data_in);

	destruct_nodes(nodes);

	return retval;
}

