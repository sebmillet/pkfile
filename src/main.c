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

#ifdef HAVE_CONFIG_H
#include "config.h"
#else
#include "..\extracfg.h"
#endif

#define ENV_CHARSET "PKFILE_CHARSET"

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

#if defined(_WIN32) || defined(_WIN64)
#include <windows.h>
#else
#include <termios.h>
#include <langinfo.h>
#endif

#include <locale.h>

#ifdef HAS_LIB_OPENSSL
#include <openssl/objects.h>
#include <openssl/sha.h>
#include "ppem.h"
#endif

#include "common.h"
#include "pkfile.h"

	/* Enumerated with tree_t constants, defined in pkfile.h */
static const char *tree_strings[5];

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
const char *opt_charset = NULL;
int opt_flat = FALSE;

#define H_UNDEF  0
#define H_SHA1   1
#define H_SHA256 2
#define H_SHA512 3
int opt_hash_algo = H_UNDEF;

typedef struct nodes_t nodes_t;
struct nodes_t {
	int index;
	nodes_t *child;
};

#define PASSWORD_MAX_BYTES 200
#define STR_OID_MAX_SIZE 200
#define NODES_STR_MAX_LEN 100

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

int my_stricmp(const char *a, const char *b)
{
#if defined(_WIN32) || defined(_WIN64)
	return _stricmp(a, b);
#else
	return strcasecmp(a, b);
#endif
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
	fprintf(stderr, "Display or extract sequences inside PKCS files.\n"
		"This program will automatically detect whether PEM format\n"
		"is being used, or DER, unless started with --inform.\n"
		"  -h  --help           print this usage and exit\n"
		"  -v  --version        print version information and exit\n"
		"  -V  --verbose        verbose output\n"
		"  -l  --level n        set max depth level to n (default: -1)\n"
		"                       -1 = no maximum depth level\n"
		"      --offset         print file offset before node numbers\n"
		"      --flat           print data structure without hierarchical information\n"
		"  -p  --password pwd   set password to 'pwd' when source is encrypted PEM\n"
		"  -x  --extract        output binary data\n"
		"  -f  --inform format  set format. Either pem or der\n"
		"  -n  --node NODE      output only node NODE. NODE name is a sequence of\n"
		"                       integers separated by dots, like 1.3.1\n"
		"  -N  --node-open NODE for a NODE of type BIT STRING or OCTET STRING, work\n"
		"                       on NODE data assuming it is der-encoded.\n"
		"  -o  --out            output to file\n"
		"      --charset X      use 'X' as charset for tree-like display\n"
		"      --sha1           calculate sha1 hash of input\n"
		"      --sha256         calculate sha256 hash of input\n"
		"      --sha512         calculate sha512 hash of input\n"
		"  --                   end of parameters, next option is file name\n"
		"If FILE is not specified, read standard input.\n"
	);
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

#ifdef HAS_LIB_OPENSSL

char *cb_password_pre()
{
	char *password;

	if (!opt_password) {

#if defined(_WIN32) || defined(_WIN64)
		HANDLE h;
		DWORD console_mode;
		h = GetStdHandle(STD_INPUT_HANDLE);
		if (!GetConsoleMode(h, &console_mode))
			return NULL;
		if (!SetConsoleMode(h, console_mode & ~ENABLE_ECHO_INPUT))
			return NULL;
#else
		struct termios current, new;
		if (tcgetattr(fileno(stdin), &current) != 0)
			return NULL;
		new = current;
		new.c_lflag &= ~ECHO;
		if (tcsetattr(fileno(stdin), TCSAFLUSH, &new) != 0)
			return NULL;
#endif

		printf("Please type in the password:\n");
		char *readpwd = malloc(PASSWORD_MAX_BYTES);
		char *r = fgets(readpwd, PASSWORD_MAX_BYTES, stdin);

#if defined(_WIN32) || defined(_WIN64)
		SetConsoleMode(h, console_mode);
#else
		tcsetattr(fileno(stdin), TCSAFLUSH, &current);
#endif

		if (!r) {
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
			seq->tag_type_str, seq->tag_name, (long int)seq->total_len);
		if (seq->type == E_DATA && seq_has_bit_string(seq))
			fprintf(fout, " (%li+1+%li)\n", (long int)seq->header_len, (long int)seq->data_len - 1);
		else if (seq->tag_indefinite)
			fprintf(fout, " (indefinite)\n");
		else
			fprintf(fout, " (%li+%li)\n", (long int)seq->header_len, (long int)seq->data_len);
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
		} else if (!matched_at_least_once && nodes) {
			outln_error("Non-existent node");
			r = 0;
		}
	}

	pkctrl_destruct(ctrl, r != 1);

	DBG("manage_pkdata() end\n")

	return r;
}

/*
 * Inspired from tree source.
 * tree source was version 1.7.0.
 * It is tree source inspiration until the second 40 x '=' comment marker
 */
/* ======================================== */

#if defined(_WIN32) || defined(_WIN64)

/*
 * Charsets provided by Kyosuke Tokoro (NBG01720@nifty.ne.jp)
 */
void windows_getcharset(char *s, int s_len)
{
	ULONG codepage = GetConsoleOutputCP();

	DBG("codepage according to GetConsoleOutputCP(): %d\n", codepage)

	switch (codepage) {
		case 437: case 775: case 850: case 851: case 852: case 855:
		case 857: case 860: case 861: case 862: case 863: case 864:
		case 865: case 866: case 868: case 869: case 891: case 903:
		case 904:
			snprintf(s, s_len, "IBM%03lu", codepage);
			break;
		case 367:
			s_strncpy(s, "US-ASCII", s_len);
			break;
		case 813:
			s_strncpy(s, "ISO-8859-7", s_len);
			break;
		case 819:
			s_strncpy(s, "ISO-8859-1", s_len);
			break;
		case 881: case 882: case 883: case 884: case 885:
			snprintf(s, s_len, "ISO-8859-%lu", codepage - 880);
			break;
		case 858: case 924:
			snprintf(s, s_len, "IBM%05lu", codepage);
			break;
		case 874:
			s_strncpy(s, "TIS-620", s_len);
			break;
		case 897: case 932: case 942: case 943:
			s_strncpy(s, "Shift_JIS", s_len);
			break;
		case 912:
			s_strncpy(s, "ISO-8859-2", s_len);
			break;
		case 915:
			s_strncpy(s, "ISO-8859-5", s_len);
			break;
		case 916:
			s_strncpy(s, "ISO-8859-8", s_len);
			break;
		case 949: case 970:
			s_strncpy(s, "EUC-KR", s_len);
			break;
		case 950:
			s_strncpy(s, "Big5", s_len);
			break;
		case 954:
			s_strncpy(s, "EUC-JP", s_len);
			break;
		case 1051:
			s_strncpy(s, "hp-roman8", s_len);
			break;
		case 1089:
			s_strncpy(s, "ISO-8859-6", s_len);
			break;
		case 1250: case 1251: case 1253: case 1254: case 1255: case 1256:
		case 1257: case 1258:
			snprintf(s, s_len, "windows-%lu", codepage);
			break;
		case 1252:
			s_strncpy(s, "ISO-8859-1-Windows-3.1-Latin-1", s_len);
			break;
		default:
			s_strncpy(s, "", s_len);
	}
}

#endif /* defined(_WIN32) || defined(_WIN64) */

	/* This declaration is taken from tree.h */
struct linedraw {
  const char **name, *vert, *vert_left, *corner;
};

const struct linedraw *initlinedraw(const char *charset, int flag)
{
	static const char *latin1_3[] = {
		"ISO-8859-1", "ISO-8859-1:1987", "ISO_8859-1", "latin1", "l1", "IBM819",
		"CP819", "csISOLatin1", "ISO-8859-3", "ISO_8859-3:1988", "ISO_8859-3",
		"latin3", "ls", "csISOLatin3", NULL
	};

	static const char *iso8859_789[] = {
		"ISO-8859-7", "ISO_8859-7:1987", "ISO_8859-7", "ELOT_928", "ECMA-118",
		"greek", "greek8", "csISOLatinGreek", "ISO-8859-8", "ISO_8859-8:1988",
		"iso-ir-138", "ISO_8859-8", "hebrew", "csISOLatinHebrew", "ISO-8859-9",
		"ISO_8859-9:1989", "iso-ir-148", "ISO_8859-9", "latin5", "l5",
		"csISOLatin5", NULL
	};

	static const char *shift_jis[] = {
		"Shift_JIS", "MS_Kanji", "csShiftJIS", NULL
	};

	static const char *euc_jp[] = {
		"EUC-JP", "Extended_UNIX_Code_Packed_Format_for_Japanese",
		"csEUCPkdFmtJapanese", NULL
	};

	static const char *euc_kr[] = {
		"EUC-KR", "csEUCKR", NULL
	};

	static const char *iso2022jp[] = {
		"ISO-2022-JP", "csISO2022JP", "ISO-2022-JP-2", "csISO2022JP2", NULL
	};

	static const char *ibm_pc[] = {
		"IBM437", "cp437", "437", "csPC8CodePage437", "IBM852", "cp852", "852",
		"csPCp852", "IBM863", "cp863", "863", "csIBM863", "IBM855", "cp855",
		"855", "csIBM855", "IBM865", "cp865", "865", "csIBM865", "IBM866",
		"cp866", "866", "csIBM866", NULL
	};

	static const char *ibm_ps2[] = {
		"IBM850", "cp850", "850", "csPC850Multilingual", "IBM00858", "CCSID00858",
		"CP00858", "PC-Multilingual-850+euro", NULL
	};

	static const char *ibm_gr[] = {
		"IBM869", "cp869", "869", "cp-gr", "csIBM869", NULL
	};

	static const char *gb[] = {
		"GB2312", "csGB2312", NULL
	};

	static const char *utf8[] = {
		"UTF-8", "utf8", NULL
	};

	static const char *big5[] = {
		"Big5", "csBig5", NULL
	};

	static const char *viscii[] = {
		"VISCII", "csVISCII", NULL
	};

	static const char *koi8ru[] = {
		"KOI8-R", "csKOI8R", "KOI8-U", NULL
	};

	static const char *windows[] = {
		"ISO-8859-1-Windows-3.1-Latin-1", "csWindows31Latin1",
		"ISO-8859-2-Windows-Latin-2", "csWindows31Latin2", "windows-1250",
		"windows-1251", "windows-1253", "windows-1254", "windows-1255",
		"windows-1256", "windows-1256", "windows-1257", NULL
	};

	static const struct linedraw cstable[]={
		{latin1_3,    "|   ",              "|-- ",            "`-- "    },
		{iso8859_789, "|   ",              "|-- ",            "`-- "    },
		{shift_jis,   "\204\240  ",        "\204\245 ",       "\204\244 ",     },
		{euc_jp,      "\250\242  ",        "\250\247 ",       "\250\246 ",     },
		{euc_kr,      "\246\242  ",        "\246\247 ",       "\246\246 ",     },
		{iso2022jp,   "\033$B(\"\033(B  ", "\033$B('\033(B ", "\033$B(&\033(B "},
		{ibm_pc,      "\263   ",           "\303\304\304 ",   "\300\304\304 "  },
		/*{ibm_ps2,     "\263   ",           "\303\304\304 ",   "\300\304\304 "  },*/
		{ibm_ps2,     "\xB3   ",           "\xC3\xC4\xC4 ",   "\xC0\xC4\xC4 "  },
		{ibm_gr,      "\263   ",           "\303\304\304 ",   "\300\304\304 "  },
		{gb,          "\251\246  ",        "\251\300 ",       "\251\270 "      },
		{utf8,        "\342\224\202   ",
		"\342\224\234\342\224\200\342\224\200 ", "\342\224\224\342\224\200\342\224\200 "},
		{big5,        "\242x  ",           "\242u ",          "\242| "         },
		{viscii,      "|   ",              "|-- ",            "`-- "           },
		{koi8ru,      "\201   ",           "\206\200\200 ",   "\204\200\200 "  },
		{windows,     "|   ",              "|-- ",            "`-- "           },
		{NULL,        "|   ",              "|-- ",            "`-- "           }
	};

	const struct linedraw *linedraw;
	const char**s;
	if (flag) {
		fprintf(stderr,"Valid charsets include:\n");
		for (linedraw = cstable; linedraw->name; ++linedraw)
			for (s = linedraw->name; *s; ++s)
				fprintf(stderr,"  %s\n", *s);
		return NULL;
	}

	if (charset) {
		int i = 0;
		for (linedraw = cstable; linedraw->name; ++linedraw) {
			for (s = linedraw->name; *s; ++s) {
				if (!my_stricmp(charset, *s)) {
					DBG("found charset in cstable[], index %d, name %s\n", i, linedraw->name[0])
					return linedraw;
				}
			}
			++i;
		}
	}
	DBG("charset not found in cstable[], returning default\n")
	return cstable + sizeof(cstable) / sizeof(*cstable)-1;
}

/* ======================================== */
/*
 * End of tree source take away...
 */


#ifdef HAS_LIB_OPENSSL
void hash(unsigned char *data_in, ssize_t size, int hash_algo, FILE *fout)
{
	unsigned char *(*func)(const unsigned char *d, size_t n, unsigned char *md) = NULL;
	int bytes;

	DBG("Calculating hash of %lu byte(s)\n", size)

	switch (hash_algo) {
		case H_SHA1:
			func = SHA1;
			bytes = SHA_DIGEST_LENGTH;
			DBG("Hash algo: SHA1\n")
			break;
		case H_SHA256:
			func = SHA256;
			bytes = SHA256_DIGEST_LENGTH;
			DBG("Hash algo: SHA256\n")
			break;
		case H_SHA512:
			func = SHA512;
			bytes = SHA512_DIGEST_LENGTH;
			DBG("Hash algo: SHA512\n")
			break;
		default:
			FATAL_ERROR("Unknown hash algo: %d", hash_algo);
	}

	unsigned char *h = (unsigned char *)malloc(bytes);
	func(data_in, size, h);
	int i;
	for (i = 0; i < bytes; ++i) {
		fprintf(fout, "%02x", (unsigned char)h[i]);
	}
	fprintf(fout, "\n");
	free(h);
}
#endif

static void opt_check(unsigned int n, const char *opt)
{
	static int defined_options[13] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};

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
	missing_option = argv_a_short + 1; \
	a = -1; \
	break; \
} \
if (++a >= argc) { \
	missing_option = argv[a - 1] + 2; \
	a = -1; \
	break; \
}

	int optset_debug = FALSE;

	char *missing_option = NULL;

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
		} else if (!strcmp(argv[a], "--charset")) {
			opt_check(11, argv[a]);
			OPT_WITH_VALUE_CHECK
			opt_charset = argv[a];
		} else if (!strcmp(argv[a], "--sha1")) {
			opt_check(12, argv[a]);
			opt_hash_algo = H_SHA1;
		} else if (!strcmp(argv[a], "--sha256")) {
			opt_check(12, argv[a]);
			opt_hash_algo = H_SHA256;
		} else if (!strcmp(argv[a], "--sha512")) {
			opt_check(12, argv[a]);
			opt_hash_algo = H_SHA512;
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
	} else if (missing_option) {
		fprintf(stderr, "%s: option '%s' requires one argument\n", PACKAGE_NAME, missing_option);
		if (!strcmp(missing_option, "charset")) {
			initlinedraw(NULL, 1);
			exit(1);
		}
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
	if (a >= 0 && opt_hash_algo != H_UNDEF) {
#ifndef HAS_LIB_OPENSSL
		fprintf(stderr, "%s: this version does not support calculating hashes\n", PACKAGE_NAME);
		exit(-10);
#endif
		if (opt_bin) {
			fprintf(stderr, "%s: option -x not compatible with a hash option\n", PACKAGE_NAME);
			a = -1;
		} else if (opt_node) {
			fprintf(stderr, "%s: option -n not compatible with a hash option\n", PACKAGE_NAME);
			a = -1;
		} else if (opt_node_open) {
			fprintf(stderr, "%s: option -N not compatible with a hash option\n", PACKAGE_NAME);
			a = -1;
		} else if (opt_inform) {
			fprintf(stderr, "%s: option -f not compatible with a hash option\n", PACKAGE_NAME);
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

	const char *charset = NULL;
	char buf[100];
	const char *env;

	if (opt_charset) {
		DBG("charset defined in command-line options\n")
		charset = opt_charset;
	}
	if (!charset) {
		env = getenv(ENV_CHARSET);
		if (env) {
			DBG("charset defined in environment variable %s\n", ENV_CHARSET)
			s_strncpy(buf, env, sizeof(buf));
			if (buf[strlen(buf) - 1] == '"')
				buf[strlen(buf) - 1] = '\0';
			charset = buf;
			if (charset[0] == '"')
				++charset;
		}
	}

#if defined(_WIN32) || defined(_WIN64)
	if (!charset) {
		windows_getcharset(buf, sizeof(buf));
		if (strlen(buf)) {
			DBG("charset found with windows_getcharset() function\n", ENV_CHARSET)
			charset = buf;
		}
	}
#else
	setlocale(LC_ALL, "");
	setlocale(LC_COLLATE, "");
	if (!charset && !my_stricmp(nl_langinfo(CODESET), "UTF-8")) {
		DBG("charset UTF-8 found by calling nl_langindo\n", ENV_CHARSET)
		charset = "UTF-8";
	}
#endif

	DBG("charset = %s\n", charset)

	const struct linedraw *linedraw = initlinedraw(charset, 0);
	tree_strings[T_NORTH_EAST] = linedraw->corner;
	tree_strings[T_BLANK] = "    ";
	tree_strings[T_NORTH_SOUTH_EAST] = linedraw->vert;
	tree_strings[T_NORTH_SOUTH_EAST] = linedraw->vert_left;
	tree_strings[T_NORTH_SOUTH] = linedraw->vert;
	tree_strings[T_EMPTY] = "";

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

	const unsigned char *pkdata = NULL;
	size_t pkdata_len = 0;
	if (opt_hash_algo == H_UNDEF) {
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

	if (opt_hash_algo == H_UNDEF) {
		retval = (manage_pkdata(pkdata, pkdata_len, nodes, analyze_embedded_data, fout) == 1 ? 0 : -999);
	} else {
#ifdef HAS_LIB_OPENSSL
		hash(data_in, size, opt_hash_algo, fout);
#else
		FATAL_ERROR("Serious error");
#endif
	}

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

