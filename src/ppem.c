/*
 * =====================================================================================
 *
 *       Filename:  ppem.c
 *
 *    Description:  Parse a PEM file
 *
 *        Version:  1.0
 *        Created:  28/12/2015 13:52:33
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  Sébastien Millet (smt), milletseb@laposte.net
 *
 * =====================================================================================
 */

/*#define PPEM_DEBUG*/

#include "ppem.h"

#include <assert.h>

#include <ctype.h>
#include <string.h>

#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/conf.h>
#include <openssl/err.h>

#define SALT_MINIMUM_BYTES 8

static void reset_round(pem_ctrl_t *ctrl);
static int pem_base64_estimate_decoded_data_len(const unsigned char* b64msg, size_t b64msg_len);
static int pem_base64_decode(const unsigned char *b64msg, size_t b64msg_len, unsigned char **binbuf, size_t *binbuf_len);

#define UNUSED(x) (void)(x)

#ifdef PPEM_DEBUG
#define DBG(...) \
{\
	fprintf(stderr, "%s[%d]\t", __FILE__, __LINE__); \
	fprintf(stderr, __VA_ARGS__); \
	fprintf(stderr, "\n"); \
}
#else
#define DBG(...)
#endif

static const char *errorstrings[] = {
	"no PEM information",                  /* PEM_NO_PEM_INFORMATION */
	"PEM parsing error",                   /* PEM_PARSE_ERROR */
	"unmanaged PEM format",                /* PEM_UNMANAGED_PROC_TYPE */
	"missing encryption information"    ,  /* PEM_MISSING_ENCRYPTION_INFORMATION */
	"non standard encryption information", /* PEM_MISSING_EMPTY_LINE_AFTER_ENCRYPTION_INFO */
	"incorrect salt",                      /* PEM_INCORRECT_SALT */
	"empty data",                          /* PEM_EMPTY_DATA */
	"bad base64 content",                  /* PEM_BAD_BASE64_CONTENT */
	"encrypted data",                      /* PEM_ENCRYPTED_DATA */
	"clear data"                           /* PEM_CLEAR_DATA */
};

struct pem_ctrl_t {
		/* Fields remanent across calls to pem_next() */
	int index;
	const unsigned char *data_current;
		/* cb = call back */
	char *(*cb_password_pre)();
	void (*cb_password_post)(char *password);
	void (*cb_loop_top)(const pem_ctrl_t *ctrl);
	void (*cb_loop_decrypt)(int decrypt_ok, const char *errmsg);
	void (*cb_loop_bottom)(const unsigned char *data_src, size_t data_src_len);

		/* Fields reset at each call of pem_next() */
	int status;
	char *header;
	char *cipher;
	unsigned char *salt;
	size_t salt_len;
	unsigned char *bin;
	size_t bin_len;
};

static const unsigned char *str_leftis(const unsigned char *buf, const char *left)
{
	while (*left != '\0' && toupper(*left) == toupper(*buf)) {
		++buf;
		++left;
	}
	if (*left == '\0')
		return buf;
	return NULL;
}

static const unsigned char *str_rightis(const unsigned char *buf, const unsigned char **buf_nextline, const char *right)
{
	const unsigned char *p = buf;
	while (*p != '\0' && *p != '\n' && (*p != '\r' || p[1] != '\n'))
		++p;
	if (*p == '\0')
		*buf_nextline = NULL;
	else if (p[0] == '\r' && p[1] == '\n')
		*buf_nextline = p + 2;
	else if (p[0] == '\n')
		*buf_nextline = p + 1;

	if (p > buf)
		--p;

	int l = strlen(right);
	if (l <= 0)
		return p + 1;
	const char *r = right + l - 1;
	while (r >= right && p >= buf && toupper(*p) == toupper(*r)) {
		--p;
		--r;
	}
	if (r < right)
		return p + 1;
	return NULL;
}

const char *pem_errorstring(int e)
{
	if ((size_t)e >= sizeof(errorstrings) / sizeof(*errorstrings))
		return NULL;
	else
		return errorstrings[e];
}

	/*
	 * The data_in pointer must contain data that is terminated with a
	 * '\0' character.
	 * This assumption is used by pem_next() to detect the end of data_in
	 * */
pem_ctrl_t *pem_construct_pem_ctrl(const unsigned char *data_in)
{
	pem_ctrl_t *ctrl = malloc(sizeof(pem_ctrl_t));
	ctrl->index = 0;
	ctrl->data_current = data_in;

	ctrl->header = NULL;
	ctrl->cipher = NULL;
	ctrl->salt = NULL;
	ctrl->bin = NULL;

	ctrl->cb_password_pre = NULL;
	ctrl->cb_password_post = NULL;
	ctrl->cb_loop_top = NULL;
	ctrl->cb_loop_decrypt = NULL;
	ctrl->cb_loop_bottom = NULL;

	DBG("pem_construct_pem_ctrl(): constructed one pem_ctrl_t*: %lu", (long unsigned int)ctrl)
	return ctrl;
}

void pem_regcb_password(pem_ctrl_t *ctrl, char *(*cb_password_pre)(), void (*cb_password_post)(char *password))
{
	ctrl->cb_password_pre = cb_password_pre;
	ctrl->cb_password_post = cb_password_post;
}

void pem_regcb_loop_top(pem_ctrl_t *ctrl, void (*cb_loop_top)(const pem_ctrl_t *ctrl))
{
	ctrl->cb_loop_top = cb_loop_top;
}

void pem_regcb_loop_decrypt(pem_ctrl_t *ctrl, void (*cb_loop_decrypt)(int decrypt_ok, const char *errmsg))
{
	ctrl->cb_loop_decrypt = cb_loop_decrypt;
}

void pem_regcb_loop_bottom(pem_ctrl_t *ctrl, void (*cb_loop_bottom)(const unsigned char *data_src, size_t data_src_len))
{
	ctrl->cb_loop_bottom = cb_loop_bottom;
}

void pem_destruct_pem_ctrl(pem_ctrl_t *ctrl)
{
	reset_round(ctrl);
	free(ctrl);
	DBG("pem_destruct_pem_ctrl(): destructed one pem_ctrl_t*: %lu", (long unsigned int)ctrl)
}

static void reset_round(pem_ctrl_t *ctrl)
{
	if (ctrl->header) {
		free(ctrl->header);
		ctrl->header = NULL;
	}
	if (ctrl->cipher) {
		free(ctrl->cipher);
		ctrl->cipher = NULL;
	}
	if (ctrl->salt) {
		free(ctrl->salt);
		ctrl->salt = NULL;
	}
	if (ctrl->bin) {
		free(ctrl->bin);
		ctrl->bin = NULL;
	}
	ctrl->bin_len = 0;

	ctrl->status = -1;
}

int pem_status(const pem_ctrl_t *ctrl)                { return ctrl->status; }
const char *pem_header(const pem_ctrl_t *ctrl)        { return ctrl->header; }
const char *pem_cipher(const pem_ctrl_t *ctrl)        { return ctrl->cipher; }
const unsigned char *pem_salt(const pem_ctrl_t *ctrl) { return ctrl->salt; }
size_t pem_salt_len(const pem_ctrl_t *ctrl)           { return ctrl->salt_len; }
const unsigned char *pem_bin(const pem_ctrl_t *ctrl)  { return ctrl->bin; }
size_t pem_bin_len(const pem_ctrl_t *ctrl)            { return ctrl->bin_len; }

	/*
	 * Copy a string.
	 * The target of the copy (return value) is allocated (malloc) and later
	 * it will have to be freed by the caller.
	 *
	 * The source string is *NOT* represented by a unique char *.
	 * It is represented by a pointer to the first character (begin) and a
	 * pointer next to the last character (end). Thus it allows to copy a
	 * source string that *DOES NOT HAVE* a terminating null character.
	 *
	 * On the other hand, the target string returned by this function is
	 * regular, it *DOES HAVE* a terminating null character.
	 *
	 * The case begin == end corresponds to an empty string.
	 * if end is not >= begin, then consider source being an empty string.
	 *
	 * */
static char *special_str_copy(const unsigned char *begin, const unsigned char *end)
{
	assert(begin && end);

	ssize_t len;
	if (begin <= end)
		len = end - begin;
	else
		len = 0;
	unsigned char *s0 = (unsigned char *)malloc(len + 1);
	unsigned char *s = s0;
	while (begin < end) {
		*(s++) = *(begin++);
	}
	assert(s - s0 == len);
	*s = '\0';

	return (char *)s0;
}

int pem_next(pem_ctrl_t *ctrl)
{
	DBG("pem_next(): start")
	DBG("Index = %d", ctrl->index)

	reset_round(ctrl);

	if (!ctrl->data_current) {
		ctrl->status = PEM_TERMINATED;
		DBG("Status set to PEM_TERMINATED")
		DBG("pem_next(): returning 0")
		return 0;
	}

/*
 * * ****** *
 * * PART I *
 * * ****** *
 *
 *   Parse PEM text to identify BASE64 inner content
 *
 * */


	DBG("pem_next() part 1: parse PEM tags to find inner BASE64-encoded content")
	const unsigned char *b = ctrl->data_current;
	const unsigned char *b0 = b;
	const unsigned char *old_b;
	const unsigned char *nextline;
	do {
		const unsigned char *header = str_leftis(b, "-----begin ");
		const unsigned char *fin = str_rightis(b, &nextline, "-----");
		old_b = b;
		b = nextline;
		if (header && fin && header < fin) {
			ctrl->header = special_str_copy(header, fin);

			DBG("Found header opening '%s'", ctrl->header)

			break;
		}
	} while (nextline);

	int rogue_chars_sequence = 0;
	if (ctrl->header) {
		while (b0 < old_b && (*b0 == '\n' || *b0 == '\r' || isblank(*b0)))
			++b0;
		if (b0 != old_b) {
			nextline = old_b;
			rogue_chars_sequence = 1;
			free(ctrl->header);
			ctrl->header = NULL;
		}
	}

	if (!nextline || rogue_chars_sequence) {
		if (!ctrl->header || rogue_chars_sequence) {
			if (!ctrl->header) {
				ctrl->header = malloc(1);
				ctrl->header[0] = '\0';
			}
			DBG("Status set to PEM_NO_PEM_INFORMATION")
			ctrl->status = PEM_NO_PEM_INFORMATION;
		} else {
			DBG("Status set to PEM_PARSE_ERROR")
			ctrl->status = PEM_PARSE_ERROR;
		}
		ctrl->data_current = nextline;
		DBG("pem_next(): returning 1")
		return 1;
	}

	const unsigned char *header = str_leftis(b, "proc-type:");
	int has_proc_type = 0;
	int proc_type_is_set_for_encryption = 0;

	const unsigned char *cipher_begin = NULL;
	const unsigned char *cipher_end = NULL;
	const unsigned char *salt_begin = NULL;
	const unsigned char *salt_end = NULL;

	if (!header) {
		DBG("No Proc-Type in the line next to header: assuming clear data")
	} else {
		DBG("Found Proc-Type in the line next to header")
		has_proc_type = 1;
		while (isblank(*header))
			++header;
		if (*header == '4') {
			++header;
			while (isblank(*header))
				++header;
			if (*header == ',') {
				++header;
				while (isblank(*header))
					++header;
				const unsigned char *fin = str_rightis(header, &nextline, "encrypted");
				if (header == fin && nextline) {
					proc_type_is_set_for_encryption = 1;

					DBG("Proc-Type content is set for encryption ('4,ENCRYPTED')")

					b = nextline;
					const unsigned char *h2;
					if ((h2 = str_leftis(b, "dek-info:"))) {

						DBG("Found Dek-Info")

						while (isblank(*h2))
							++h2;
						cipher_begin = h2;
						while (*h2 != '\0' && *h2 != ',' && !isblank(*h2) && *h2 != '\r' && *h2 != '\n')
							++h2;
						cipher_end = h2;
						while (isblank(*h2))
							++h2;
						if (*h2 == ',') {
							++h2;
							while (isblank(*h2))
								++h2;
							salt_begin = h2;
							while (*h2 != '\0' && *h2 != '\r' && *h2 != '\n')
								++h2;
							--h2;
							while (isblank(*h2) && h2 >= salt_begin)
								--h2;
							salt_end = h2 + 1;

							DBG("Found salt")

						}
					}
				}
			}
		}
	}

/*    DBG("A- b: [%c] %d, [%c] %d, [%c] %d, [%c] %d, [%c] %d", b[0], b[0], b[1], b[1], b[2], b[2], b[3], b[3], b[4], b[4])*/

	int got_empty_line_after_dek_info = 0;
	if (has_proc_type && cipher_begin) {
		str_rightis(b, &nextline, "");
		if (nextline) {
			b = nextline;
			if (b[0] == '\n') {
				got_empty_line_after_dek_info = 1;
				DBG("Empty line (as expected) after Dek-Info")
				b += 1;
			} else if (b[0] == '\r' && b[1] == '\n') {
				got_empty_line_after_dek_info = 1;
				DBG("Empty line (as expected) after Dek-Info (CR-LF format)")
				b += 2;
			} else {
				DBG("Missing empty line after Dek-Info")
			}
		}
	}

	int salt_is_ok = 1;
	if (cipher_begin) {
		if (cipher_end > cipher_begin)
			ctrl->cipher = special_str_copy(cipher_begin, cipher_end);
		if (salt_begin) {
			if (salt_end > salt_begin) {
				char *str_salt = special_str_copy(salt_begin, salt_end);
				pem_alloc_and_read_hexa(str_salt, SALT_MINIMUM_BYTES, &ctrl->salt, &ctrl->salt_len);
				if (!ctrl->salt) {
					ctrl->salt_len = 0; /* Already done by pem_alloc_and_read_hexa, yes */
					salt_is_ok = 0;
				}
				free(str_salt);
			}
		}
	}

	while (*b == '\n' || (*b == '\r' && b[1] == '\n'))
		b += (*b == '\n' ? 1 : 2);
	const unsigned char *b64_start = b;
	size_t b64_len = 0;

	int got_closed = 0;
	do {
		const unsigned char *h = str_leftis(b, "-----end ");
		const unsigned char *fin = str_rightis(b, &nextline, "-----");
		if (h && fin && h < fin) {
			char *header_closure = special_str_copy(h, fin);
			got_closed = 1;
			DBG("Found header closure '%s'", header_closure)
			free(header_closure);
			break;
		}
		b = nextline;
	} while (nextline);

	if (nextline) {
		while (isblank(*nextline) || *nextline == '\n' || *nextline == '\r')
			++nextline;
		if (*nextline == '\0')
			nextline = NULL;
	}

	if (nextline) {
		DBG("nextline[0] = '%c' (%d)", nextline[0], nextline[0])
	} else {
		DBG("nextline is NULL")
	}

	ctrl->data_current = nextline;

	if (got_closed) {
		ctrl->index++;
		DBG("Increasing index. New value = %d", ctrl->index)

			/*
			 * Not a typo.
			 * Normally blen is 'arrival - beginning + 1' but here,
			 * arrival is 'b - 1' so -1 + 1 => no '+ 1' term.
			 * */
		b64_len = b - b64_start;
		if (has_proc_type && !ctrl->cipher) {
			if (proc_type_is_set_for_encryption) {
				DBG("Status set to PEM_MISSING_ENCRYPTION_INFORMATION")
				ctrl->status = PEM_MISSING_ENCRYPTION_INFORMATION;
			} else {
				DBG("Status set to PEM_UNMANAGED_PROC_TYPE")
				ctrl->status = PEM_UNMANAGED_PROC_TYPE;
			}
		} else if (b64_len == 0) {
			DBG("Status set to PEM_EMPTY_DATA")
			ctrl->status = PEM_EMPTY_DATA;
		} else if (!ctrl->cipher) {
			DBG("Status set to PEM_CLEAR_DATA")
			ctrl->status = PEM_CLEAR_DATA;
		} else if (got_empty_line_after_dek_info) {
			if (!salt_is_ok) {
				DBG("Status set to PEM_INCORRECT_SALT")
				ctrl->status = PEM_INCORRECT_SALT;
			} else {
				DBG("Status set to PEM_ENCRYPTED_DATA")
				ctrl->status = PEM_ENCRYPTED_DATA;
			}
		} else {
			DBG("Status set to PEM_MISSING_EMPTY_LINE_AFTER_ENCRYPTION_INFO")
			ctrl->status = PEM_MISSING_EMPTY_LINE_AFTER_ENCRYPTION_INFO;
		}
	} else {
		ctrl->data_current = NULL;
		DBG("Status set to PEM_PARSE_ERROR")
		ctrl->status = PEM_PARSE_ERROR;
	}


/*
 * * ******* *
 * * PART II *
 * * ******* *
 *
 *   Decode BASE64 data
 *
 * */


	DBG("pem_next() part 2: decode BASE64-encoded content found")
	if (pem_has_data(ctrl)) {
		if (!pem_base64_decode(b64_start, b64_len, &ctrl->bin, &ctrl->bin_len)) {
			DBG("Status set to PEM_BAD_BASE64_CONTENT")
			ctrl->status = PEM_BAD_BASE64_CONTENT;
		}
	}

	DBG("pem_next(): returning 1")

	return 1;
}

int pem_has_data(const pem_ctrl_t *ctrl)
{
	return ctrl->status == PEM_ENCRYPTED_DATA || ctrl->status == PEM_CLEAR_DATA;
}

int pem_has_encrypted_data(const pem_ctrl_t *ctrl)
{
	return ctrl->status == PEM_ENCRYPTED_DATA;
}

static int pem_base64_estimate_decoded_data_len(const unsigned char* b64msg, size_t b64msg_len)
{
UNUSED(b64msg);

		/* Very loose approximation (we ignore newlines and padding) */
	return (b64msg_len * 3 + 3) / 4 + 1;
}

static int pem_base64_decode(const unsigned char *b64msg, size_t b64msg_len, unsigned char **binbuf, size_t *binbuf_len)
{
	BIO *bio;
	BIO *b64;

	size_t allocated_len = pem_base64_estimate_decoded_data_len(b64msg, b64msg_len);
	*binbuf = (unsigned char*)malloc(allocated_len);

	bio = BIO_new_mem_buf((void *)b64msg, b64msg_len);
	b64 = BIO_new(BIO_f_base64());
	bio = BIO_push(b64, bio);

	*binbuf_len = BIO_read(bio, *binbuf, b64msg_len);

	assert(*binbuf_len <= allocated_len);

	BIO_free_all(bio);

	if (*binbuf_len <= 0) {
		free(*binbuf);
		*binbuf = NULL;
		*binbuf_len = 0;
		return 0;
	} else if (allocated_len != *binbuf_len) {
		*binbuf = (unsigned char *)realloc(*binbuf, *binbuf_len);
	}
	return 1;
}

static int hexchar_to_int(const char c)
{
	if (c >= '0' && c <= '9')
		return c - '0';
	else if (c >= 'A' && c <= 'F')
		return (c - 'A') + 10;
	else if (c >= 'a' && c <= 'f')
		return (c - 'a') + 10;
	else
		return -1;
}

	/*
	 * Read a hex string (like "A0F23BB1") and convert into
	 * a binary block corresponding to the hex string.
	 * Hex characters can be lower or upper case letters.
	 *
	 * The target binary block is allocated and the caller will
	 * later have to manage freeing it.
	 *
	 * If there is an issue in the conversion (illegal characters),
	 * no allocation is done and *buf and *buf_len are zeroed.
	 *
	 * Return 1 if success (meaning, the binary block got allocated
	 * and contains the binary corresponding to hex string), return 0
	 * otherwise.
	 *
	 * *WARNING*
	 *   The returned block is *NOT* a string (it is not null-character
	 *   terminated).
	 *
	 */
int pem_alloc_and_read_hexa(const char *s, int salt_min_bytes, unsigned char **buf, size_t *buf_len)
{
	*buf = NULL;
	*buf_len = 0;

	if (!s)
		return 0;

	int n = strlen(s);
	if (n < 2 * salt_min_bytes || n % 2 != 0)
		return 0;

	*buf_len = n / 2;
	*buf = malloc(*buf_len);
	int i;
	int j = 0;
	for (i = 0; i < n; i += 2) {
		int code_hi = hexchar_to_int(s[i]);
		int code_lo = hexchar_to_int(s[i + 1]);
		if (code_hi < 0 || code_lo < 0) {
			free(*buf);
			*buf = NULL;
			*buf_len = 0;
			return 0;
		}
		(*buf)[j] = (unsigned char)((code_hi << 4) + code_lo);
		++j;
	}
	assert(j == (int)*buf_len);
	return 1;
}

void pem_openssl_start()
{
	OpenSSL_add_all_algorithms();
}

	/*
	 * the list of functions to call was found here:
	 *   https://wiki.openssl.org/index.php/Library_Initialization
	 *
	 * */
void pem_openssl_terminate()
{
	FIPS_mode_set(0);
	CONF_modules_unload(1);
	EVP_cleanup();
	CRYPTO_cleanup_all_ex_data();
	ERR_remove_state(0);
	ERR_free_strings();
}

int pem_decrypt(const pem_ctrl_t *ctrl, unsigned char **out, int *out_len, const char **errmsg)
{
	*out = NULL;
	*out_len = 0;
	*errmsg = NULL;

	const EVP_CIPHER *evp_cipher;
	if (!(evp_cipher = EVP_get_cipherbyname(ctrl->cipher))) {
		*errmsg = "unable to acquire cipher by its name";
		DBG("do_decrypt(): set *errmsg to '%s' and returning 0 (FAILURE)", *errmsg)
		return 0;
	}

	char *password = NULL;
	if (ctrl->cb_password_pre) {
		if (!(password = ctrl->cb_password_pre())) {
			*errmsg = "no password";
			DBG("do_decrypt(): set *errmsg to '%s' and returning 0 (FAILURE)", *errmsg)
			return 0;
		}
	}

	EVP_CIPHER_CTX *ctx;
	if (!(ctx = EVP_CIPHER_CTX_new())) {
		*errmsg = "unable to initialize cipher context";
		DBG("do_decrypt(): set *errmsg to '%s' and returning 0 (FAILURE)", *errmsg)
		if (ctrl->cb_password_post)
			ctrl->cb_password_post(password);
		return 0;
	}

	unsigned char *key = malloc(evp_cipher->key_len);
	unsigned char *iv = malloc(evp_cipher->iv_len);

	do {

		int nb_bytes;
		int l = 0;
		if (password)
			l = strlen(password);
		if ((nb_bytes = EVP_BytesToKey(evp_cipher, EVP_md5(), ctrl->salt, (unsigned char *)password, l, 1, key, iv)) < 1) {
			*errmsg = "could not derive KEY and IV from password and salt";
			break;
		}

		if (EVP_DecryptInit_ex(ctx, evp_cipher, NULL, key, ctrl->salt) != 1) {
			*errmsg = "unable to initialize decryption";
			break;
		}

		int outl;
		*out = malloc(ctrl->bin_len + 256);
		if (EVP_DecryptUpdate(ctx, *out, &outl, ctrl->bin, ctrl->bin_len) != 1) {
			*errmsg = "unable to perform decryption";
			break;
		}
		int final_outl;
		if (EVP_DecryptFinal_ex(ctx, *out + outl, &final_outl) != 1) {
			*errmsg = "decryption error";
			break;
		}
		*out_len = outl + final_outl;

	} while (0);

	free(iv);
	free(key);
	EVP_CIPHER_CTX_free(ctx);
	if (ctrl->cb_password_post)
		ctrl->cb_password_post(password);

	if (*errmsg) {
		if (*out) {
			free(*out);
			*out = NULL;
			*out_len = 0;
		}
		DBG("do_decrypt(): set *errmsg to '%s' and returning 0 (FAILURE)", *errmsg)
		return 0;
	}

	DBG("do_decrypt(): returning 1 (SUCCESS)")
	return 1;
}

	/*
	 * Perform walk through PEM blocks.
	 * Uses call back functions to interact as walk moves on.
	 *
	 * Returns 0 is no PEM information at all was found (even in error)
	 * Returns 1 if something (maybe in error, maybe clear, maybe encrypted...) was found
	 */
int pem_walker(pem_ctrl_t *ctrl, unsigned char **data_out, size_t *data_out_len)
{
	DBG("pem_walker() start")

	pem_openssl_start();

	*data_out = NULL;
	*data_out_len = 0;

	int count = 0;
	int pem_content = 0;

	while (pem_next(ctrl)) {

		if (ctrl->status != PEM_NO_PEM_INFORMATION)
			pem_content = 1;

		if (ctrl->cb_loop_top)
			ctrl->cb_loop_top(ctrl);

		if (!pem_has_data(ctrl))
			continue;

		++count;

		unsigned char *data_src;
		size_t data_src_len;
		int data_src_is_readonly = 1;
		if (!pem_has_encrypted_data(ctrl)) {
			DBG("pem_walker(): data is clear")
			data_src = (unsigned char *)pem_bin(ctrl);
			data_src_len = pem_bin_len(ctrl);
		} else {
			DBG("pem_walker(): data is encrypted")
			data_src = NULL;
			data_src_len = 0;

			unsigned char *out;
			int out_len;
			const char *errmsg;
			if (pem_decrypt(ctrl, &out, &out_len, &errmsg) == 1) {
				DBG("pem_walker(): decrypt successful")
				data_src = out;
				data_src_len = out_len;
				data_src_is_readonly = 0;
				if (ctrl->cb_loop_decrypt)
					ctrl->cb_loop_decrypt(1, NULL);
			} else {
				DBG("pem_walker(): decrypt error: %s", errmsg)
				if (ctrl->cb_loop_decrypt)
					ctrl->cb_loop_decrypt(0, errmsg);
			}
		}

		if (ctrl->cb_loop_bottom)
			ctrl->cb_loop_bottom(data_src, data_src_len);

		if (data_src) {
			DBG("data (was clear or got decrypted) to add to buffer")
			unsigned char *target;
			if (!*data_out) {
				*data_out = malloc(data_src_len);
				target = *data_out;
				*data_out_len = 0;
			} else {
				*data_out = realloc(*data_out, *data_out_len + data_src_len);
				target = *data_out + *data_out_len;
			}
			memcpy(target, data_src, data_src_len);
			*data_out_len += data_src_len;
			if (!data_src_is_readonly)
				free(data_src);
		}
	}
	pem_openssl_terminate();

	int r = (count || pem_content);
	DBG("pem_walker() returning value %d (0 means no PEM content at all, 1 means PEM stuff found)", r)
	return r;
}

