/*
 * =====================================================================================
 *
 *       Filename:  ppem.h
 *
 *    Description:  Header file of ppem.c
 *
 *        Version:  1.0
 *        Created:  28/12/2015 13:53:10
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  Sébastien Millet (smt), milletseb@laposte.net
 *
 * =====================================================================================
 */

#ifndef PPEM_H

#include <stdlib.h>

	/*
	 * * ******* *
	 * * WARNING *
	 * * ******* *
	 *
	 *   The values below are assumed to be in this order here:
	 *     ppem.c -> errorstrings strings table
	 *
	 * */
enum {
	PEM_NO_PEM_INFORMATION,
	PEM_PARSE_ERROR,
	PEM_UNMANAGED_PROC_TYPE,
	PEM_MISSING_ENCRYPTION_INFORMATION,
	PEM_MISSING_EMPTY_LINE_AFTER_ENCRYPTION_INFO,
	PEM_INCORRECT_SALT,
	PEM_EMPTY_DATA,
	PEM_BAD_BASE64_CONTENT,
	PEM_ENCRYPTED_DATA,
	PEM_CLEAR_DATA,
	PEM_TERMINATED
};

struct pem_ctrl_t;
typedef struct pem_ctrl_t pem_ctrl_t;

const char *pem_errorstring(int e);

pem_ctrl_t *pem_construct_pem_ctrl(const unsigned char *data_in);
void pem_regcb_password(pem_ctrl_t *ctrl, char *(*cb_password_pre)(), void (*cb_password_post)(char *password));
void pem_regcb_loop_top(pem_ctrl_t *ctrl, void (*cb_loop_top)(const pem_ctrl_t *ctrl));
void pem_regcb_loop_decrypt(pem_ctrl_t *ctrl, void (*cb_loop_decrypt)(int decrypt_ok, const char *errmsg));
void pem_regcb_loop_bottom(pem_ctrl_t *ctrl, void (*cb_loop_bottom)(const unsigned char *data_src, size_t data_src_len));
int pem_walker(pem_ctrl_t *ctrl, unsigned char **data_out, size_t *data_out_len);

void pem_destruct_pem_ctrl(pem_ctrl_t *ctrl);
int pem_next(pem_ctrl_t *ctrl);
int pem_has_data(const pem_ctrl_t *ctrl);
int pem_has_encrypted_data(const pem_ctrl_t *ctrl);

int pem_status(const pem_ctrl_t *ctrl);
const char *pem_header(const pem_ctrl_t *ctrl);
const char *pem_cipher(const pem_ctrl_t *ctrl);
const unsigned char *pem_salt(const pem_ctrl_t *ctrl);
size_t pem_salt_len(const pem_ctrl_t *ctrl);
const unsigned char *pem_bin(const pem_ctrl_t *ctrl);
size_t pem_bin_len(const pem_ctrl_t *ctrl);

int pem_alloc_and_read_hexa(const char *s, int minimum_length, unsigned char **buf, size_t *buf_len);
void pem_openssl_start();
void pem_openssl_terminate();
int pem_decrypt(const pem_ctrl_t *ctrl, unsigned char **out, int *out_len, const char **errmsg);

#endif /* PPEM_H */

