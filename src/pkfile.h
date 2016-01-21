/*
 * =====================================================================================
 *
 *       Filename:  pkfile.h
 *
 *    Description:  Header file of pkfile.c
 *
 *        Version:  1.0
 *        Created:  23/12/2015 20:02:53
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  Sébastien Millet (smt), milletseb@laposte.net
 *
 * =====================================================================================
 */

#ifndef PKFILE_H

#include "common.h"

#include <stdio.h>

typedef enum {E_META, E_DATA, E_ERROR} entry_t;

typedef enum {
	T_NORTH_EAST = 0,
	T_BLANK = 1,
	T_NORTH_SOUTH_EAST = 2,
	T_NORTH_SOUTH = 3,
	T_EMPTY = 4
} tree_t;

struct seq_t;
typedef struct seq_t seq_t;

	/* Includes the initial byte of tag number 31 */
#define TAG_U_LONG_FORMAT_MAX_BYTES 6
	/* Includes the initial byte that indicates the number of bytes used to encode length */
#define LENGTH_MULTIBYTES_MAX_BYTES 7
#define TAG_MAX_HLENGTH (TAG_U_LONG_FORMAT_MAX_BYTES + LENGTH_MULTIBYTES_MAX_BYTES)

#define MAX_TAG_NAME 100

struct seq_t {
	entry_t type;
	ssize_t header_len;
	ssize_t data_len;
	ssize_t total_len;
	int level;
	int index;

	const char *tag_type_str;
	char tag_name[MAX_TAG_NAME];
	int tag_class;
	int tag_type;
	int tag_number;
	int tag_indefinite;

	char header[TAG_MAX_HLENGTH];
	char *data;   /* Used with E_DATA */
	char *errmsg; /* Used with E_ERROR */

	tree_t tree;

	size_t offset;
	ssize_t consumed;

	seq_t *parent;
	seq_t *child;
};

struct pkctrl_t;
typedef struct pkctrl_t pkctrl_t;

pkctrl_t *pkctrl_construct(const unsigned char *data_in, size_t data_in_len);
void pkctrl_destruct(pkctrl_t *ctrl, int keep_silent);
seq_t *pkctrl_head(const pkctrl_t *ctrl);

seq_t *seq_next(pkctrl_t *pkf);
void seq_clear_error(seq_t *seq);
int seq_has_string_data(const seq_t *seq);
int seq_has_oid(const seq_t *seq);
int seq_has_integer(const seq_t *seq);
int seq_has_bit_string(const seq_t *seq);
int seq_has_octet_string(const seq_t *seq);

#endif /* PKFILE_H */

