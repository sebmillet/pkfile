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

#include "common.h"

#include <stdio.h>

typedef enum {E_META, E_DATA, E_ERROR} entry_t;

struct seq_t;
typedef struct seq_t seq_t;

struct seq_t {
	entry_t type;
	ssize_t length;
	int level;
	int index;

	char *data;   /* Used with E_DATA */
	char *errmsg; /* Used with E_ERROR */

	ssize_t consumed;
	seq_t *parent;
	seq_t *child;
};

struct pkctrl_t;
typedef struct pkctrl_t pkctrl_t;

pkctrl_t *pkctrl_construct(FILE *f, ssize_t file_size);
void pkctrl_destruct(pkctrl_t *pkf);
seq_t *seq_next(pkctrl_t *pkf);

