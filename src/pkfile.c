/*
 * =====================================================================================
 *
 *       Filename:  pkfile.c
 *
 *    Description:  Do the work of managing PKCS files
 *
 *        Version:  1.0
 *        Created:  23/12/2015 13:39:29
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  Sébastien Millet (smt), milletseb@laposte.net
 *
 * =====================================================================================
 */

#include "pkfile.h"

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>

struct pkctrl_t {
	FILE *f;
	int level;
	seq_t *head;
	seq_t *tail;
};

static const char *short_classes[] = {
	"univ", /* CLASS_UNIVERSAL */
	"appl", /* CLASS_APPLICATION */
	"cont", /* CLASS_CONTEXT_SPECIFIC */
	"priv"  /* CLASS_PRIVATE */
};
#define TAG_CLASS_UNIVERSAL        0
#define TAG_CLASS_APPLICATION      1
#define TAG_CLASS_CONTEXT_SPECIFIC 2
#define TAG_CLASS_PRIVATE          3

	/* Includes the initial byte of tag number 31 */
#define TAG_U_LONG_FORMAT_MAX_BYTES 6
	/* Includes the initial byte that indicates the number of bytes used to encode length */
#define LENGTH_MULTIBYTES_MAX_BYTES 7

static const char *short_types[] = {
	"prim", /* T_PRIM */
	"cons"  /* T_CONS */
};
typedef enum {
	T_PRIM = 0,
	T_CONS = 1,
	T_PRIM_OR_CONS = 2,  /* (does not belong to DER specs, used here-only */
	T_NA = -1           /* (same as above: value used here-only) */
} type_t;

typedef struct tag_univ_t {
	const char *name;
	type_t type;
	int is_string;
} tag_univ_t;

typedef struct {
	int class;
	type_t type;
	int number;
	unsigned long length;
} tag_t;

static tag_univ_t univ_tags[] = {
/*   name                 type_t          is_string */
	{"EOC",               T_PRIM,         FALSE},
	{"BOOLEAN",           T_PRIM,         FALSE},
	{"INTEGER",           T_PRIM,         FALSE},
	{"BIT STRING",        T_PRIM_OR_CONS, FALSE},
	{"OCTET STRING",      T_PRIM_OR_CONS, FALSE},
	{"NULL",              T_PRIM,         FALSE},
	{"OBJECT IDENTIFIER", T_PRIM,         FALSE}, /* TAG_U_OBJECT_IDENTIFIER */
	{"OBJECT DESCRIPTOR", T_PRIM_OR_CONS, FALSE},
	{"EXTERNAL",          T_CONS,         FALSE},
	{"REAL",              T_PRIM,         FALSE},
	{"ENUMERATED",        T_PRIM,         FALSE},
	{"EMBEDDED PDV",      T_CONS,         FALSE},
	{"UTF8String",        T_PRIM_OR_CONS, TRUE},
	{"RELATIVE-OID",      T_CONS,         FALSE},
	{"(reserved)",        T_NA,           FALSE},
	{"(reserved)",        T_NA,           FALSE},
	{"SEQUENCE",          T_CONS,         FALSE},
	{"SET",               T_CONS,         FALSE},
	{"NUMERICSTRING",     T_PRIM_OR_CONS, FALSE},
	{"PRINTABLESTRING",   T_PRIM_OR_CONS, TRUE},
	{"T61STRING",         T_PRIM_OR_CONS, TRUE},
	{"VIDEOTEXSTRING",    T_PRIM_OR_CONS, TRUE},
	{"IA5String",         T_PRIM_OR_CONS, TRUE},
	{"UTCTime",           T_PRIM_OR_CONS, FALSE},
	{"GeneralizedTime",   T_PRIM_OR_CONS, FALSE},
	{"GraphicString",     T_PRIM_OR_CONS, TRUE},
	{"VisibleString",     T_PRIM_OR_CONS, TRUE},
	{"GeneralString",     T_PRIM_OR_CONS, TRUE},
	{"UniversalString",   T_PRIM_OR_CONS, TRUE},
	{"CHARACTER STRING",  T_PRIM_OR_CONS, TRUE},
	{"BMPString",         T_PRIM_OR_CONS, TRUE},
	{"(long form)",       T_NA,           FALSE}       /* TAG_U_LONG_FORMAT */
};

#define TAG_U_OBJECT_IDENTIFIER 6
#define TAG_U_LONG_FORMAT       31

static void get_tag_name(char *s, const size_t slen, const int tag_class, const int tag_number)
{
	if (tag_class == TAG_CLASS_UNIVERSAL &&
			(size_t)tag_number < sizeof(univ_tags) / sizeof(*univ_tags)) {
		s_strncpy(s, univ_tags[tag_number].name, slen);
	} else if (tag_class == TAG_CLASS_UNIVERSAL) {
		snprintf(s, slen, "![ %i ]", tag_number);
	} else {
		snprintf(s, slen, "[ %i ]", tag_number);
	}
}

static seq_t *seq_construct_and_attach_to_chain(seq_t *parent, ssize_t length)
{
	seq_t *seq = (seq_t *)malloc(sizeof(seq_t));
	seq->length = length;
	seq->index = 0;
	seq->data = NULL;
	seq->consumed = 0;
	seq->parent = parent;
	seq->child = NULL;
	if (parent == NULL) {
		seq->level = 0;
	} else {
		seq->level = seq->parent->level + 1;
		seq->parent->child = seq;
	}
	out_dbg("++ Adding one seq_t level, current level = %d\n", seq->level);
	return seq;
}

void seq_destruct(seq_t *seq)
{
	if (seq->data != NULL)
		free(seq->data);
	free(seq);
}

pkctrl_t *pkctrl_construct(FILE *f, ssize_t file_size)
{
	pkctrl_t *ctrl = (pkctrl_t *)malloc(sizeof(pkctrl_t));
	ctrl->f = f;
	ctrl->tail = seq_construct_and_attach_to_chain(NULL, file_size);
	ctrl->head = ctrl->tail;
	return ctrl;
}

void pkctrl_destruct(pkctrl_t *ctrl)
{
	if (ctrl->tail != NULL) {
		if (ctrl->tail->type != E_ERROR)
			FATAL_ERROR("%s", "ctrl->tail should be NULL!");
		do {
			seq_t *to_free = ctrl->tail;
			ctrl->tail = ctrl->tail->parent;
			free(to_free);
		} while (ctrl->tail != NULL);
	}
	if (ctrl->tail != NULL)
		FATAL_ERROR("%s", "Cette fois-ci c'est encore plus grave ! Incohérence à l'intérieur de pkctrl_destruct()!");
	free(ctrl);
}

seq_t *seq_next(pkctrl_t *ctrl)
{
	char *errmsg = "unexpected end of file";

	while ((ctrl->tail->length >= 0 && ctrl->tail->consumed >= ctrl->tail->length) || feof(ctrl->f)) {
		if (feof(ctrl->f)) {
			if (ctrl->tail->parent == NULL) {
				seq_destruct(ctrl->tail);
				ctrl->tail = NULL;
				return NULL;
			} else {
				out_dbg("end of file encountered (1)\n");
				goto error;
			}
		}
		out_dbg("-- Removing one seq_t level\n");
		if (ctrl->tail->consumed > ctrl->tail->length) {
			errmsg = "data size inside sequence exceeds sequence size";
			goto error;
		}
		seq_t *to_free = ctrl->tail;
		if (ctrl->tail->parent != NULL)
			ctrl->tail->parent->consumed += ctrl->tail->consumed;
		ctrl->tail = ctrl->tail->parent;
		seq_destruct(to_free);
		if (ctrl->tail != NULL)
			ctrl->tail->child = NULL;
		else
			return NULL;
	}
	ctrl->tail->index++;

	ssize_t consumed = 0;

	int c;
	if ((c = fgetc(ctrl->f)) == EOF) {
		if (ctrl->tail->length < 0 && ctrl->tail->parent == NULL) {
				/* Input was stdin thus size was unknown => not an error */
			seq_destruct(ctrl->tail);
			ctrl->tail = NULL;
			return NULL;
		}
		out_dbg("end of file encountered (2)\n");
		goto error;
	}
	++consumed;

	tag_t tag;
	tag.class = (c & 0xc0) >> 6;
	tag.type = (c & 0x20) >> 5;
	type_t original_type = tag.type;
	tag.number = (c & 0x1F);
	type_t type = univ_tags[tag.number].type;
	if (tag.class == TAG_CLASS_UNIVERSAL && (type == T_PRIM || type == T_CONS) && tag.type != type) {
		tag.type = T_PRIM;
		outln_warning("primitive/constructed bit mismatch, enforcing primitive");
	}

	char buflength[TAG_U_LONG_FORMAT_MAX_BYTES + LENGTH_MULTIBYTES_MAX_BYTES];
	buflength[0] = (char)c;
	int pos = 0;
	if (tag.number == TAG_U_LONG_FORMAT) {
		pos = 1;

		do {
			if ((c = fgetc(ctrl->f)) == EOF) {
				out_dbg("end of file encountered (3)\n");
				goto error;
			}
			++consumed;
			buflength[pos] = (char)c;
		} while (buflength[pos] & 0x80 && ++pos < TAG_U_LONG_FORMAT_MAX_BYTES);
		if (pos == sizeof(buflength)) {
			errmsg = "tag number too big";
			goto error;
		}
		int rev;
		long unsigned multi = 1;
		int shift = 0;
		unsigned rmask;
		unsigned lmask;
		unsigned bm1;
		unsigned v0;
		long unsigned value = 0;
		for (rev = pos; rev >= 1; --rev) {
			if (rev == 1)
				bm1 = 0;
			else
				bm1 = (unsigned)buflength[rev - 1];
			rmask = (0x7Fu >> shift);
			lmask = (0xFFu << (7 - shift)) & 0xFFu;
			v0 = (long unsigned)(((bm1 << (7 - shift)) & lmask) | (((unsigned)buflength[rev] >> shift) & rmask));

			value += v0 * multi;
			multi *= 256;   /* Can be written <<8, but... */
			++shift;
		}
		tag.number = (int)value;
		out_dbg("Tag number: %i\n", tag.number);
	}

	if (tag.class == TAG_CLASS_UNIVERSAL && tag.number >= 31) {
		outln_warning("universal tag number above maximum allowed value (30)\n");
	}

	int cc;
	if ((cc = fgetc(ctrl->f)) == EOF) {
		out_dbg("end of file encountered (4)\n");
		goto error;
	}
	++consumed;
	int n = 0;
	tag.length = (unsigned long)cc;
	if (cc & 0x80) {
		n = (cc & 0x7F);
		if (n > LENGTH_MULTIBYTES_MAX_BYTES - 1) {
			errmsg = "number of bytes to encode length exceeds maximum";
			goto error;
		} else if (n == 0) {
			errmsg = "number of bytes to encode length cannot be null";
			goto error;
		}
		tag.length = 0;
		int i;
		for (i = 1; i <= n; ++i) {
			if ((cc = fgetc(ctrl->f)) == EOF) {
				out_dbg("end of file encountered (5)\n");
				goto error;
			}
			++consumed;
			tag.length <<= 8;
			tag.length += (unsigned int)cc;
		}
	}
	out_dbg("Length: %lu\n", tag.length);

	char tag_name[100];
	get_tag_name(tag_name, sizeof(tag_name), tag.class, tag.number);
	out_dbg("%s-%s: %s, len: %lu\n",
			short_classes[tag.class], short_types[original_type], tag_name, tag.length);

	ctrl->tail->consumed += consumed;
	consumed = 0;

	ctrl->tail = seq_construct_and_attach_to_chain(ctrl->tail, tag.length);

	if (tag.type == T_PRIM) {
		ctrl->tail->type = E_DATA;
		if (tag.length >= 1) {
			ctrl->tail->data = (char *)malloc(tag.length);
			size_t nbread;
			nbread = fread(ctrl->tail->data, 1, (size_t)tag.length, ctrl->f);
			consumed += nbread;

			if (nbread != tag.length) {
				if (feof(ctrl->f)) {
					out_dbg("end of file encountered (6)\n");
					goto error;
				} else {
					errmsg = strerror(errno);
					goto error;
				}
			}
		}
	} else { /* tag->type == T_CONS */
		ctrl->tail->type = E_META;
	}
	ctrl->tail->consumed += consumed;

	return ctrl->tail;

error:
	ctrl->tail->type = E_ERROR;
	ctrl->tail->errmsg = errmsg;
	return ctrl->tail;
}

