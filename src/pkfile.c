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
#include <string.h>

typedef struct {
	const unsigned char *data;
	size_t data_len;
	size_t idx;
} vf_t;

struct pkctrl_t {
	vf_t vf;
	size_t offset;
	seq_t *head;
	seq_t *tail;
};

#ifdef DEBUG
static const char *short_classes[] = {
	"univ", /* CLASS_UNIVERSAL */
	"appl", /* CLASS_APPLICATION */
	"cont", /* CLASS_CONTEXT_SPECIFIC */
	"priv"  /* CLASS_PRIVATE */
};
#endif

#define TAG_CLASS_UNIVERSAL        0
#define TAG_CLASS_APPLICATION      1
#define TAG_CLASS_CONTEXT_SPECIFIC 2
#define TAG_CLASS_PRIVATE          3

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

typedef struct {
	int class;
	type_t type;
	int number;
	unsigned long header_len;  /* Size of tag itself */
	unsigned long data_len;    /* Value coded by the tag */
} tag_t;

typedef struct tag_univ_t {
	const char *name;
	type_t type;
	int is_string;
} tag_univ_t;

static tag_univ_t univ_tags[] = {
/*   name                 type_t          is_string */
	{"EOC",               T_PRIM,         FALSE},
	{"BOOLEAN",           T_PRIM,         FALSE},
	{"INTEGER",           T_PRIM,         FALSE}, /* TAG_U_INTEGER */
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
	{"UTCTime",           T_PRIM_OR_CONS, TRUE},
	{"GeneralizedTime",   T_PRIM_OR_CONS, TRUE},
	{"GraphicString",     T_PRIM_OR_CONS, TRUE},
	{"VisibleString",     T_PRIM_OR_CONS, TRUE},
	{"GeneralString",     T_PRIM_OR_CONS, TRUE},
	{"UniversalString",   T_PRIM_OR_CONS, TRUE},
	{"CHARACTER STRING",  T_PRIM_OR_CONS, TRUE},
	{"BMPString",         T_PRIM_OR_CONS, TRUE},
	{"(long form)",       T_NA,           FALSE} /* TAG_U_LONG_FORMAT */
};

#define TAG_U_INTEGER           2
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

static seq_t *seq_construct_and_attach_to_chain(seq_t *parent)
{
	seq_t *seq = (seq_t *)malloc(sizeof(seq_t));
	seq->header_len = -1;
	seq->data_len = -1;
	seq->total_len = -1;
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
	seq->offset = 0;
	DBG("++ Adding one seq_t level, current level = %d\n", seq->level)
	return seq;
}

static void seq_set_len(seq_t *s, ssize_t header_len, ssize_t data_len)
{
	s->header_len = header_len;
	s->data_len = data_len;
	s->total_len = header_len + data_len;
}

void seq_destruct(seq_t *seq)
{
	if (seq->data != NULL)
		free(seq->data);
	free(seq);
}

void seq_clear_error(seq_t *seq)
{
	if (seq->type != E_ERROR)
		FATAL_ERROR("%s", "seq_clear_error(): call without error condition!");
	if (seq->errmsg == NULL)
		FATAL_ERROR("%s", "seq_clear_error(): error condition but no error message!");
	free(seq->errmsg);
}

int seq_has_string_data(const seq_t *seq)
{
	if (seq->tag_class == TAG_CLASS_UNIVERSAL &&
			(size_t)seq->tag_number < sizeof(univ_tags) / sizeof(*univ_tags)) {
		return univ_tags[seq->tag_number].is_string;
	}
	return FALSE;
}

int seq_has_oid(const seq_t *seq)
{
	return (seq->tag_class == TAG_CLASS_UNIVERSAL && seq->tag_number == TAG_U_OBJECT_IDENTIFIER);
}

pkctrl_t *pkctrl_construct(const unsigned char *data_in, size_t data_in_len)
{
	pkctrl_t *ctrl = (pkctrl_t *)malloc(sizeof(pkctrl_t));
	ctrl->vf.data = data_in;
	ctrl->vf.data_len = data_in_len;
	ctrl->vf.idx = 0;
	ctrl->tail = seq_construct_and_attach_to_chain(NULL);
	seq_set_len(ctrl->tail, 0, data_in_len);
	ctrl->head = ctrl->tail;
	ctrl->offset = 0;
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
			seq_destruct(to_free);
		} while (ctrl->tail != NULL);
	}
	if (ctrl->tail != NULL)
		FATAL_ERROR("%s", "Cette fois-ci c'est encore plus grave ! Incohérence à l'intérieur de pkctrl_destruct()!");
	free(ctrl);
}

seq_t *pkctrl_head(const pkctrl_t *ctrl)
{
	return ctrl->head;
}

static int vf_eof(const vf_t *vf)
{
	return (vf->idx > vf->data_len);
}

static int vf_getc(vf_t *vf)
{
	if (vf->idx >= vf->data_len) {
		if (vf->idx == vf->data_len)
			vf->idx++;
		return EOF;
	} else {
		return vf->data[vf->idx++];
	}
}

size_t vf_read(void *ptr, size_t size, size_t nmemb, vf_t *vf)
{
	if (vf->idx >= vf->data_len)
		return 0;

		/* We are certain that 'remaining' is '>= 1' */
	size_t remaining = vf->data_len - vf->idx;

	size_t nb_bytes = size * nmemb;
	int flag1 = 0;
	if (nb_bytes > remaining) {
		flag1 = 1;
		nb_bytes = remaining;
	}

	memcpy(ptr, &vf->data[vf->idx], nb_bytes);
	vf->idx += nb_bytes + flag1;
	return nb_bytes;
}

seq_t *seq_next(pkctrl_t *ctrl)
{
	const char *prefix = "offset %lu: ";
	char *errmsg = "unexpected end of file";

	size_t cons = 0;

	while ((ctrl->tail->data_len >= 0 && ctrl->tail->consumed >= ctrl->tail->total_len) || vf_eof(&ctrl->vf)) {
		if (vf_eof(&ctrl->vf)) {
			if (ctrl->tail->parent == NULL) {
				seq_destruct(ctrl->tail);
				ctrl->tail = NULL;
				return NULL;
			} else {
				DBG("end of file encountered (1)\n")
				goto error;
			}
		}
		DBG("-- Removing one seq_t level\n")
		if (ctrl->tail->consumed > ctrl->tail->total_len) {
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

	ctrl->tail = seq_construct_and_attach_to_chain(ctrl->tail);
	ctrl->tail->offset = ctrl->offset;

	int c;
	if ((c = vf_getc(&ctrl->vf)) == EOF) {
		if (ctrl->tail->data_len < 0 && (ctrl->tail->parent == NULL || ctrl->tail->parent->parent == NULL)) {
				/* Input was stdin thus size was unknown => not an error */
			seq_destruct(ctrl->tail);
			ctrl->tail = NULL;
			return NULL;
		}
		DBG("ctrl->tail->data_len = %li\n", ctrl->tail->data_len)
		DBG("ctrl->tail->parent = %lu\n", ctrl->tail->parent)
		DBG("end of file encountered (2)\n")
		goto error;
	}
	char *hh = ctrl->tail->header;
	hh[cons++] = (char)c;

	tag_t tag;
	tag.class = (c & 0xc0) >> 6;
	tag.type = (c & 0x20) >> 5;
	tag.number = (c & 0x1F);
	type_t type = univ_tags[tag.number].type;
	if (tag.class == TAG_CLASS_UNIVERSAL && (type == T_PRIM || type == T_CONS) && tag.type != type) {
		tag.type = T_PRIM;
		outln_warning("primitive/constructed bit mismatch, enforcing primitive");
	}

	if (tag.number == TAG_U_LONG_FORMAT) {
		int cc;
		do {
			if ((cc = vf_getc(&ctrl->vf)) == EOF) {
				DBG("end of file encountered (3)\n")
				goto error;
			}
			hh[cons++] = (char)cc;
		} while (cc & 0x80 && cons < TAG_U_LONG_FORMAT_MAX_BYTES);
		if (cons == TAG_U_LONG_FORMAT_MAX_BYTES) {
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
		for (rev = cons; rev >= 1; --rev) {
			if (rev == 1)
				bm1 = 0;
			else
				bm1 = (unsigned)hh[rev - 1];
			rmask = (0x7Fu >> shift);
			lmask = (0xFFu << (7 - shift)) & 0xFFu;
			v0 = (long unsigned)(((bm1 << (7 - shift)) & lmask) | (((unsigned)hh[rev] >> shift) & rmask));

			value += v0 * multi;
			multi *= 256;   /* Can be written <<8, but... */
			++shift;
		}
		tag.number = (int)value;
		DBG("Tag number: %i\n", tag.number)
	}

	if (tag.class == TAG_CLASS_UNIVERSAL && tag.number >= 31) {
		outln_warning("universal tag number above maximum allowed value (30)\n");
	}

	int c2;
	if ((c2 = vf_getc(&ctrl->vf)) == EOF) {
		DBG("end of file encountered (4)\n")
		goto error;
	}

	hh[cons++] = (char)c2;

	int n = 0;
	tag.data_len = (unsigned long)c2;
	if (c2 & 0x80) {
		n = (c2 & 0x7F);
		if (n > LENGTH_MULTIBYTES_MAX_BYTES - 1) {
			errmsg = "number of bytes to encode length exceeds maximum";
			goto error;
		} else if (n == 0) {
			errmsg = "number of bytes to encode length cannot be null";
			goto error;
		}
		tag.data_len = 0;
		int i;
		int cc;
		for (i = 1; i <= n; ++i) {
			if ((cc = vf_getc(&ctrl->vf)) == EOF) {
				DBG("end of file encountered (5)\n")
				goto error;
			}
			hh[cons++] = (char)cc;
			tag.data_len <<= 8;
			tag.data_len += (unsigned int)cc;
		}
	}
	DBG("Length: %lu\n", tag.data_len)

	get_tag_name(ctrl->tail->tag_name, sizeof(ctrl->tail->tag_name), tag.class, tag.number);
	ctrl->tail->tag_type_str = short_types[tag.type];
	ctrl->tail->tag_class = tag.class;
	ctrl->tail->tag_type = tag.type;
	ctrl->tail->tag_number = tag.number;

	/*
	 * I "repeat" the 'ifdef DEBUG' as short_classes definition occurs
	 * only in debug mode. At the moment DBG does something only when DEBUG
	 * is defined but who knows...
	 * */
#ifdef DEBUG
	DBG("%s-%s: %s, len: %lu\n", short_classes[tag.class], short_types[tag.type], ctrl->tail->tag_name, tag.data_len)
#endif

	tag.header_len = cons;
	seq_set_len(ctrl->tail, tag.header_len, tag.data_len);

	if (tag.type == T_PRIM) {
		ctrl->tail->type = E_DATA;
		if (tag.data_len >= 1) {
			ctrl->tail->data = (char *)malloc(tag.data_len);
			size_t nbread;
			nbread = vf_read(ctrl->tail->data, 1, (size_t)tag.data_len, &ctrl->vf);
			cons += nbread;

			if (nbread != tag.data_len) {
				if (vf_eof(&ctrl->vf)) {
					DBG("end of file encountered (6)\n")
					goto error;
				} else {
					FATAL_ERROR("%s", "Internal inconsistency");
				}
			}
		}
	} else { /* tag->type == T_CONS */
		ctrl->tail->type = E_META;
	}
	ctrl->offset += cons;
	ctrl->tail->consumed += cons;

	seq_t *s = ctrl->tail;
	ssize_t virtual_consumed = 0;
	s->tree = T_EMPTY;
	while (s->parent != NULL) {
		virtual_consumed = s->total_len;
		if (s->parent->consumed + virtual_consumed == s->parent->total_len) {
			if (s->child == NULL)
				s->parent->tree = T_NORTH_EAST;
			else
				s->parent->tree = T_BLANK;
		} else {
			if (s->child == NULL)
				s->parent->tree = T_NORTH_SOUTH_EAST;
			else
				s->parent->tree = T_NORTH_SOUTH;
		}
		s = s->parent;
	}

	return ctrl->tail;

error:
	ctrl->tail->type = E_ERROR;
	size_t l = strlen(prefix) + strlen(errmsg) + 30;
	ctrl->tail->errmsg = malloc(l);
	snprintf(ctrl->tail->errmsg, l, prefix, ctrl->offset + cons);
	s_strncat(ctrl->tail->errmsg, errmsg, l);
	return ctrl->tail;
}

