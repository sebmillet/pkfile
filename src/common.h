/*
 * =====================================================================================
 *
 *       Filename:  common.h
 *
 *    Description:  Common header file
 *
 *        Version:  1.0
 *        Created:  23/12/2015 13:37:51
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  Sébastien Millet (smt), milletseb@laposte.net
 *
 * =====================================================================================
 */

#ifndef COMMON_H
#define COMMON_H

#define DEBUG

#include <sys/types.h>

#define FALSE 0
#define TRUE  1

#define L_ENFORCE   (-1)
#define L_ERROR     0
#define L_WARNING   1
#define L_QUIET     2
#define L_NORMAL    3
#define L_VERBOSE   4
#define L_DEBUG     5

int out(int level, const char *fmt, ...);
int outln(int level, const char *fmt, ...);
int outln_error(const char *fmt, ...);
int outln_warning(const char *fmt, ...);
int outln_errno(int e);

void fatalln(const char *file, int line, const char *fmt, ...);
#define FATAL_ERROR(s, ...) \
	fatalln(__FILE__, __LINE__, s, __VA_ARGS__)
int dbg_core(const char *filename, int line, const char *fmt, ...);
#ifdef DEBUG
#define DBG(...) \
	dbg_core(__FILE__, __LINE__, __VA_ARGS__);
#else
#define DBG(...)
#endif

char *s_strncpy(char *dest, const char *src, size_t n);
char *s_strncat(char *dest, const char *src, size_t n);

#endif

