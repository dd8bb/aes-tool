/*
 * argp-standalone: standalone version of glibc's argp functions.
 * Copyright (C) 2020 Thomas Mathys <tom42@github.com>
 *
 * argp-standalone is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * argp-standalone is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with the GNU C Library; if not, see
 * <http://www.gnu.org/licenses/>.
 */

/* Headers */
#define HAVE_MEMPCPY_H 0
#define HAVE_STRCASE_H 0
#define HAVE_STRCHRNUL_H 0
#define HAVE_STRNDUP_H 0
#define HAVE_SYSEXITS_H 0
#define HAVE_UNISTD_H 1

/* Unlocked variants of stdio functions */
#define HAVE_DECL_PUTC_UNLOCKED 0
#define HAVE_DECL_FPUTS_UNLOCKED 0
#define HAVE_DECL_FWRITE_UNLOCKED 0

/* strerror_r and strerror */
#define HAVE_STRERROR_R 0
#define HAVE_DECL_STRERROR_R 0
#define HAVE_DECL_STRERROR 1

/* Miscellaneous functions */
#define HAVE_ASPRINTF 1
#define HAVE_MEMPCPY 1
#define HAVE_RANDOM 0
#define HAVE_SLEEP 1
#define HAVE_STRCASECMP 1
#define HAVE_STRCHRNUL 0
#define HAVE_STRNDUP 0

/* Variables */
#define HAVE_DECL_PROGRAM_INVOCATION_SHORT_NAME 0
#define HAVE_DECL_PROGRAM_INVOCATION_NAME 0

/* Types */
#define HAVE_SSIZE_T 1
