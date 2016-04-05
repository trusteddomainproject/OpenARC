/* **  Copyright (c) 2016, The Trusted Domain Project.  All rights reserved.
*/

#ifndef _ARC_UTIL_H_
#define _ARC_UTIL_H_

#include "build-config.h"

/* system includes */
#include <sys/types.h>
#include <sys/param.h>
#ifdef HAVE_STDBOOL_H
# include <stdbool.h>
#endif /* HAVE_STDBOOL_H */

/* libopenarc includes */
#include "arc.h"

extern void arc_dstring_blank __P((struct arc_dstring *));
extern _Bool arc_dstring_cat __P((struct arc_dstring *, u_char *));
extern _Bool arc_dstring_cat1 __P((struct arc_dstring *, int));
extern _Bool arc_dstring_catn __P((struct arc_dstring *, u_char *, size_t));
extern _Bool arc_dstring_copy __P((struct arc_dstring *, u_char *));
extern void arc_dstring_free __P((struct arc_dstring *));
extern u_char *arc_dstring_get __P((struct arc_dstring *));
extern int arc_dstring_len __P((struct arc_dstring *));
extern struct arc_dstring *arc_dstring_new __P((ARC_MESSAGE *, int, int));
extern size_t arc_dstring_printf __P((struct arc_dstring *dstr, char *fmt,
                                      ...));

extern void arc_collapse __P((u_char *));
extern void arc_lowerhdr __P((u_char *));
extern u_char *arc_strndup(u_char *, size_t);
extern ARC_STAT arc_tmpfile __P((ARC_MESSAGE *, int *, _Bool));

#endif /* _ARC_UTIL_H_ */
