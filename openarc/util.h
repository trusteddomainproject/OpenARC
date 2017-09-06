/*
**  Copyright (c) 2016, 2017, The Trusted Domain Project.
**    All rights reserved.
*/

#ifndef _UTIL_H_
#define _UTIL_H_

/* system includes */
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <regex.h>
#include <stdio.h>

/* openarc includes */
#include "build-config.h"

/* TYPES */
struct arcf_dstring;

/* PROTOTYPES */
extern const char **arcf_mkarray __P((char *));
extern size_t arcf_inet_ntoa __P((struct in_addr, char *, size_t));
extern void arcf_lowercase __P((u_char *));
extern void arcf_optlist __P((FILE *));
extern void arcf_setmaxfd __P((void));
extern int arcf_socket_cleanup __P((char *));

extern struct arcf_dstring *arcf_dstring_new __P((int, int));
extern void arcf_dstring_free __P((struct arcf_dstring *));
extern _Bool arcf_dstring_copy __P((struct arcf_dstring *, u_char *));
extern _Bool arcf_dstring_cat __P((struct arcf_dstring *, u_char *));
extern _Bool arcf_dstring_cat1 __P((struct arcf_dstring *, int));
extern _Bool arcf_dstring_catn __P((struct arcf_dstring *, u_char *, size_t));
extern void arcf_dstring_chop __P((struct arcf_dstring *, int));
extern u_char *arcf_dstring_get __P((struct arcf_dstring *));
extern int arcf_dstring_len __P((struct arcf_dstring *));
extern void arcf_dstring_blank __P((struct arcf_dstring *));
extern size_t arcf_dstring_printf __P((struct arcf_dstring *, char *, ...));

#endif /* _UTIL_H_ */
