/*
**  Copyright (c) 2010, 2012, 2017, The Trusted Domain Project.
**    All rights reserved.
*/

#ifndef _ARC_DNS_H_
#define _ARC_DNS_H_

/* libopenarc includes */
#include "arc.h"

/* prototypes */
extern int arc_res_cancel __P((void *, void *));
extern void arc_res_close __P((void *));
extern int arc_res_init __P((void **));
extern int arc_res_nslist __P((void *, const char *));
extern int arc_res_query __P((void *, int, unsigned char *, unsigned char *,
                               size_t, void **));
extern int arc_res_waitreply __P((void *, void *, struct timeval *,
                                   size_t *, int *, int *));

#endif /* ! _ARC_DNS_H_ */
