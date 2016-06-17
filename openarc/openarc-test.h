/*
**  Copyright (c) 2007 Sendmail, Inc. and its suppliers.
**	All rights reserved.
**
**  Copyright (c) 2009-2012, The Trusted Domain Project.  All rights reserved.
**
*/

#ifndef _TEST_H_
#define _TEST_H_

/* system includes */
#include <sys/param.h>
#include <sys/types.h>

/* libmilter includes */
#include <libmilter/mfapi.h>

/* libopenarc includes */
#include "arc.h"

/* PROTOTYPES */
extern int arcf_testfiles __P((ARC_LIB *, char *, int));

extern int arcf_test_addheader __P((void *, char *, char *));
extern int arcf_test_addrcpt __P((void *, char *));
extern int arcf_test_chgheader __P((void *, char *, int, char *));
extern int arcf_test_delrcpt __P((void *, char *));
extern void *arcf_test_getpriv __P((void *));
extern char *arcf_test_getsymval __P((void *, char *));
extern int arcf_test_insheader __P((void *, int, char *, char *));
extern int arcf_test_progress __P((void *));
extern int arcf_test_quarantine __P((void *, char *));
extern int arcf_test_setpriv __P((void *, void *));
extern int arcf_test_setreply __P((void *, char *, char *, char *));

#endif /* _TEST_H_ */
