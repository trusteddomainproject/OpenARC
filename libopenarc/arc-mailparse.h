/*
**  Copyright (c) 2004 Sendmail, Inc. and its suppliers.
**    All rights reserved.
**
**  Copyright (c) 2009, 2010, 2012, 2014, 2019, The Trusted Domain Project.
**    All rights reserved.
*/

#ifndef _ARC_MAILPARSE_H_
#define _ARC_MAILPARSE_H_

#ifdef __STDC__
# ifndef __P
#  define __P(x)  x
# endif /* ! __P */
#else /* __STDC__ */
# ifndef __P
#  define __P(x)  ()
# endif /* ! __P */
#endif /* __STDC__ */

/* prototypes */
extern int arc_mail_parse __P((unsigned char *line, unsigned char **user_out,
                               unsigned char **domain_out));
extern int arc_mail_parse_multi __P((unsigned char *line,
                                     unsigned char ***users_out,
                                     unsigned char ***domains_out));
#endif /* ! _ARC_MAILPARSE_H_ */
