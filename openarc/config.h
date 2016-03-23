/*
**  Copyright (c) 2006-2008 Sendmail, Inc. and its suppliers.
**	All rights reserved.
**
**  Copyright (c) 2009-2012, 2015, The Trusted Domain Project.  All rights reserved.
**
*/

#ifndef _CONFIG_H_
#define _CONFIG_H_

#include "build-config.h"

/* system includes */
#include <sys/types.h>
#ifdef HAVE_STDBOOL_H
# include <stdbool.h>
#endif /* HAVE_STDBOOL_H */
#include <stdio.h>

/* types and things */
#define	CONFIG_TYPE_STRING	0
#define	CONFIG_TYPE_INTEGER	1
#define	CONFIG_TYPE_BOOLEAN	2
#define	CONFIG_TYPE_INCLUDE	3
#define	CONFIG_TYPE_DEPRECATED	4

struct config
{
	_Bool		cfg_bool;
	u_int		cfg_type;
	int		cfg_int;
	char *		cfg_name;
	char *		cfg_string;
	struct config *	cfg_next;
};

struct configdef
{
	char *		cd_name;
	u_int		cd_type;
	u_int		cd_req;
};

/* prototypes */
extern char *config_check __P((struct config *, struct configdef *));
extern unsigned int config_dump __P((struct config *, FILE *, const char *));
extern char *config_error __P((void));
extern void config_free __P((struct config *));
extern int config_get __P((struct config *, const char *, void *, size_t));
extern struct config *config_load __P((char *, struct configdef *,
                                       unsigned int *, char *, size_t, char **));
extern _Bool config_validname __P((struct configdef *, const char *));

#endif /* _CONFIG_H_ */
