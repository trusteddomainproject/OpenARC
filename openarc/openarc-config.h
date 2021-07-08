/*
**  Copyright (c) 2016, 2017, The Trusted Domain Project.  All rights reserved.
*/

#ifndef _ARC_CONFIG_H_
#define _ARC_CONFIG_H_

#include "build-config.h"

/* system includes */
#include <sys/types.h>

/* macros */
#ifndef FALSE
# define FALSE	0
#endif /* ! FALSE */
#ifndef TRUE
# define TRUE	1
#endif /* ! TRUE */

/* config definition */
struct configdef arcf_config[] =
{
	{ "AuthservID",			CONFIG_TYPE_STRING,	FALSE },
	{ "AutoRestart",		CONFIG_TYPE_BOOLEAN,	FALSE },
	{ "AutoRestartCount",		CONFIG_TYPE_INTEGER,	FALSE },
	{ "AutoRestartRate",		CONFIG_TYPE_STRING,	FALSE },
	{ "Background",			CONFIG_TYPE_BOOLEAN,	FALSE },
	{ "BaseDirectory",		CONFIG_TYPE_STRING,	FALSE },
	{ "Canonicalization",		CONFIG_TYPE_STRING,	FALSE },
	{ "ChangeRootDirectory",	CONFIG_TYPE_STRING,	FALSE },
	{ "Domain",			CONFIG_TYPE_STRING,	TRUE },
	{ "EnableCoredumps",		CONFIG_TYPE_BOOLEAN,	FALSE },
	{ "FinalReceiver",		CONFIG_TYPE_BOOLEAN,	FALSE },
	{ "FixedTimestamp",		CONFIG_TYPE_STRING,	FALSE },
	{ "Include",			CONFIG_TYPE_INCLUDE,	FALSE },
	{ "InternalHosts",		CONFIG_TYPE_STRING,	FALSE },
	{ "KeepTemporaryFiles",		CONFIG_TYPE_BOOLEAN,	FALSE },
	{ "KeyFile",			CONFIG_TYPE_STRING,	TRUE },
	{ "MaximumHeaders",		CONFIG_TYPE_INTEGER,	FALSE },
	{ "MilterDebug",		CONFIG_TYPE_INTEGER,	FALSE },
	{ "Mode",			CONFIG_TYPE_STRING,	FALSE },
	{ "PeerList",			CONFIG_TYPE_STRING,	FALSE },
	{ "PidFile",			CONFIG_TYPE_STRING,	FALSE },
	{ "Selector",			CONFIG_TYPE_STRING,	TRUE },
	{ "SignatureAlgorithm",		CONFIG_TYPE_STRING,	FALSE },
	{ "SignHeaders",		CONFIG_TYPE_STRING,	FALSE },
	{ "OverSignHeaders",		CONFIG_TYPE_STRING,	FALSE },
	{ "SealHeaderChecks",		CONFIG_TYPE_STRING,	FALSE },
	{ "Socket",			CONFIG_TYPE_STRING,	FALSE },
	{ "SoftwareHeader",		CONFIG_TYPE_BOOLEAN,	FALSE },
	{ "Syslog",			CONFIG_TYPE_BOOLEAN,	FALSE },
	{ "SyslogFacility",		CONFIG_TYPE_STRING,	FALSE },
	{ "TemporaryDirectory",		CONFIG_TYPE_STRING,	FALSE },
	{ "UMask",			CONFIG_TYPE_INTEGER,	FALSE },
	{ "UserID",			CONFIG_TYPE_STRING,	FALSE },
	{ NULL,				(u_int) -1,		FALSE }
};

#endif /* _ARC_CONFIG_H_ */
