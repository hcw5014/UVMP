#include <string.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <glib.h>
#include <pbc.h>
#include <pbc_random.h>

#include "bswabe.h"
#include "common.h"
#include "policy_lang.h"

char* usage =
"Usage: setPolicy [OPTION ...] FILE [POLICY]\n"
"\n"
"OPTION:\n"
"	-h, --help		print this message\n\n"
"";

char* file  = 0;
char* policy = 0;

void
parse_args( int argc, char** argv )
{
	int i;

	for( i = 1; i < argc; i++ )
		if(      !strcmp(argv[i], "-h") || !strcmp(argv[i], "--help") )
		{
			printf("%s", usage);
			exit(0);
		}
		else if( !file )
		{
			file = argv[i];
		}
		else if( !policy )
		{
			policy = parse_policy_lang(argv[i]);
		}
		else
			die(usage);
	
	if( !policy )
		policy = parse_policy_lang(suck_stdin());
}

int
main( int argc, char** argv )
{
	GByteArray policybuf;

	parse_args(argc, argv);
	printf("file:	%s\n", file);
	printf("policy:	%s\n", policy);
	
	policybuf.data = (unsigned char*)policy;
	policybuf.len = strlen(policy);
	
	spit_file(file, &policybuf, 0);

	free(policy);	
	return 0;
}
