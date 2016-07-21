#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <sys/shm.h>
#include <sys/time.h>
#include <string.h>
#include <unistd.h>
#include <glib.h>
#include <pbc.h>
#include <pbc_random.h>
#include "bswabe.h"
#include "common.h"
#include "policy_lang.h"

#define MYPORT  8887
#define BUFFER_SIZE 1024
#define TYPE_A_PARAMS \
"type a\n" \
"q 87807107996633125224377819847540498158068831994142082" \
"1102865339926647563088022295707862517942266222142315585" \
"8769582317459277713367317481324925129998224791\n" \
"h 12016012264891146079388821366740534204802954401251311" \
"822919615131047207289359704531102844802183906537786776\n" \
"r 730750818665451621361119245571504901405976559617\n" \
"exp2 159\n" \
"exp1 107\n" \
"sign1 1\n" \
"sign0 1\n"

char* usage =
"Usage: client [options] <Domain> <host>\n\n"
"Enabling User-Policy-Confined VM-vTPM Migration in Trusted Cloud Computing\n\n"
"Options:\n\n"
" -h, --help               print this message\n"
" -d, --debug		   print debug information\n";

int sock_cli;
struct sockaddr_in servaddr;
char *domain_id = 0;
char *host_ip = 0;
int debug = 0;

int socketInit(){
	int err_num, ret, on;
	sock_cli = socket(AF_INET,SOCK_STREAM, 0);
	on = 1;
	ret = setsockopt( sock_cli, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on) );
	memset(&servaddr, 0, sizeof(servaddr));
    	servaddr.sin_family = AF_INET;
    	servaddr.sin_port = htons(MYPORT);
    	servaddr.sin_addr.s_addr = inet_addr(host_ip);
    	
	err_num = connect(sock_cli, (struct sockaddr *)&servaddr, sizeof(servaddr));
	return err_num;
}

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
		else if( !strcmp(argv[i], "-d") || !strcmp(argv[i], "--debug") )
		{
			debug = 1;
		}
		else if( !domain_id )
		{
			domain_id = argv[i];
		}
		else if( !host_ip )
		{
			host_ip = argv[i];
		}
		else
			die(usage);

	if( !domain_id || !host_ip )
		die(usage);
}

GByteArray *P_Seal(char *policy_src_file, char *pk_file, element_t *m){
	char *policy;
	bswabe_pub_t *pub;
	bswabe_cph_t *cph;	
	GByteArray *c;
	
	policy = suck_file_str(policy_src_file);
	pub = bswabe_pub_unserialize(suck_file(pk_file),1);
	cph = bswabe_enc(pub, *m, policy);
	c = bswabe_cph_serialize(cph);
	return c;
}

void P_Unseal(GByteArray *buf, char *pk_file, char *sk_file, element_t *m){
	bswabe_pub_t *pub;
	bswabe_cph_t *cph;
	bswabe_prv_t *prv;
	
	pub = bswabe_pub_unserialize(suck_file(pk_file),1);
	prv = bswabe_prv_unserialize(pub, suck_file(sk_file), 1);
	cph = bswabe_cph_unserialize(pub, buf, 1);
	bswabe_dec(pub, prv, cph, *m);
}

int main( int argc, char** argv  )
{
	struct timeval t;
	char *type_a_params;
	GByteArray *cph_buf;
	element_t alpha, beta_src, beta_dst;	
	pairing_t pairing;
	char xl_migrate[40] = "xl migrate ";
		
	parse_args(argc, argv);

	if (socketInit() < 0)
    	{
        	perror("connect");
        	exit(1);
    	}
	
	type_a_params = strdup(TYPE_A_PARAMS);
	pairing_init_set_buf(pairing, type_a_params, strlen(type_a_params));
	element_init_GT(alpha, pairing);
	element_init_GT(beta_dst, pairing);
	element_random(alpha);
	char* recvbuf= (char*)malloc(1024*sizeof(char));
        memset(recvbuf, 0, sizeof(recvbuf));
	printf("-------------------------> Stage 1 ABE-based Migration Attestation\n\n");
		gettimeofday(&t,NULL);
		printf("Time 1: %ld-%ld\n", (long)t.tv_sec, (long)t.tv_usec);
	cph_buf = P_Seal("policy.src", "PK", &alpha);	
	//element_printf("randnum:%B\n", *m);
	P_Unseal(cph_buf,"PK", "SK_SRC", &beta_src);
	if( !element_cmp(alpha, beta_src)  ){
		printf("*Outgoing Migration Attestation Success!\n\n");
		// the secondly seal operation
		element_random(alpha);
		cph_buf = P_Seal("policy.dst", "PK", &alpha);	
		send(sock_cli, cph_buf->data, cph_buf->len, 0);
		recv(sock_cli, recvbuf, 1024,0);
		element_from_bytes(beta_dst, recvbuf);
		if ( !element_cmp(alpha, beta_dst)){
			printf("*Incoming Migration Attestation Success! \n\n");
		gettimeofday(&t,NULL);
		printf("Time 2: %ld-%ld\n", (long)t.tv_sec, (long)t.tv_usec);
			printf("-------------------------> Stage 2 VM-vTPM Transfer \n\n");
			strcat(xl_migrate, domain_id);	
			strcat(xl_migrate, " ");	
			strcat(xl_migrate, host_ip);	
			//printf("%s\n", xl_migrate);
			system(xl_migrate);
		}
		else
			printf("*Incomimg Migration Attestation Fail! \n\n");
		
	}else{
		printf("Outgoing Migration Attestatiuon Fail \n\n");
	}	

		gettimeofday(&t,NULL);
		printf("Time 3: %ld-%ld\n", (long)t.tv_sec, (long)t.tv_usec);
	printf("<---------------------------------------------------------------\n\n");
//		gettimeofday(&t,NULL);
//		printf("Start save: %ld\n", (long)t.tv_sec, (long)t.tv_usec);

//        	memset(sendbuf, 0, sizeof(sendbuf));
	free(recvbuf);
    	close(sock_cli);
    	return 0;
}
