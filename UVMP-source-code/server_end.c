#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
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
#define QUEUE   20
#define BUFFER_SIZE 1024*16
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


int server_sockfd;
struct sockaddr_in server_sockaddr;

int socketInit(){
	int conn, ret, on;
	struct sockaddr_in client_addr;
	socklen_t length = sizeof(client_addr);

	server_sockfd = socket(AF_INET,SOCK_STREAM, 0); 
	on = 1;
	ret = setsockopt( server_sockfd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on) );
	server_sockaddr.sin_family = AF_INET;
	server_sockaddr.sin_port = htons(MYPORT);
	server_sockaddr.sin_addr.s_addr = htonl(INADDR_ANY);
	if(bind(server_sockfd,(struct sockaddr *)&server_sockaddr,sizeof(server_sockaddr))==-1)
	{
		perror("bind");
		return -1;
	}

	if(listen(server_sockfd,QUEUE) == -1)
	{
		perror("listen");
		return -1;
	}
	
	conn = accept(server_sockfd, (struct sockaddr*)&client_addr, &length);
	if(conn<0)
	{
		perror("connect");
		return -1;
	}
	return conn;
	
}

int main()
{
	int conn;
	char *type_a_params;
	element_t alpha, beta;
	pairing_t pairing;
	char bufferdata[BUFFER_SIZE];
	bswabe_pub_t *pub;
	bswabe_cph_t *cph;
	bswabe_prv_t *prv;
	GByteArray buffer;
	
	char* sendbuf= (char*)malloc(1024*sizeof(char));
	memset(sendbuf, 0, sizeof(sendbuf));
	buffer.data = bufferdata;
	conn = socketInit();
	memset(buffer.data, 0, sizeof(buffer.data));
	
	type_a_params = strdup(TYPE_A_PARAMS);
	pairing_init_set_buf(pairing, type_a_params, strlen(type_a_params));
	element_init_GT(alpha, pairing);
	element_init_GT(beta, pairing);
	int len = recv(conn, buffer.data, BUFFER_SIZE,0);
	buffer.len = len;
	
	pub = bswabe_pub_unserialize(suck_file("PK"),1);
	prv = bswabe_prv_unserialize(pub, suck_file("SK_DST"), 1);
	cph = bswabe_cph_unserialize(pub, &buffer, 0);
	bswabe_dec(pub, prv, cph, alpha);
    	//element_printf("decrypted random %B\n", alpha);
	element_to_bytes(sendbuf, alpha);
	element_from_bytes(beta, sendbuf);
	send(conn, sendbuf, strlen(sendbuf), 0);
	close(conn);
	close(server_sockfd);
	return 0;
}
