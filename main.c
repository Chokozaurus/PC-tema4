/*
 * main.c
 *
 *  Created on: May 8, 2012
 *      Author: tudalex
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

#include <sys/select.h>
#include <sys/time.h>
#pragma pack(push,1)
#include "dns_message.h"
unsigned int len = 0;

char * get_label(char * buff,  int pos)
{
	char * response = calloc(70, 1);
	int k = 0;
	while (buff[pos])
	{
		if ((buff[pos] & (3<<6)) == (3<<6)) //Pointer
		{
			unsigned short pointer;
			memcpy(&pointer, buff+pos, 2);
			pointer = ntohs(pointer);
			pointer = pointer & ((1<<14) -1);
			if (pos+2 > len)
				len = pos+2;
			pos = pointer;
		}
		int cnt = buff[pos];
		++pos;
		while (cnt--)
			response[k++] = buff[pos++];
		if (len < pos)
			len = pos;
		response[k++] = '.';
	}
	return response;
}
char * get_type(unsigned short int t)
{
// A		1	/* IPv4 address */
// NS		2	/* Authoritative name server */
// CNAME	5 	/* Canonical name for an alias */
// PTR		12 	/* Domain name pointer. */
// MX		15 	/* Mail exchange */


	switch(t){
	case 1: return strdup("A");
	case 2: return strdup("NS");
	case 5: return strdup("CNAME");
	case 12: return strdup("PTR");
	case 15: return strdup("MX");
	}
	return strdup("");
}

int main( int argc, char * argv[])
{
	if (argc < 3)
	{
		printf("Usage: %s domain type\n", argv[0]);
		return 0;
	}

	char send_buff[2048];
	char read_buff[2048];
	FILE * config_file = fopen("dns_servers.conf","r");
	if (config_file == NULL)
	{
		printf("You don't have a dns_servers.conf file.\n");
		return 0;
	}

	freopen("logfile","a", stdout);
	printf( "; Trying: %s %s\n\n", argv[1], argv[2]);
	memset(send_buff, 0, sizeof(send_buff));



	dns_header_t req;
	memset(&req, 0,  sizeof(dns_header_t));
	req.id = 1;
	req.rd = 1;
	req.tc = 0;
	req.opcode = 0; //To be changed for revere queries
	req.qdcount = htons(1);
	memcpy(send_buff, &req, sizeof(dns_header_t));
	len += sizeof(dns_header_t);


	char buff[255];
	memset(buff, 0, sizeof(buff));
	char host[255];
	if (strcmp("PTR", argv[2])==0)
	{
		//Ma folosesc de ntohl ca sa inversez IP-ul
		struct in_addr temp;
		inet_aton(argv[1], &temp);
		unsigned int t = ntohl(*(unsigned int*)&temp);
		temp = *(struct in_addr*)&t;



		sprintf(host,"%s.in-addr.arpa",inet_ntoa(temp) );
		memcpy(buff+1, host, sizeof(char) * strlen(host));
	} else
		memcpy(buff+1, argv[1], sizeof(char) * strlen(argv[1])); //Altfel doar copiez parametrul

	//Creez un label
	buff[0] = '.';
	int l = strlen(buff);
	char cnt = 0;
	int i;
	for ( i = l-1; i >=0; --i)
		if (buff[i] == '.')
			buff[i] = cnt, cnt = 0;
		else
			++cnt;

	//Setez tipul
	short int type;
	if (strcmp("A", argv[2]) == 0)
		type = htons(A);
	if (strcmp("NS", argv[2]) == 0)
			type = htons(NS);
	if (strcmp("MX", argv[2]) == 0)
			type = htons(MX);
	if (strcmp("CNAME", argv[2]) == 0)
			type = htons(CNAME);
	if (strcmp("PTR", argv[2]) == 0)
				type = htons(PTR);
	short int class = htons(1); //IN

	memcpy(send_buff+len, buff, l+1); //Label
	len+=l+1;
	memcpy(send_buff+len, &type, 2);  //Type
	len+=2;
	memcpy(send_buff+len, &class, 2); //Class
	len+=2;


	//Trimitem pachetul
	struct sockaddr_in serv_addr;
	char dns_server[256];
	while (fgets(dns_server, 256,config_file )!=NULL)
	{
		if (dns_server[0] == '#' || dns_server[0] =='\n' || dns_server[0]==' ')
		{
		//	fprintf(stderr, "Line: {%s} is not good.\n", dns_server);
			continue;
		}
		dns_server[strlen(dns_server)-1] = 0;
		serv_addr.sin_family = AF_INET;
		serv_addr.sin_port = htons(53);
		inet_aton(dns_server, &serv_addr.sin_addr);
		int nsock = socket(AF_INET,SOCK_DGRAM,0);
		if (nsock < 0)
				perror("ERROR opening socket");
		if (connect(nsock,(struct sockaddr*) &serv_addr,sizeof(serv_addr)) < 0)
					perror("ERROR connecting");
		send(nsock, &send_buff, len, 0);
		fd_set rfds;
		struct timeval tv;
		FD_SET(nsock, &rfds);
		tv.tv_sec = 5;
		tv.tv_usec = 0;
		int r = select(nsock+1, &rfds, NULL, NULL, &tv);
		if (r == -1)
			perror("Select did not work!\n");
		if (!r) //Timer triggered
		{
			fprintf(stderr,"server %s timed out\n", dns_server);
			close(nsock);
			continue;
		}


		//Citim headerul primit
		dns_header_t res;
		recv(nsock, &read_buff, 2048, 0);
		memcpy(&res, read_buff, sizeof(dns_header_t));
		if (res.rcode!=0)
		{
			fprintf(stderr,"Server %s did not give us an answer.\n", dns_server);
			continue;
		}
		//fprintf(stderr,"Recursion: %d\n", res.ra);
		//fprintf(stderr,"Responses: %d\n", ntohs(res.ancount));

		//Converting stuff back from network order
		unsigned short count[4];
		char section_name[4][64] = {"ANSWER SECTION", "AUTHORITY SECTION", "ADDITIONAL SECTION"};
		count[0] = ntohs(res.ancount);
		count[1] = ntohs(res.nscount);
		count[2] = ntohs(res.arcount);



		for (i = 0; i < 3; ++ i) //Pentru fiecare sectiune
		{
			if (count[i])
				printf(";; %s:\n", section_name[i]);

			while (count[i]--) //Pentru fiecare record din sectiune
			{
				char * label = get_label(read_buff, len);
				dns_rr_t op;

				memcpy(&op, read_buff+len, sizeof(dns_rr_t));

				len +=sizeof(dns_rr_t);
				op.type = ntohs(op.type);
				op.ttl = ntohl(op.ttl);
				op.class = ntohs(op.class);
				op.rdlength = ntohs(op.rdlength);
				unsigned int len_after = len+op.rdlength;
				switch (op.type)
				{
					case 1: { //A
						printf( "%s\tIN\tA\t%hhu.%hhu.%hhu.%hhu\n",label,  read_buff[len], read_buff[len+1], read_buff[len+2], read_buff[len+3] );
						break;
					}
					case 5:   //CNAME
					case 12:  //PTR
					case 2: { //NS
						char * ns_label  = get_label(read_buff,len);
						printf( "%s\tIN\t%s\t%s\n", label,get_type(op.type), ns_label );
						free(ns_label);
						break;
					}
					case 15: { //MX
						unsigned short pref;
						memcpy(&pref, read_buff+len, 2);
						len+=2;
						char * ns_label = get_label(read_buff, len);
						printf("%s\tIN\tMX\t%d\t%s\n", label, ntohs(pref), ns_label);
						free(ns_label);
						break;

					}
				}
				len  = len_after; //This is useful to bypass records that we don't know how to process.
				free(label);

			}

		}
		close(nsock);
		break; //Nu mai incercam si celelalte dns-uri

	}
	return 0;
}
#pragma pack(pop)
