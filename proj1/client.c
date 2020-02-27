/*
** client.c -- a stream socket client demo
** Reference: 	beej.us/guide/bgnet/examples/client.c
				Bryant, O'Hallaron, [Computer Systems: A Programmer's Perspective],
					Section 11.4, <The Sockets Interface>
*/

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <netdb.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include <arpa/inet.h>

#define CHUNK		800	// process unit bytes we can get at once

static unsigned long end_carry(unsigned long num);


/* get sockaddr, assume it is IPv4: */
void *get_in_addr(struct sockaddr *sa)
{
	return &(((struct sockaddr_in*)sa)->sin_addr);
}

/* calculate end-around carry */
static unsigned long end_carry(unsigned long num){
	unsigned long sum, carry;
	carry = (num >> 16);
	sum = num % (1<<16);
	sum += carry;

	return sum;
}

// Argument format: ./client -h 143.248.111.222 -p 1234 -o 0-k cake < test.txt > a.txt
int main(int argc, char *argv[])
{
	int sockfd, bytes_sent, numbytes;
	unsigned short op, len, ck_i, cksum_s, cksum_r_s;
	unsigned long cksum, cksum_r, len_l;
	char packet[CHUNK+17], buf[CHUNK+17];
	struct addrinfo hints, *servinfo, *p;

	if (argc != 9) {	/* Protocol violated */
	    exit(1);
	}

	/* Get a list of potential server addresses*/
	memset(&hints, 0, sizeof hints);
	hints.ai_family = AF_INET;			/* TODO: Local Unix or IPv4? */
	hints.ai_socktype = SOCK_STREAM;	/* Connections only */
	hints.ai_flags = AI_NUMERICSERV;	/* Using a numeric port arg. */

	/* Converts string representations of
	 * host addresses, service names, port #s
	 * into socket address structures.
	 */
	// TODO: check host(argv[2]) and port(argv[4]) follow Part #1 arg format
	if (strncmp(argv[1], "-h", 2) || strncmp(argv[3], "-p", 2) ||
		(getaddrinfo(argv[2], argv[4], &hints, &servinfo) != 0)) {
		return 1;						/* Protocol violated */
	}

	/* Encrypt or decrypt? */
	if (!strncmp(argv[5], "-o", 2)){
		if (!strncmp(argv[6], "0", 1))
			op = 0;
		else if (!strncmp(argv[6],"1",1))
			op = 1;
		else 							/* Protocol violated */
			exit(1);
	}
	else 								/* Protocol violated */
		exit(1);

	/* Keyword */
	if (strncmp(argv[7], "-k", 2) || (strlen(argv[8]) != 4))
		exit(1);


	/* loop through all the results and connect to the first we can */
	for(p = servinfo; p != NULL ; p = p->ai_next) {
		/* Create a socket descriptor */
		if ((sockfd = socket(p->ai_family, p->ai_socktype,
				p->ai_protocol)) == -1)
			continue;					/* Socket failed, try the next */

		if (connect(sockfd, p->ai_addr, p->ai_addrlen) == -1) {
			close(sockfd);				/* Connect failed, try the next */
			continue;
		}

		break;							/* Success */
	}

	if (p == NULL) {					/* All connects failed */
		return 2;
	}

	freeaddrinfo(servinfo); 			// all done with this structure

	memset(packet, 0, sizeof(char)*16);
	while (fgets(packet+16, CHUNK+1, stdin) != NULL){
		/* wrap op */
		memset(packet, op>>8, 1);
		memset(packet+1, op & 0xff, 1);

		/* initialize checksum */
		memset(packet+2, 0, 2);			
		
		/* wrap keyword */
		strncpy(packet+4, argv[8], 4);
		
		/* wrap length */
		len = (unsigned short)strlen(packet+16) + 16;
		memset(packet+8, 0, 6);
		memset(packet+14, (len>>8) & 0xff, 1);
		memset(packet+15, len & 0xff, 1);

		/* Calculate checksum */
		// op
		cksum = (packet[0]<<8) + packet[1];
		// keyword, len, data
		ck_i = 4;
		while (ck_i < len) {
			cksum += ((packet[ck_i]<<8) + packet[ck_i+1]);
			cksum = end_carry(cksum);
			ck_i += 2;
		}
		cksum %= (1<<16);
		// one's complement
		cksum_s = ~((unsigned short)cksum);

		// wrap checksum
		memset(packet+2, (cksum_s>>8) & 0xff, 1);
		memset(packet+3, cksum_s & 0xff, 1);

		// TODO: receive continuity of kw?
		bytes_sent = send(sockfd, packet, len, 0);

		memset(buf, 0, sizeof(char)*(CHUNK+17));	// if fail, remove this part
		if ((numbytes = recv(sockfd, buf, CHUNK+16, 0)) == -1)
			exit(1);
		
		buf[numbytes] = '\0';
		/* stdout only if checksum correct */
		cksum_r = (buf[0]<<8) + buf[1];
		ck_i = 4; /*cksum_r = 0;*/
		while (ck_i < len) {
			cksum_r += ((buf[ck_i]<<8) + buf[ck_i+1]);
			cksum_r = end_carry(cksum_r);
			ck_i += 2;
		}
		cksum_r %= (1<<16);
		cksum_r_s = (unsigned short)cksum_r;

		if ((cksum_r_s + ((unsigned char)(buf[2])<<8) + (unsigned char)(buf[3])) == 65535){
			// cksum_r_s == 0xffff
			fputs(buf+16, stdout);
		}	

		memset(packet, 0, sizeof(char)*(CHUNK+17));

	}
	close(sockfd);
	return 0;
}

