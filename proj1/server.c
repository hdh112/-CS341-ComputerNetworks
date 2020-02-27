/*
** server.c -- a stream socket server demo
** Reference:	beej.us/guide/bgnet/examples/server.c
				Bryant, O'Hallaron, [Computer Systems: A Programmer's Perspective]
					Section 11.4, <The Sockets Interface>
*/

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/wait.h>
#include <signal.h>
#include <ctype.h>

#define BACKLOG 10	// how many pending connections queue will hold
#define CHUNK 800 // max number of bytes we can get at once 

static unsigned long end_carry(unsigned long num);

int k_i;			// encrypt or decrypt by this key index

void sigchld_handler(int s)
{
	(void)s; // quiet unused variable warning

	// waitpid() might overwrite errno, so we save and restore it:
	int saved_errno = errno;

	while(waitpid(-1, NULL, WNOHANG) > 0);

	errno = saved_errno;
}

/* calculate end-around carry */
static unsigned long end_carry(unsigned long num){
	unsigned long sum, carry;
	carry = (num >> 16);
	sum = num % (1<<16);
	sum += carry;

	return sum;
}

/* get sockaddr, assume it is IPv4: */
void *get_in_addr(struct sockaddr *sa)
{
	return &(((struct sockaddr_in*)sa)->sin_addr);
}

/* Encryption of each character, by Vigenere Cipher method */
char encrypt(char plain, unsigned short kw) {
	char encrypted;
	unsigned short carry;

	/* Ignore special char */
	if (plain < 'a' || plain > 'z')
		return plain;

	carry = plain + kw;
	if (carry > 122)	// goes over 'z'
		carry -= 26;
	encrypted = carry;
	k_i++;	k_i %= 4;

	return encrypted;
}

/* Decryption of each character, by Vigenere Cipher method */
char decrypt(char cipher, unsigned short kw) {
	char decrypted;

	/* Ignore special char */
	if (cipher < 'a' || cipher > 'z')
		return cipher;

	decrypted = cipher - kw;
	k_i++;	k_i %= 4;
	if (decrypted < 'a')
		decrypted = decrypted + 26;
	
	return decrypted;
}

int main(int argc, char *argv[])
{
	int sockfd, new_fd, numbytes;  // listen on sock_fd, new connection on new_fd
	char buf[CHUNK+17];
	char *ch;
	struct addrinfo hints, *servinfo, *p;
	struct sockaddr_storage their_addr; // connector's address information
	socklen_t sin_size;
	struct sigaction sa;
	int yes=1;
	char s[INET6_ADDRSTRLEN];
	unsigned short ck_i, cksum_r_s, op, i, k[4];
	unsigned long cksum_r;

	if (argc != 3) {					/* Protocol violated */
		exit(1);
	}

	memset(&hints, 0, sizeof hints);
	hints.ai_family = AF_INET;			/* TODO: Local Unix or IPv4? */
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_PASSIVE;		/* TODO: use my IP or any IP? */

	/* TODO: check port */
	if (strncmp(argv[1], "-p", 2) ||
		getaddrinfo(NULL, argv[2], &hints, &servinfo) != 0) {
		return 1;
	}

	/* loop through all the results and bind to the first we can */
	for(p = servinfo; p != NULL; p = p->ai_next) {
		/* Create a socket descriptor */
		if ((sockfd = socket(p->ai_family, p->ai_socktype,
				p->ai_protocol)) == -1)
			continue;					/* Socket failed, try the next */

		/* Eliminates "Addr already in use" error from bind */
		if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, (const void *)&yes,
				sizeof(int)) == -1)
			exit(1);

		/* Bind the descriptor to the address */
		if (bind(sockfd, p->ai_addr, p->ai_addrlen) == -1) {
			close(sockfd);				/* Bind failed, try the next */
			continue;
		}

		break;							/* Success */
	}

	freeaddrinfo(servinfo); 			// all done with this structure

	if (p == NULL)						/* No address worked */
		exit(1);

	if (listen(sockfd, BACKLOG) == -1) {
		close(sockfd);
		exit(1);
	}

	sa.sa_handler = sigchld_handler;	// reap all dead processes
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = SA_RESTART;
	if (sigaction(SIGCHLD, &sa, NULL) == -1) {
		// perror("sigaction");
		exit(1);
	}

	while(1) {			// main accept() loop
		sin_size = sizeof their_addr;
		new_fd = accept(sockfd, (struct sockaddr *)&their_addr, &sin_size);
		if (new_fd == -1)
			continue;

		if (!fork()) {		// this is the child process
			close(sockfd);	// child doesn't need the listener

			memset(buf, 0, sizeof(char)*(CHUNK+17));
			while ((numbytes = recv(new_fd, buf, CHUNK+16, 0)) != 0) {
				if ((numbytes == -1) || (numbytes < 16)){
					exit(1);
				}

				/* stdout only if checksum correct */
				cksum_r = (buf[0]<<8) + buf[1];
				ck_i = 4;
				while (ck_i < numbytes) {
					cksum_r += ((buf[ck_i]<<8) + buf[ck_i+1]);
					cksum_r = end_carry(cksum_r);
					ck_i += 2;
				}
				cksum_r %= (1<<16);
				cksum_r_s = (unsigned short)cksum_r;

				if ((cksum_r_s + ((unsigned char)(buf[2])<<8) + (unsigned char)(buf[3])) != 65535){
					// cksum_r_s != 0xfffff
					exit(1);				/* Checksum incorrect */
				}


				/* Encrypt or Decrypt? */
				if (buf[1] == 0)
					op = 0;
				else if (buf[1] == 1)
					op = 1;
				else
					exit(1);				/* Protocol violation */

				/* Receive & save keyword info */
				for (i = 4; i < 8; i++) {
					if (((buf[i] >= 65) && (buf[i] < 91)) ||
						((buf[i] >= 97) && (buf[i] < 123))){
						k[i-4] = ((unsigned short) tolower(buf[i])) - 97;
					}
					else
						exit(1);			/* Protocol violation */
				}

				/* Process string */
				k_i = 0;
				if (op == 0) {	// encrypt
					for (i = 16; i < numbytes; i++)
						buf[i] = encrypt((char)tolower(buf[i]), k[k_i]);
				}
				else {			// decrypt
					for (i = 16; i < numbytes; i++)
						buf[i] = decrypt((char)tolower(buf[i]), k[k_i]);
				}
				buf[numbytes] = '\0';

				/* Calculate checksum */
				// op
				cksum_r = (buf[0]<<8) + buf[1];
				// keyword, len, data
				ck_i = 4;
				while (ck_i < numbytes) {
					cksum_r += ((buf[ck_i]<<8) + buf[ck_i+1]);
					cksum_r = end_carry(cksum_r);
					ck_i += 2;
				}
				cksum_r %= (1<<16);
				// one's complement
				cksum_r_s = ~((unsigned short)cksum_r);

				// wrap checksum
				memset(buf+2, (cksum_r_s>>8) & 0xff, 1);
				memset(buf+3, cksum_r_s & 0xff, 1);

				if (send(new_fd, buf, numbytes+1, 0) == -1){
					close(new_fd);
					exit(1);
				}
				memset(buf, 0, sizeof(char)*(CHUNK+17));
				// close(new_fd);
				// exit(0);
			}
		}
		close(new_fd);  // parent doesn't need this
	}

	return 0;
}
