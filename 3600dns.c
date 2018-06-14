/*
 * CS3600, Spring 2013
 * Project 3 Starter Code
 * (c) 2013 Alan Mislove
 *
 */

#include <math.h>
#include <ctype.h>
#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netdb.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "3600dns.h"

//Converts a domain (www.domain.com) into its proper DNS format (3www6domain3com)
void dnsparser(char *name) { 
char *token;
char buffer1[128];
token = strtok( name, "."); //Seperating host into tokens
int len = strlen(token);
sprintf( buffer1, "%c%s", len, token);
    while((token = strtok( NULL, "."))) { //If there is more than 1 "."it continues to go through them
        char buf[128];
        len = strlen(token);
        sprintf( buf, "%c%s", len, token); //Converts int to string since itoa is not supported by gcc.
        strcat( buffer1, buf);
    }
strcpy(name,buffer1);
return;
}

char *decompress(unsigned char *data, int *paj, unsigned char *res_buffer) {
  char *str = (char *)malloc( 1024);
  int istr = 0;
  str[istr] = 0;
  
  int aj = *paj;
  unsigned char *p = data + *paj;// using a short name
 

  int pointerflag = 0; // is used to keep track of the fact whether we have seen the pointer yet; helps to track the number of bytes that have been read in the main dns message   
  while( *p) {
    if( *p >= 0xc0) { // this means it is a pointer, two leftmost bits set
      int start = p[1]; //  + ((p[0]<<2) << 6);
      //printf("*p = %d start = %d\n", *p, start);
      p = res_buffer + start; 
      if( !pointerflag) {
        aj = aj + 2;
      }
      pointerflag = 1;
    } else {
      int len = p[0];
      memcpy( str + istr, p + 1, len);
      istr = istr + len;
      if(p[len+1]) { // means itis not ending, so we need to add  a dot
        str[istr++] = '.';
      }
      if(!pointerflag) { 
        aj = aj + len + 1;
      }
      p = p + len + 1;
    }
  } 

  str[istr] = 0;
  *paj = aj; 
  return str;
}
/**
 * This function will print a hex dump of the provided packet to the screen
 * to help facilitate debugging.  In your milestone and final submission, you 
 * MUST call dump_packet() with your packet right before calling sendto().  
 * You're welcome to use it at other times to help debug, but please comment those
 * out in your submissions.
 *
 * DO NOT MODIFY THIS FUNCTION
 *
 * data - The pointer to your packet buffer
 * size - The length of your packet
 */
static void dump_packet(unsigned char *data, int size) {
    unsigned char *p = data;
    unsigned char c;
    int n;
    char bytestr[4] = {0};
    char addrstr[10] = {0};
    char hexstr[ 16*3 + 5] = {0};
    char charstr[16*1 + 5] = {0};
    for(n=1;n<=size;n++) {
        if (n%16 == 1) {
            /* store address for this line */
            snprintf(addrstr, sizeof(addrstr), "%.4x",
               ((unsigned int)p-(unsigned int)data) );
        }
            
        c = *p;
        if (isprint(c) == 0) {
            c = '.';
        }

        /* store hex str (for left side) */
        snprintf(bytestr, sizeof(bytestr), "%02X ", *p);
        strncat(hexstr, bytestr, sizeof(hexstr)-strlen(hexstr)-1);

        /* store char str (for right side) */
        snprintf(bytestr, sizeof(bytestr), "%c", c);
        strncat(charstr, bytestr, sizeof(charstr)-strlen(charstr)-1);

        if(n%16 == 0) { 
            /* line completed */
            printf("[%4.4s]   %-50.50s  %s\n", addrstr, hexstr, charstr);
            hexstr[0] = 0;
            charstr[0] = 0;
        } else if(n%8 == 0) {
            /* half line: add whitespaces */
            strncat(hexstr, "  ", sizeof(hexstr)-strlen(hexstr)-1);
            strncat(charstr, " ", sizeof(charstr)-strlen(charstr)-1);
        }
        p++; /* next byte */
    }

    if (strlen(hexstr) > 0) {
        /* print rest of buffer if not empty */
        printf("[%4.4s]   %-50.50s  %s\n", addrstr, hexstr, charstr);
    }
}

int main(int argc, char *argv[]) {
  /**
   * I've included some basic code for opening a socket in C, sending
   * a UDP packet, and then receiving a response (or timeout).  You'll
   * need to fill in many of the details, but this should be enough to
   * get you started.
   */
char *ipaddress  = malloc(strlen("555:555:555.555:12345" + 1) * sizeof(char));
char *host  = malloc(strlen("555:555:555.555:12345" + 1) * sizeof(char)); //TODO free *host when I am done using it 
char *name  = malloc(strlen("555:555:555.555:12345" + 1) * sizeof(char)); //TODO free *host when I am done 
int port;
	if(argc != 3) {
	printf ("Format is @<server:port> <name>!\n");
	}
	else	{
		strcpy(host,++argv[1]);
		host = strtok(host,":"); //Seperates host from argc[1] string, dumping :58
		char *temp = strtok( NULL, ":");
		port = 53;
			if(temp != NULL) { 
				port = atoi(temp);
			}
		strcpy(ipaddress,host);
		strcpy(name,argv[2]);
		dnsparser(name); //passing over to be parsed in DNS format
	}

unsigned char buffer[65536]; //Buffer equal to max for an IP address
unsigned char res_buffer[65536]; //Buffer for recieving packet
unsigned char *qname;
dnsheader *dnssend = (dnsheader*)&buffer;
dnsquestion *dnsquest = NULL;

//Setting header
dnssend->id = htons(1337);
dnssend->qr = 0;
dnssend->opcode = htons(0);
dnssend->aa = 0;
dnssend->tc = 0;
dnssend->rd = 1;
dnssend->ra = 0;
dnssend->z = 0;
dnssend->rcode = htons(0);
dnssend->qdcount = htons(1);
dnssend->ancount = 0;
dnssend->nscount = 0;
dnssend->arcount = 0;

qname =(unsigned char*)&buffer[sizeof(dnsheader)];
strcpy((char *)qname,(char *)name); //passing domain name into qname. 

dnsquest = (dnsquestion*)&buffer[sizeof(dnsheader) + (strlen((char *)qname) + 1)];
dnsquest->qtype = htons(1);
dnsquest->qclass = htons(1);

int dnssend_len = sizeof(dnsheader) + strlen((char *)qname) + 1 + sizeof(dnsquestion);
dump_packet(buffer, dnssend_len);

// TODO send the DNS request (and call dump_packet with your request)
  
// first, open a UDP socket  
int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);

// next, construct the destination address
struct sockaddr_in out;
out.sin_family = AF_INET;
out.sin_port = htons(port); 
out.sin_addr.s_addr = inet_addr(ipaddress);

if (sendto(sock, (const char *)buffer, dnssend_len, 0,(const struct sockaddr *) &out, sizeof(out)) < 0) {
printf("Did not send packet!");
    return 0;
}

// wait for the DNS reply (timeout: 5 seconds)
struct sockaddr_in in;
socklen_t in_len;

// construct the socket set
fd_set socks;
FD_ZERO(&socks);
FD_SET(sock, &socks);

// construct the timeout
struct timeval t;
t.tv_sec = 5; //5 second timeout on requests;
t.tv_usec = 0;

int len; // will be set to the return value of recvfrom; as length of packet received
// wait to receive, or for a timeout
if (select(sock + 1, &socks, NULL, NULL, &t)) {
if ((len = recvfrom(sock, res_buffer, sizeof(res_buffer), 0, (struct sockaddr *)&in, &in_len)) < 0) {
    printf("Packet failed to send!\n");
    return 0;
}
} else {
    // a timeout occurred
    printf("NORESPONSE\n");
    return 0;
}

//printf("Received packet. Length = %d\n", len);
//dump_packet( res_buffer, len);
dnsheader *dnsreceive= (dnsheader*)&res_buffer;
memcpy(dnsreceive,res_buffer, sizeof(dnsheader)); //Saving results into dnsrecieve

//Converting back to host byte  order
dnsreceive->id = ntohs(dnsreceive->id);
dnsreceive->qdcount= ntohs(dnsreceive->qdcount);
dnsreceive->nscount = ntohs(dnsreceive->nscount);
dnsreceive->ancount = ntohs(dnsreceive->ancount);
dnsreceive->arcount = ntohs(dnsreceive->arcount);

//Checking for errors
if(dnsreceive->rcode == 1) { printf("ERROR\tFormat error!\n"); return 0;}
if(dnsreceive->rcode == 2) { printf("ERROR\tName server unable to process query!\n"); return 0;}
if(dnsreceive->rcode == 3) { printf("NOTFOUND\n"); return 0;}
if(dnsreceive->rcode == 4) { printf("ERROR\tName server does not support the requested kind of query!\n"); return 0;}
if(dnsreceive->rcode == 5) { printf("ERROR\tName server refuses to perform operation!\n"); return 0;}


unsigned char *questionsection = res_buffer + sizeof( dnsheader);
int qj = 0;
int qi;
//printf("dnsreceive->qdcount is %d\n",dnsreceive->qdcount);
for(qi = 0; qi < (dnsreceive->qdcount); qi++) {
while( questionsection[qj++]); // this while loop will find the last null byte at the end of he Qname for question
qj+=4; // add four bytes, two for qtype and 2 for qclass
}

//printf("sizeof question section is qj = %d\n", qj);
unsigned char *answersection = res_buffer + sizeof(dnsheader) + qj;
//dump_packet( answersection, len - sizeof(dnsheader) - qj); 

int aj = 0;
int ai;
for(ai = 0; ai < (dnsreceive->ancount); ai++) {
// the following function will traverse the qname for the answer, and modify aj as required
//printf("before decompress for qname aj = %d\n", aj);
char *str = decompress(answersection, &aj, res_buffer);
//printf("after; aj = %d\n", aj);

//printf("after qname in answer aj = %d qname = %s\n", aj, str);
int type = ntohs( *(short *)(answersection + aj));
aj = aj + 2;// for type
aj = aj + 2;// for class
aj = aj + 4;// for ttl

int rdlength = ntohs( *(short *)(answersection + aj));
aj = aj + 2; // for rdlength
//printf("type = %d aj = %d\n", type, aj);
if(type == 1){ // this means we were returned an IP address of 4 bytes
  int ip[4];
  printf("IP\t%d.%d.%d.%d\t%s\n", answersection[aj], answersection[aj+1], answersection[aj+2],answersection[aj+3], dnsreceive->aa? "auth":"nonauth");
  aj = aj + 4;// for four bytes of IP 
}
if(type == 5) {
  //printf("aj = %d\n", aj); 
  char *str = decompress( answersection, &aj, res_buffer);
  printf("CNAME\t%s\t%s\n", str, dnsreceive->aa?"auth":"nonauth");
  //printf("aj = %d\n", aj);
}
}
//FREEING malloced chars.
free(ipaddress);
free(host);
free(name);
// print out the result
  return 0;
}


