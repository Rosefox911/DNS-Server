/*
 * CS3600, Spring 2013
 * Project 2 Starter Code
 * (c) 2013 Alan Mislove
 *
 */

#ifndef __3600DNS_H__
#define __3600DNS_H__


typedef struct { //structure for DNS Header (see handout page 2-3) 
 unsigned short id; 
 unsigned short rd :1; 
 unsigned short tc :1; 
 unsigned short aa :1; 
 unsigned short opcode :4; 
 unsigned short qr :1; 
 
 unsigned short rcode :4; 
 unsigned short z :3; 
 unsigned short ra :1; 
 unsigned short qdcount; 
 unsigned short ancount; 
 unsigned short nscount; 
 unsigned short arcount; 
} dnsheader;

typedef struct { //structure for DNS Question (see handout page 3-4)
	unsigned short qtype;
	unsigned short qclass;
}	dnsquestion;

typedef struct {
unsigned char *name;
unsigned short type;
unsigned short _class;
unsigned int ttl;
unsigned short rdlength;
unsigned char *rdata;
} dnsanswer;



#endif

