#ifndef DEFENDER_H
#define DEFENDER_H

#define PROTOCOL_ANY 0
#define PROTOCOL_TCP 1

#define TIME_ANY 0
#define TIME_WORK 1

#define ACT_DEL 0
#define ACT_REJECT 1
#define ACT_PERMIT 2
#define ACT_CLEAR 3

struct rule {
	int position;
	char source_ip[16];
	int source_port;
	char dest_ip[16];
	int dest_port;
	int protocol;
	int time;
	int act;
	struct rule *next;
};

#endif