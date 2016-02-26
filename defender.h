#ifndef DEFENDER_H
#define DEFENDER_H

#define PROTOCOL_ANY 0
#define PROTOCOL_TCP 1

#define TIME_ANY 0
#define TIME_WORK 1

#define WORK_BEGIN 8
#define WORK_END 17
#define TIME_LAG 8

#define ACT_DEL 0
#define ACT_REJECT 1
#define ACT_PERMIT 2
#define ACT_CLEAR 3

#define  PORT_ANY 0
#define IP_ANY "\0"
#define IF_ANY "\0"

#define IP_SIZE 16
#define FULL_IP_SIZE 20
#define IF_SIZE 10



struct rule {
	int position;
	char source_ip[FULL_IP_SIZE];
	int source_port;
	char dest_ip[FULL_IP_SIZE];
	int dest_port;
	int protocol;
	char interface[IF_SIZE];
	int time_rule;
	int act;
	struct rule *next;
};

#endif