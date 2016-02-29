#include <stdio.h>
#include <sys/ioctl.h>
#include <getopt.h>
#include <fcntl.h>
#include <sys/file.h>
#include "defender.h"


struct rule rules[] = {
	{0, IP_ANY, PORT_ANY, "119.75.218.0/24", 80, PROTOCOL_ANY,  "eth0", TIME_ANY, ACT_PERMIT},
	{1, "119.75.218.0/24", 80, IP_ANY, PORT_ANY, PROTOCOL_ANY, "eth0", TIME_ANY, ACT_PERMIT},
};

static char *protocol[] = {"any", "tcp"};
static char *time_rule[] = {"any", "work"};
static char *act[] = {"reject", "permit"};
static char *filename = "rule";
static char *devicename = "/dev/myDevice";

int insert_rule();
int del_rule(int rule_position);
int load_to_kernel();
int store_to_file();
void print_rule();

int main()
{
	//insert_rule();
	load_to_kernel();
	//store_to_file();
	print_rule();
	return 0;
}

int insert_rule() {
	int kern_fd;

	if ((kern_fd = open(devicename, O_RDWR)) < 0) printf("%s open error\n", devicename);

	write(kern_fd, &rules[0], sizeof(struct rule), NULL);
	write(kern_fd, &rules[1], sizeof(struct rule), NULL);

	close(kern_fd);
	return 0;
}

int del_rule(int rule_position) {
	
	return 0;
}

int store_to_file() {
	int i;
	FILE *store_fd = NULL;
	int kern_fd;
	struct rule temp;

	if ((kern_fd = open(devicename, O_RDWR)) < 0) printf("%s open error\n", devicename);
	if ((store_fd = fopen(filename, "w" )) == NULL) printf("%s open error\n", filename);

	for (i=0;;i++) {
		temp.position = i;
		if (read(kern_fd, &temp, sizeof(struct rule), NULL)<0)
			break;
		if (fwrite(&temp, 1, sizeof(temp), store_fd) < 0)printf("write error!\n");
	}
	fclose(store_fd);
	close(kern_fd);
	return 0;
}

int load_to_kernel() {
	FILE *store_fd = NULL;
	int kern_fd;
	struct rule temp;

	if ((kern_fd = open(devicename, O_RDWR)) < 0) printf("%s open error\n", devicename);
	if ((store_fd = fopen(filename, "r" )) == NULL) printf("%s open error\n", filename);

	while(1) {
		fread(&temp, 1, sizeof(temp), store_fd);
		if (feof(store_fd)) break;
		write(kern_fd, &temp, sizeof(struct rule), NULL);
	}
	fclose(store_fd);
	close(kern_fd);
	return 0;
}

void print_rule() {
	int i;
	int kern_fd;
	struct rule temp;

	if ((kern_fd = open(devicename, O_RDWR)) < 0) printf("%s open error\n", devicename);

	for (i=0;;i++) {
		temp.position = i;
		if (read(kern_fd, &temp, sizeof(struct rule), NULL)<0)
			break;
		printf("%d, %20s, %d, %20s, %d, %s, %s, %s, %s\n", temp.position, temp.source_ip, temp.source_port,
			temp.dest_ip, temp.dest_port, protocol[temp.protocol], temp.interface, 
			time_rule[temp.time_rule], act[temp.act]);
	}
	close(kern_fd);
}