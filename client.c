#include <stdio.h>
#include <sys/ioctl.h>
#include <getopt.h>
#include <fcntl.h>
#include "defender.h"


struct rule rules = {0, "1.1.1.1", 1, "1.1.1.1", 1, PROTOCOL_ANY, TIME_ANY, ACT_REJECT};

int main()
{
	int fd;
	int i;
	struct rule temp;
	fd = open("/dev/myDevice", O_RDWR);
	if (fd < 0) printf("open error\n");
	else printf("open success\n");
	write(fd, &rules, sizeof(struct rule), NULL);
	write(fd, &rules, sizeof(struct rule), NULL);
	write(fd, &rules, sizeof(struct rule), NULL);
	for (i=0;;i++) {
		temp.position = i;
		if (read(fd, &temp, sizeof(struct rule), NULL)<0)
			break;
		printf("%d, %s, %d, %s, %d\n", temp.position, temp.source_ip, temp.source_port,
			temp.dest_ip, temp.dest_port);
	}
	rules.position = 1;
	rules.act = ACT_CLEAR;
	write(fd, &rules, sizeof(struct rule), NULL);
	for (i=0;;i++) {
		temp.position = i;
		if (read(fd, &temp, sizeof(struct rule), NULL)<0)
			break;
		printf("%d, %s, %d, %s, %d\n", temp.position, temp.source_ip, temp.source_port,
			temp.dest_ip, temp.dest_port);
	}
	close(fd);
	return 0;
}