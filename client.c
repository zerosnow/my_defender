#include <stdio.h>
#include <sys/ioctl.h>
#include <getopt.h>
#include <fcntl.h>
#include "defender.h"


struct rule rules[] = {
	{0, IP_ANY, PORT_ANY, "119.75.218.0/24", 80, PROTOCOL_ANY,  "eth0", TIME_ANY, ACT_PERMIT},
	{0, "119.75.218.0/24", 80, IP_ANY, PORT_ANY, PROTOCOL_ANY, "eth0", TIME_ANY, ACT_PERMIT},
};


int main()
{
	int fd;
	int i;
	struct rule temp;
	fd = open("/dev/myDevice", O_RDWR);
	if (fd < 0) printf("open error\n");
	else printf("open success\n");
	write(fd, &rules[0], sizeof(struct rule), NULL);
	write(fd, &rules[1], sizeof(struct rule), NULL);
	for (i=0;;i++) {
		temp.position = i;
		if (read(fd, &temp, sizeof(struct rule), NULL)<0)
			break;
		printf("%d, %s, %d, %s, %d\n", temp.position, temp.source_ip, temp.source_port,
			temp.dest_ip, temp.dest_port);
	}
	return 0;
}