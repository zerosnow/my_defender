#include <gtk/gtk.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <getopt.h>
#include <fcntl.h>
#include <sys/file.h>

void list_select(GtkList *gtklist, GtkWidget *child);
void update_list(GtkList *gtklist);
void insert(GtkWidget *widget, gpointer *data);
void delete(GtkWidget *widget, gpointer *data);
void clear(GtkWidget *widget, gpointer *data);
void store_to_file(GtkWidget *widget, gpointer *data);
void load_from_file(GtkWidget *widget, gpointer *data);
void closes(GtkWidget *widget, gpointer *data);

char *protocol[] = {"any", "tcp", "udp", "icmp"};
char *time_rule[] = {"any", "work"};
char *act[] = {"reject", "permit"};
char *filename = "rule";
char *devicename = "/dev/myDevice";

char *labels[] = {"position", "source_ip", "source_port", "dest_ip", "dest_port", "protocol", "interface", "time_rule", "act"};
int label_width[] = {10, 20, 10, 20, 10, 10, 10, 10, 10};
const int label_size = 9;

char *buttons[] = {"insert", "delete", "clear", "store to file", "load fromfile", "closes"};
void (*button_fun[])(GtkWidget *widget, gpointer *data) = {insert, delete, clear, store_to_file, load_from_file, closes};
const int button_size = 6;

int cur_position;
GtkEntryBuffer *buffer[6];
GtkWidget *radio_button[4];