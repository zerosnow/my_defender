#include <gtk/gtk.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <getopt.h>
#include <fcntl.h>
#include <sys/file.h>
#include "defender.h"

void list_select(GtkList *gtklist, GtkWidget *child);
void update_list(GtkList *gtklist);
void insert(GtkWidget *widget, gpointer *data);
void delete(GtkWidget *widget, gpointer *data);
void clear(GtkWidget *widget, gpointer *data);
void store_to_file(GtkWidget *widget, gpointer *data);
void load_from_file(GtkWidget *widget, gpointer *data);
void closes(GtkWidget *widget, gpointer *data);

struct rule rules[] = {
	{0, IP_ANY, PORT_ANY, "119.75.218.0/24", 80, PROTOCOL_ANY,  "eth0", TIME_ANY, ACT_PERMIT},
	{1, "119.75.218.0/24", 80, IP_ANY, PORT_ANY, PROTOCOL_ANY, "eth0", TIME_ANY, ACT_PERMIT},
};

static char *protocol[] = {"any", "tcp"};
static char *time_rule[] = {"any", "work"};
static char *act[] = {"reject", "permit"};
static char *filename = "rule";
static char *devicename = "/dev/myDevice";

char *labels[] = {"position", "source_ip", "source_port", "dest_ip", "dest_port", "protocol", "interface", "time_rule", "act"};
int label_width[] = {10, 20, 10, 20, 10, 10, 10, 10, 10};
const int label_size = 9;

char *buttons[] = {"insert", "delete", "clear", "store to file", "load fromfile", "closes"};
void (*button_fun[])(GtkWidget *widget, gpointer *data) = {insert, delete, clear, store_to_file, load_from_file, closes};
const int button_size = 6;

static int cur_position;
GtkEntryBuffer *buffer[6];
GtkWidget *radio_button[4];

gint main(int argc, char *argv[]) 
{
	GtkWidget *window;
	GtkWidget *vbox, *button_box, *label_box, *input_box, *radio_box;
	GtkWidget *scrolled_window;
	GtkWidget *gtklist;
	GtkWidget *button;
	GtkWidget *label;
	GtkWidget *entry;
	GSList *radio_group;
	guint i;
	
	gtk_init(&argc, &argv);

	window = gtk_window_new(GTK_WINDOW_TOPLEVEL);
	gtk_window_set_title(GTK_WINDOW(window), "My Defender");
	gtk_window_set_position(GTK_WINDOW(window), GTK_WIN_POS_CENTER);
	gtk_signal_connect(GTK_OBJECT(window), "destroy", 
		GTK_SIGNAL_FUNC(gtk_main_quit), NULL);

	vbox = gtk_vbox_new(FALSE, 5);
	gtk_container_border_width(GTK_CONTAINER(vbox), 5);
	gtk_container_add(GTK_CONTAINER(window), vbox);
	gtk_widget_show(vbox);

	label_box = gtk_hbox_new(FALSE, 5);
	gtk_container_border_width(GTK_CONTAINER(label_box), 5);
	gtk_box_pack_start(GTK_BOX(vbox), label_box, FALSE, FALSE, 0);
	gtk_widget_show(label_box);

	for (i=0; i<label_size; i++) {
		label = gtk_label_new(labels[i]);
		gtk_label_set_width_chars(GTK_LABEL(label), label_width[i]);
		gtk_misc_set_alignment(GTK_MISC(label), 0.5, 0.5);
		gtk_box_pack_start(GTK_BOX(label_box), label, TRUE, TRUE, 0);
		gtk_widget_show(label);
	}

	scrolled_window = gtk_scrolled_window_new(NULL, NULL);
	gtk_widget_set_usize(scrolled_window, 250, 250);
	gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(scrolled_window),
		GTK_POLICY_AUTOMATIC, GTK_POLICY_AUTOMATIC);
	gtk_box_pack_start(GTK_BOX(vbox), scrolled_window, TRUE, TRUE, 0);
	gtk_widget_show(scrolled_window);

	gtklist = gtk_list_new();
	gtk_scrolled_window_add_with_viewport(GTK_SCROLLED_WINDOW(scrolled_window), gtklist);
	gtk_widget_show(gtklist);
	gtk_signal_connect(GTK_OBJECT(gtklist), "select_child", 
		GTK_SIGNAL_FUNC(list_select), NULL);

	input_box = gtk_hbox_new(FALSE, 5);
	//gtk_container_border_width(GTK_CONTAINER(input_box), 5);
	gtk_box_pack_start(GTK_BOX(vbox), input_box, FALSE, FALSE, 0);
	gtk_widget_show(input_box);

	for (i=0; i<label_size; i++) {
		if (i >= 0 && i <= 6) {
			buffer[i] = gtk_entry_buffer_new("\0", 20);
			entry = gtk_entry_new_with_buffer(buffer[i]);
			gtk_misc_set_alignment(GTK_MISC(entry), 0.5, 0.5);
			gtk_entry_set_width_chars(GTK_ENTRY(entry), label_width[i]-2);
			gtk_box_pack_start(GTK_BOX(input_box), entry, TRUE, TRUE, 0);
			gtk_widget_show(entry);
		}
		else {
			switch(i) {
				case 7:
				radio_box = gtk_vbox_new(TRUE, 5);
				gtk_box_pack_start(GTK_BOX(input_box), radio_box, TRUE, TRUE, 0);
				gtk_widget_show(radio_box);
				radio_button[0] = gtk_radio_button_new_with_label(NULL, time_rule[0]);
				radio_group = gtk_radio_button_get_group(GTK_RADIO_BUTTON(radio_button[0]));
				radio_button[1] = gtk_radio_button_new_with_label(radio_group, time_rule[1]);
				gtk_box_pack_start(GTK_BOX(radio_box), radio_button[0], TRUE, TRUE, 0);
				gtk_box_pack_start(GTK_BOX(radio_box), radio_button[1], TRUE, TRUE, 0);
				gtk_widget_show(radio_button[0]);
				gtk_widget_show(radio_button[1]);
				break;
				case 8:
				radio_box = gtk_vbox_new(TRUE, 5);
				gtk_box_pack_start(GTK_BOX(input_box), radio_box, TRUE, TRUE, 0);
				gtk_widget_show(radio_box);
				radio_button[2] = gtk_radio_button_new_with_label(NULL, act[0]);
				radio_group = gtk_radio_button_get_group(GTK_RADIO_BUTTON(radio_button[2]));
				radio_button[3] = gtk_radio_button_new_with_label(radio_group, act[1]);
				gtk_box_pack_start(GTK_BOX(radio_box), radio_button[2], TRUE, TRUE, 0);
				gtk_box_pack_start(GTK_BOX(radio_box), radio_button[3], TRUE, TRUE, 0);
				gtk_widget_show(radio_button[2]);
				gtk_widget_show(radio_button[3]);
				break;
				default: break;
			}
		}
	}

	button_box = gtk_hbox_new(TRUE, 5);
	gtk_container_border_width(GTK_CONTAINER(button_box), 5);
	gtk_box_pack_start(GTK_BOX(vbox), button_box, FALSE, FALSE, 0);
	gtk_widget_show(button_box);

	for (i=0; i<button_size; i++) {
		button = gtk_button_new_with_label(buttons[i]);
		gtk_box_pack_start(GTK_BOX(button_box), button, TRUE, TRUE, 0);
		gtk_signal_connect(GTK_OBJECT(button), "clicked", 
			GTK_SIGNAL_FUNC(button_fun[i]), (gpointer *)gtklist);
		gtk_widget_show(button);
	}

	gtk_widget_show(window);

	gtk_main();
	return 0;
}

void list_select(GtkList *gtklist, GtkWidget *child)
{
	cur_position = gtk_list_child_position(gtklist, child);
	g_print("list_select %d\n", cur_position);
}

void update_list(GtkList *gtklist)
{
	int kern_fd;
	struct rule temp;
	GtkWidget *list_item;
	GtkWidget *rule_box;
	GtkWidget *rule_label;
	guint i, j;
	gchar buffer[20];

	if ((kern_fd = open(devicename, O_RDWR)) < 0) printf("%s open error\n", devicename);

	gtk_list_clear_items(gtklist, 0 ,-1);

	for (i=0;;i++) {
		temp.position = i;
		if (read(kern_fd, &temp, sizeof(struct rule))<0)
			break;
		list_item = gtk_list_item_new();
		rule_box = gtk_hbox_new(FALSE, 5);
		gtk_container_border_width(GTK_CONTAINER(rule_box), 5);
		gtk_container_add(GTK_CONTAINER(list_item), rule_box);
		gtk_widget_show(rule_box);
		for (j=0; j<label_size; j++) {
			switch(j) {
				case 0:sprintf(buffer, "%d", temp.position);break;
				case 1:sprintf(buffer, "%s", temp.source_ip);break;
				case 2:sprintf(buffer, "%d", temp.source_port);break;
				case 3:sprintf(buffer, "%s", temp.dest_ip);break;
				case 4:sprintf(buffer, "%d", temp.dest_port);break;
				case 5:sprintf(buffer, "%s", protocol[temp.protocol]);break;
				case 6:sprintf(buffer, "%s", temp.interface);break;
				case 7:sprintf(buffer, "%s", time_rule[temp.time_rule]);break;
				case 8:sprintf(buffer, "%s", act[temp.act]);break;
			}
			rule_label = gtk_label_new(buffer);
			gtk_label_set_width_chars(GTK_LABEL(rule_label), label_width[j]);
			gtk_misc_set_alignment(GTK_MISC(rule_label), 0.5, 0.5);
			gtk_box_pack_start(GTK_BOX(rule_box), rule_label, TRUE, TRUE, 0);
			gtk_widget_show(rule_label);
		}
		gtk_container_add(GTK_CONTAINER(gtklist), list_item);
		gtk_widget_show(list_item);
	}
	g_print("update_list\n");
	close(kern_fd);
}

void insert(GtkWidget *widget, gpointer *data)
{
	int i;
	int kern_fd;
	struct rule temp;

	if ((kern_fd = open(devicename, O_RDWR)) < 0) printf("%s open error\n", devicename);
	// write(kern_fd, &rules[0], sizeof(struct rule));
	// write(kern_fd, &rules[1], sizeof(struct rule));
	if (strcmp(gtk_entry_buffer_get_text(buffer[1]), "\0") == 0) temp.position = 0;
	sscanf(gtk_entry_buffer_get_text(buffer[0]), "%d", &(temp.position));
	if (strcmp(gtk_entry_buffer_get_text(buffer[1]), "\0") == 0) strcpy(temp.source_ip, IP_ANY);
	else sscanf(gtk_entry_buffer_get_text(buffer[1]), "%s", temp.source_ip);
	if (strcmp(gtk_entry_buffer_get_text(buffer[2]), "\0") == 0) temp.source_port = 0;
	sscanf(gtk_entry_buffer_get_text(buffer[2]), "%d", &(temp.source_port));
	if (strcmp(gtk_entry_buffer_get_text(buffer[3]), "\0") == 0) strcpy(temp.dest_ip, IP_ANY);
	else sscanf(gtk_entry_buffer_get_text(buffer[3]), "%s", temp.dest_ip);
	if (strcmp(gtk_entry_buffer_get_text(buffer[4]), "\0") == 0) temp.dest_port = 0;
	sscanf(gtk_entry_buffer_get_text(buffer[4]), "%d", &(temp.dest_port));
	if (strcmp(gtk_entry_buffer_get_text(buffer[5]), "tcp") == 0) temp.protocol = PROTOCOL_TCP;
	else temp.protocol = PROTOCOL_ANY;
	if (strcmp(gtk_entry_buffer_get_text(buffer[6]), "\0") == 0) strcpy(temp.interface, "eth0");
	sscanf(gtk_entry_buffer_get_text(buffer[6]), "%s", temp.interface);
	if (gtk_toggle_button_get_active((GtkToggleButton *)radio_button[1])) temp.time_rule = TIME_WORK;
	else temp.time_rule = TIME_ANY;
	if (gtk_toggle_button_get_active((GtkToggleButton *)radio_button[2])) temp.act = ACT_REJECT;
	else temp.act = ACT_PERMIT;
	write(kern_fd, &temp, sizeof(struct rule));

	close(kern_fd);
	update_list((GtkList *)data);
	g_print("insert\n");
}

void delete(GtkWidget *widget, gpointer *data)
{
	int kern_fd;
	struct rule temp;

	if ((kern_fd = open(devicename, O_RDWR)) < 0) printf("%s open error\n", devicename);

	temp.act = ACT_DEL;
	temp.position = cur_position;
	write(kern_fd, &temp, sizeof(struct rule));

	close(kern_fd);

	g_print("delete\n");

	update_list((GtkList *)data);
}

void clear(GtkWidget *widget, gpointer *data)
{
	int kern_fd;
	struct rule temp;

	if ((kern_fd = open(devicename, O_RDWR)) < 0) printf("%s open error\n", devicename);

	temp.act = ACT_CLEAR;
	write(kern_fd, &temp, sizeof(struct rule));

	close(kern_fd);

	update_list((GtkList *)data);
	g_print("clear\n");
}

void store_to_file(GtkWidget *widget, gpointer *data)
{
	int i;
	FILE *store_fd = NULL;
	int kern_fd;
	struct rule temp;

	if ((kern_fd = open(devicename, O_RDWR)) < 0) printf("%s open error\n", devicename);
	if ((store_fd = fopen(filename, "w" )) == NULL) printf("%s open error\n", filename);

	for (i=0;;i++) {
		temp.position = i;
		if (read(kern_fd, &temp, sizeof(struct rule))<0)
			break;
		if (fwrite(&temp, 1, sizeof(temp), store_fd) < 0)printf("write error!\n");
	}
	fclose(store_fd);
	close(kern_fd);
	g_print("store_to_file\n");
}

void load_from_file(GtkWidget *widget, gpointer *data)
{
	FILE *store_fd = NULL;
	int kern_fd;
	struct rule temp;

	clear(widget, data);
	if ((kern_fd = open(devicename, O_RDWR)) < 0) printf("%s open error\n", devicename);
	if ((store_fd = fopen(filename, "r" )) == NULL) printf("%s open error\n", filename);

	while(1) {
		fread(&temp, 1, sizeof(temp), store_fd);
		if (feof(store_fd)) break;
		write(kern_fd, &temp, sizeof(struct rule));
	}
	fclose(store_fd);
	close(kern_fd);
	update_list((GtkList *)data);
	g_print("load_from_file\n");
}

void closes(GtkWidget *widget, gpointer *data)
{
	g_print("closes\n");
	gtk_main_quit();
}