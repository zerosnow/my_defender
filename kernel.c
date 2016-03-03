#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/types.h>
#include <linux/errno.h>
#include <linux/uaccess.h>
#include <linux/kdev_t.h>
#include <linux/slab.h>
#include <linux/version.h>
#include <linux/skbuff.h>
#include <linux/netfilter.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/time.h>
#include <linux/rtc.h>
#include <linux/netfilter_ipv4.h>
#include "defender.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("leiyong");

static int my_open(struct inode *inode, struct file *file);
static int my_release(struct inode *inode, struct file *file);
static ssize_t my_read(struct file *file, char __user *user, size_t t, loff_t *f);
static ssize_t my_write(struct file *file, const char __user *user, size_t t, loff_t *f);

//用于与内核交互的静态变量
static struct rule *rules_head;
static int device_num = 0;
static int mutex = 0;//互斥用
static char *devName = "myDevice";
static char logs[MAX_LOG][100];
static int log_position = 0;
static bool loop = false;

//用于与netfilter的静态变量
static struct nf_hook_ops nfho_local_in;
static struct nf_hook_ops nfho_local_out;

struct file_operations pStruct = {
	.owner = THIS_MODULE,
	.open = my_open,
	.release = my_release,
	.read = my_read,
	.write = my_write,
};

//将字符ip转换为数字
unsigned int inet_addr(char *str) {
	int a, b, c, d;
	char arr[4];
	sscanf(str, "%d.%d.%d.%d", &a, &b, &c, &d);
	arr[0] = a; arr[1] = b; arr[2] = c; arr[3] = d;
	return *(unsigned int *)arr;
}

void arr_to_addr(const unsigned int arr, char *str) {
	sprintf(str, "%d.%d.%d.%d", arr & 0xff, (arr>>8) & 0xff, (arr>>16) & 0xff, (arr>>24) & 0xff);
}

//short大端小端存储互相转换
unsigned short translate(unsigned short source) {
	return ((source<<8) & 0xff00) | ((source>>8) & 0xff);
}

//查找子网掩码，如果有则将ip填入ip串，返回子网掩码，如果没有则返回负一
int mask_find(const char *str, char *ip) {
	int i = 0;
	int mask = 0;
	while(str[i] != '\0') {
		if (str[i] == '/') {
			ip[i] = '\0';
			while(str[++i] != '\0') {
				mask = mask*10 + str[i] - '0';
			}
			return mask;
		}
		ip[i] = str[i];
		i++;
	}
	return -1;
}

//检查skb中的ip是否在规则ip段中或与规则ip相等
bool check_ip_packet(struct sk_buff *skb, const char *source_ip, const char *dest_ip) {
	char source_sip[IP_SIZE], dest_sip[IP_SIZE];
	int source_mask, dest_mask;
	if (strcmp(source_ip, IP_ANY) != 0) {
		if ((source_mask = mask_find(source_ip, source_sip)) != -1) {//存在子网掩码
			if ((ip_hdr(skb)->saddr & (~((~0)<<source_mask))) != inet_addr(source_sip)) 
				return false;
		}
		else {//不存在子网掩码
			if (ip_hdr(skb)->saddr != inet_addr(source_sip))
				return false;
		}
	}
	if (strcmp(dest_ip, IP_ANY) != 0) {
		if ((dest_mask = mask_find(dest_ip, dest_sip)) != -1) {//存在子网掩码
			if ((ip_hdr(skb)->daddr & (~((~0)<<dest_mask))) != inet_addr(dest_sip)) 
				return false;
		}
		else {//不存在子网掩码
			if (ip_hdr(skb)->daddr != inet_addr(dest_sip))
				return false;
		}
	}
	return true;
}

//协议正确返回真，否则返回假
bool check_protocol(struct sk_buff *skb, int protocol) {
	if (!ip_hdr(skb)) return false;
	if (protocol == PROTOCOL_TCP && ip_hdr(skb)->protocol != IPPROTO_TCP) return false;
	if (protocol == PROTOCOL_UDP && ip_hdr(skb)->protocol != IPPROTO_UDP) return false;
	if (protocol == PROTOCOL_ICMP && ip_hdr(skb)->protocol != IPPROTO_ICMP) return false;
	return true;
}

//检查skb中的port是否与规则port相等
bool check_port(struct sk_buff *skb, int source_port, int dest_port) {
	struct tcphdr *thead;
	if (!(ip_hdr(skb))) return false;
	if ((ip_hdr(skb)->protocol != IPPROTO_TCP) && (ip_hdr(skb)->protocol != IPPROTO_UDP)) return true;
	thead = (struct tcphdr *)(skb->data + (ip_hdr(skb)->ihl * 4));
	if (source_port !=PORT_ANY && translate(thead->source) != source_port) return false;
	if (dest_port !=PORT_ANY && translate(thead->dest) != dest_port) return false;
	return true;
}

bool check_time(int time_rule) {
	struct timeval timex;
	struct rtc_time cur_time;
	if (time_rule == TIME_WORK) {
		do_gettimeofday(&timex);
		rtc_time_to_tm(timex.tv_sec, &cur_time);
		if (cur_time.tm_hour >= WORK_END - TIME_LAG || cur_time.tm_hour < WORK_BEGIN - TIME_LAG) {
			printk("now isnot work time!\n");
			return false;
		}
	}
	return true;
}

bool check_interface(const struct net_device *in, const struct net_device *out, char *interface, unsigned int hooknum) {
	if (strcmp(interface, IF_ANY) == 0)return true;	//表示interface任意
	switch(hooknum) {
		case NF_INET_LOCAL_OUT:
			if (out != NULL && strcmp(out->name, interface) == 0) return true;
			return false;
		case NF_INET_LOCAL_IN:
			if (in != NULL && strcmp(in->name, interface) == 0) return true;
			return false;
		default:
			return true;
	}
}

void print_reject(struct sk_buff *skb) {
	char saddr[20];
	char daddr[20];
	struct tcphdr *thead;
	if (!(ip_hdr(skb))) return ;
	arr_to_addr(ip_hdr(skb)->saddr, saddr);
	arr_to_addr(ip_hdr(skb)->daddr, daddr);
	switch(ip_hdr(skb)->protocol) {
		case IPPROTO_TCP:
		thead = (struct tcphdr *)(skb->data + (ip_hdr(skb)->ihl * 4));
		sprintf(logs[log_position++], "reject %s %d to %s %d tcp", saddr, translate(thead->source), daddr, translate(thead->dest));
		break;
		case IPPROTO_UDP:
		thead = (struct tcphdr *)(skb->data + (ip_hdr(skb)->ihl * 4));
		sprintf(logs[log_position++], "reject %s %d to %s %d udp", saddr, translate(thead->source), daddr, translate(thead->dest));
		break;
		case IPPROTO_ICMP:
		sprintf(logs[log_position++], "reject %s to %s icmp", saddr, daddr);
		break;
	}
	if (log_position >= MAX_LOG) {
		log_position = 0;
		loop = true;
	}
}

//同时用在本机的入口和出口的钩子函数
unsigned int hook_local(const struct nf_hook_ops *ops,
		struct sk_buff *skb, 
		const struct net_device *in, 
		const struct net_device *out,
		int (*okfn)(struct sk_buff *)) 
{
	struct rule *cur_rule = rules_head;
	if (!skb) return NF_DROP;
	while(cur_rule != NULL) {
		if ( (check_ip_packet(skb, cur_rule->source_ip, cur_rule->dest_ip) == true) &&
			 (check_protocol(skb, cur_rule->protocol) == true) &&
			 (check_port(skb, cur_rule->source_port, cur_rule->dest_port) == true) &&
			 (check_time(cur_rule->time_rule) == true) &&
			 (check_interface(in, out, cur_rule->interface, ops->hooknum) == true) ) {
			if (cur_rule->act == ACT_PERMIT) return NF_ACCEPT;
			else {
				print_reject(skb);
				return NF_DROP;
			}
		}
		cur_rule = cur_rule->next;
	}
	print_reject(skb);
	return NF_DROP;
}

//register module
static int kexec_test_init(void)
{
	int ret;

	ret = register_chrdev(device_num, devName, &pStruct);
	if (ret < 0) {
		printk("regist failure!\n");
		return -1;
	}
	device_num = ret;
	printk("the virtual device's major number %d.\n", device_num);

	nfho_local_in.hook = hook_local;
	nfho_local_in.owner = NULL;
	nfho_local_in.pf = PF_INET;
	nfho_local_in.hooknum = NF_INET_LOCAL_IN;
	nfho_local_in.priority = NF_IP_PRI_FIRST;

	nfho_local_out.hook = hook_local;
	nfho_local_out.owner = NULL;
	nfho_local_out.pf = PF_INET;
	nfho_local_out.hooknum = NF_INET_LOCAL_OUT;
	nfho_local_out.priority = NF_IP_PRI_FIRST;

	nf_register_hook(&nfho_local_in);
	nf_register_hook(&nfho_local_out);
	
	return 0;
}

static void kexec_test_exit(void)
{
	unregister_chrdev(device_num, devName);
	nf_unregister_hook(&nfho_local_in);
	nf_unregister_hook(&nfho_local_out);
}

static int my_open(struct inode *inode, struct file *file)
{
	if (mutex) return -EBUSY;
	mutex = 1;//lock
	try_module_get(THIS_MODULE);
	return 0;
}

static int my_release(struct inode *inode, struct file *file)
{
	module_put(THIS_MODULE);
	mutex = 0;//unlock
	return 0;
}

static ssize_t my_read(struct file *file, char __user *user, size_t t, loff_t *f)
{
	int position = ((struct rule *)user)->position;
	struct rule *cur_rule = rules_head;
	if (position == -1) {
		if (copy_to_user((char *)(((struct record *)user)->logs), (char *)logs, t))
			return -EFAULT;
		if (loop) {
			((struct record *)user)->begin = log_position;
			((struct record *)user)->end = log_position + 100;
		}
		else {
			((struct record *)user)->begin = 0;
			((struct record *)user)->end = log_position % 100;
		}
		return t;
	}
	if (cur_rule == NULL) {
		printk("sorry, there is no rule now\n");
		return -EFAULT;
	}
	//如果要读取的位置超过了规则数则读取最后一个
	while(position--) {
		cur_rule = cur_rule->next;
		if (cur_rule == NULL) 
			return -EFAULT;
	}
	if (copy_to_user(user, (char *)cur_rule, t))
		return -EFAULT;
	return t;
}
static ssize_t my_write(struct file *file, const char __user *user, size_t t, loff_t *f)
{
	int position = ((struct rule *)user)->position;
	int act = ((struct rule *)user)->act;
	struct rule *temp;
	struct rule *pre_cur_rule = NULL, *cur_rule = rules_head;
	if (act == ACT_CLEAR) {
		while(cur_rule != NULL) {
			pre_cur_rule = cur_rule;
			cur_rule = cur_rule->next;
			kfree(pre_cur_rule);
		}
		rules_head = NULL;
		return 1;
	}
	if (act == ACT_DEL) {
		if (cur_rule == NULL) {
			printk("no rule can be del\n");
			return -EFAULT;
		}
		//如果只有一条规则则直接删除
		if (cur_rule->next == NULL) {
			rules_head = NULL;
			kfree(cur_rule);
			return 1;
		}
		if (position == 0) {
			rules_head = rules_head->next;
			temp = cur_rule;
			while(temp->next != NULL) {
				temp = temp->next;
				temp->position--;
			}
			kfree(cur_rule);
			return 1;
		}
		else {
			//如果要删除的位置超过了规则数则删除最后一个
			while(position--) {
				if (cur_rule->next != NULL) {
					pre_cur_rule = cur_rule;
					cur_rule = cur_rule->next;
				}
				else
					break;
			}
			pre_cur_rule->next = cur_rule->next;
			temp = cur_rule;
			while(temp->next != NULL) {
				temp = temp->next;
				temp->position--;
			}
			kfree(cur_rule);
		}
		return 1;
	}
	if (position == 0 || cur_rule == NULL) {//插入链表首部
		temp = (struct rule *)kmalloc(sizeof(struct rule), GFP_KERNEL);
		if (copy_from_user((char *)temp, user, t))
			return -EFAULT;
		rules_head = temp;
		temp->next = cur_rule;
		temp->position = 0;
	}
	else {
		//如果要写入的位置超过了规则数则写入最后一个
		while(position--) {
			if (cur_rule != NULL) {
				pre_cur_rule = cur_rule;
				cur_rule = cur_rule->next;
			}
			else
				break;
		}
		temp = (struct rule *)kmalloc(sizeof(struct rule), GFP_KERNEL);
		if (copy_from_user((char *)temp, user, t))
			return -EFAULT;
		temp->next = cur_rule;
		pre_cur_rule->next = temp;
		temp->position = pre_cur_rule->position+1;
	}
	while(temp->next != NULL) {
		temp = temp->next;
		temp->position++;
	}
	return t;
}

module_init(kexec_test_init);
module_exit(kexec_test_exit);