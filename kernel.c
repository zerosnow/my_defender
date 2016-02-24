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

unsigned int hook_local_in(unsigned int hooknum,
		struct sk_buff **skb, 
		const struct net_device *in, 
		const struct net_device *out,
		int (*okfn)(struct sk_buff *)) 
{
	struct rule *cur_rule = rules_head;
	printk("in\n");
	while(cur_rule != NULL) {
		cur_rule = cur_rule->next;
	}
	return NF_ACCEPT;
}

unsigned int hook_local_out(unsigned int hooknum,
		struct sk_buff **skb, 
		const struct net_device *in, 
		const struct net_device *out,
		int (*okfn)(struct sk_buff *)) 
{
	struct rule *cur_rule = rules_head;
	printk("out\n");
	while(cur_rule != NULL) {
		cur_rule = cur_rule->next;
	}
	return NF_ACCEPT;
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
	printk("the device has been registered!\n");
	device_num = ret;
	printk("the virtual device's major number %d.\n", device_num);

	nfho_local_in.hook = hook_local_in;
	nfho_local_in.owner = NULL;
	nfho_local_in.pf = PF_INET;
	nfho_local_in.hooknum = NF_INET_LOCAL_IN;
	nfho_local_in.priority = NF_IP_PRI_FIRST;

	nfho_local_out.hook = hook_local_out;
	nfho_local_out.owner = NULL;
	nfho_local_out.pf = PF_INET;
	nfho_local_out.hooknum = NF_INET_LOCAL_OUT;
	nfho_local_out.priority = NF_IP_PRI_FIRST;

	nf_register_hook(&nfho_local_in);
	nf_register_hook(&nfho_local_out);
	printk("nf registered!\n");
	return 0;
}

static void kexec_test_exit(void)
{
	unregister_chrdev(device_num, devName);
	nf_unregister_hook(&nfho_local_in);
	nf_unregister_hook(&nfho_local_out);
	printk("unregister success!\n");
}

static int my_open(struct inode *inode, struct file *file)
{
	if (mutex) return -EBUSY;
	mutex = 1;//lock
	printk("open device success!\n");
	try_module_get(THIS_MODULE);
	return 0;
}

static int my_release(struct inode *inode, struct file *file)
{
	printk("Device released!\n");
	module_put(THIS_MODULE);
	mutex = 0;//unlock
	return 0;
}

static ssize_t my_read(struct file *file, char __user *user, size_t t, loff_t *f)
{
	int position = ((struct rule *)user)->position;
	struct rule *cur_rule = rules_head;
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
			printk("no rule can be del");
			return -EFAULT;
		}
		//如果只有一条规则则直接删除
		if (cur_rule->next == NULL) {
			rules_head = NULL;
			kfree(cur_rule);
		}
		if (position == 0) {
			rules_head = rules_head->next;
			kfree(cur_rule);
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
	}
	else {
		//如果要写入的位置超过了规则数则写入最后一个
		while(position--) {
			if (cur_rule->next != NULL)
				cur_rule = cur_rule->next;
			else
				break;
		}
		temp = (struct rule *)kmalloc(sizeof(struct rule), GFP_KERNEL);
		if (copy_from_user((char *)temp, user, t))
			return -EFAULT;
		temp->next = cur_rule->next;
		cur_rule->next = temp;
	}
	printk("%d, %s, %d, %s, %d\n", temp->position, temp->source_ip, temp->source_port,
		temp->dest_ip, temp->dest_port);
	while(temp->next != NULL) {
		temp = temp->next;
		temp->position++;
	}
	return t;
}

module_init(kexec_test_init);
module_exit(kexec_test_exit);


