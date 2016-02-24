#include "linux/kernel.h"
#include "linux/module.h"
#include "linux/fs.h"
#include "linux/init.h"
#include "linux/types.h"
#include "linux/errno.h"
#include "linux/uaccess.h"
#include "linux/kdev_t.h"
#include "linux/slab.h"
#include "defender.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("leiyong");

static int my_open(struct inode *inode, struct file *file);
static int my_release(struct inode *inode, struct file *file);
static ssize_t my_read(struct file *file, char __user *user, size_t t, loff_t *f);
static ssize_t my_write(struct file *file, const char __user *user, size_t t, loff_t *f);

static struct rule *rules_head;
static int device_num = 0;
static int mutex = 0;//互斥用
static char *devName = "myDevice";

struct file_operations pStruct = {
	.owner = THIS_MODULE,
	.open = my_open,
	.release = my_release,
	.read = my_read,
	.write = my_write,
};

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
	printk("Or you can see it by using\n");
	printk(" ------more /proc/devices-------\n");
	printk("To talk to the driver, create a dev file with\n");
	printk(" mknod /dev/myDevice c %d 0 \n", device_num);
	printk("Use \"rmmod\" to remove the module\n");
	return 0;

}

static void kexec_test_exit(void)
{
	unregister_chrdev(device_num, devName);
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


