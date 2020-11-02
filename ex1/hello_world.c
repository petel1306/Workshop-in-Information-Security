#include <linux/module.h>	/* Needed by all modules */
#include <linux/kernel.h>	/* Needed for KERN_INFO and for the Macros */

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Ori Petel");

static int __init my_module_init_function(void) {
	printk(KERN_INFO "Hello World!\n");
	return 0; /* if non-0 return means init_module failed */
}

static void __exit my_module_exit_function(void) {
	printk(KERN_INFO "Goodbye World!\n");
}

module_init(my_module_init_function);
module_exit(my_module_exit_function);