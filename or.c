#include <linux/module.h>
#include <linux/lsm_hooks.h>
#include <linux/sched.h>


static int or_inode_permission(struct inode *inode, int mask) {


    const struct cred *cred = current_cred();

    return 0;
}

static struct security_hook_list or_hooks[] = {
    LSM_HOOK_INIT(inode_permission, or_inode_permission),
};

void __init or_add_hooks(void) {
    pr_info("OR:  Initializing.\n");
    int i = 0;
    for (i = 0; i<200; i++) {
        printk("%s\n", "<OR> ADD HOOKS");
    }
    security_add_hooks(or_hooks, ARRAY_SIZE(or_hooks), "or_inode_permission");
}

MODULE_LICENSE("GNU");