#include <linux/module.h>
#include <linux/lsm_hooks.h>
#include <linux/sched.h>
#include <linux/security.h>
#include <linux/fs.h>
#include <linux/cred.h>



#define CONTROL_READ 0
#define CONTROL_WRITE 1

int pathlen(char* path) {
	int i = 0;
	while(path[i++] != 0);
	return i;
}

static int or_get_path(struct path* path, char** ret_pathname, char** ret_pathnamebuf) {
    	char *pathname = NULL, *pathnamebuf = NULL;
	int pathsize = PAGE_SIZE;
	int rc = 0;

	if (!path || !path->dentry)
		goto failure;

	pathnamebuf = kmalloc(pathsize, GFP_KERNEL);
	if (unlikely(!pathnamebuf)) {
		rc = -ENOMEM;
		pr_err("error %d at %d in %s\n", rc, __LINE__, __FILE__);
		goto failure;
	}
	if (path->dentry->d_op && path->dentry->d_op->d_dname)
		pathname = path->dentry->d_op->d_dname
			(path->dentry, pathnamebuf, pathsize - 1);
	else
		pathname = d_absolute_path(path, pathnamebuf,
					   pathsize - 1);
	if (IS_ERR(pathname)) {
		rc = -ENOMEM;
		pr_err("error %d and %ld at %d in %s\n",
		       rc, PTR_ERR(pathname), __LINE__, __FILE__);
		goto failure;
	}
failure:
	*ret_pathname = pathname;
	*ret_pathnamebuf = pathnamebuf;
	return rc;
}

int or_check_main(struct path* path, int cmd) {
	char *pathnamebuf = NULL;
	char *pathname;
	int rc = 0;
	int checkresult;
	int ret = 0;

	if (unlikely(!path) || unlikely(!path->dentry) ||
	    unlikely(!path->dentry->d_inode))
		goto failure;

	rc = or_get_path(path, &pathname, &pathnamebuf);
	if (rc != 0)
		goto failure;
	if (pathname != NULL && 
		pathlen(pathname) >= 21 &&
		pathname[1] == 'h' &&
		pathname[2] == 'o' &&
		pathname[3] == 'm' &&
		pathname[4] == 'e' &&
		pathname[5] == '/' &&
		pathname[6] == 's' &&
		pathname[7] == 'o' &&
		pathname[8] == 'b' &&
		pathname[9] == 'i' &&
		pathname[10] == 'e' &&
		pathname[11] == 'g' &&
		pathname[12] == '/' &&
		pathname[13] == 'r' &&
		pathname[14] == 'o' &&
		pathname[15] == 'o' &&
		pathname[16] == 't' &&
		pathname[17] == 'o' &&
		pathname[18] == 'n' &&
		pathname[19] == 'l' &&
		pathname[20] == 'y' &&
		pathname[21] == '/' 
		) {
			struct cred* cur_cred = current_cred();
			kuid_t rootUid;
			rootUid.val = 0;
			if (!uid_eq(cur_cred->uid, rootUid)) {
				// pr_info("attempt to access to %s by uid %d", pathname, cur_cred->uid.val);
				printk(KERN_WARNING, "OR : attempt to access to %s by uid %d", pathname, cur_cred->uid.val);
				ret = -1;
			}
	}


failure:
	kfree(pathnamebuf);

    return ret;
}

static int or_access_check(struct file* file, int mask) {

    if (!file) {
        return 0;
    }

    int ret;
    ret = 0;


    if (mask & MAY_READ) {
        ret = or_check_main (&file->f_path, CONTROL_READ);
        if (ret != 0) {
            goto END;
        }
    }

    if (mask & MAY_WRITE) {
        ret = or_check_main(&file->f_path, CONTROL_WRITE);
    }


    //


END:
    return ret;
}

static struct security_hook_list or_hooks[] = {
    LSM_HOOK_INIT(file_permission, or_access_check),
};

void __init or_add_hooks(void) {

    pr_info("OR:  Initializing.\n");

    security_add_hooks(or_hooks, ARRAY_SIZE(or_hooks), "or");
}

MODULE_LICENSE("GNU");