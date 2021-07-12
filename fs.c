// SPDX-License-Identifier: GPL-2.0-only
#include <linux/slab.h>
#include <linux/types.h>
#include <linux/bug.h>
#include <linux/socket.h>
#include <linux/lsm_hooks.h>
#include <linux/msg.h>
#include <linux/cred.h>
#include <linux/fs.h>
#include <linux/mm.h>
#include <linux/xattr.h>
#include <linux/security.h>

static ssize_t uob_write_pid(struct file *file, const char __user *buf,
				 size_t count, loff_t *ppos) {
    // TODO retrieve PID for buf and populate a list
    pr_info("UoB: PID added");
    return 0;
 }

 static const struct file_operations uob_pid_ops = {
	.write		= uob_write_pid,
  .llseek = generic_file_llseek,
};

static __init int init_uob_fs(void)
{
  struct dentry *uob_dir;

  pr_info("UoB fs: Initializing");
  /* create uob directory in /sys/kernel/security/ */
	uob_dir = securityfs_create_dir("uob", NULL);
  /* create pid file in /sys/kernel/security/uob/ with permission 0666
    and the operations we previously defined */
  securityfs_create_file("pid", 0666, uob_dir, NULL, &uob_pid_ops);

  return 0;
}

__initcall(init_uob_fs);

//
// Other stuff
//

// SPDX-License-Identifier: GPL-2.0-only
/* TODO identify needed include */

static int uob_socket_create(int family, int type,
				 int protocol, int kern)
{
  /* TODO:
    retrieve current process PID
    check if it is on the list or not
    return -EPERM if it is
  */
  pr_info("UoB hook: Socket created!");
  return 0;
}

/* data structure containing all our hooks */
static struct security_hook_list uob_hooks[] __lsm_ro_after_init = {
  LSM_HOOK_INIT(socket_create, uob_socket_create),
};

static __init int uob_init(void)
{
  pr_info("UoB hooks:  Initializing.\n");
  /* register our hooks */
  security_add_hooks(uob_hooks, ARRAY_SIZE(uob_hooks), "uob");
  return 0;
}

/* define our LSM */
DEFINE_LSM(uob) = {
	.name = "uob",
	.init = uob_init,
};

