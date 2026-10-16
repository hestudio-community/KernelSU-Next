#include <linux/compiler.h>
#include <linux/version.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 11, 0)
#include <linux/sched/signal.h>
#endif
#include <linux/slab.h>
#include <linux/task_work.h>
#include <linux/thread_info.h>
#include <linux/seccomp.h>
#include <linux/printk.h>
#include <linux/sched.h>
#include <linux/string.h>
#include <linux/types.h>
#include <linux/uaccess.h>
#include <linux/uidgid.h>

#include "policy/app_profile.h"
#include "policy/allowlist.h"
#include "policy/app_profile.h"
#include "hook/setuid_hook.h"
#include "klog.h" // IWYU pragma: keep
#include "manager/manager_identity.h"
#include "infra/seccomp_cache.h"
#include "supercall/supercall.h"
#include "hook/hook_manager.h"
#include "feature/kernel_umount.h"
#include "compat/kernel_compat.h"
#ifdef CONFIG_KSU_SUSFS
#include <linux/susfs_def.h>
#include "selinux/selinux.h"

extern struct work_struct susfs_extra_works;

static inline void ksu_handle_extra_susfs_work(void)
{
	if (work_pending(&susfs_extra_works))
		return;

	schedule_work(&susfs_extra_works);
}

/*
 * Mark the freshly spawned process (zygote child) for susfs:
 * - TIF_PROC_UMOUNTED makes sus_path/sus_mount/sus_map hiding effective for it.
 * - TIF_PROC_NO_SU marks processes that must never look like a su process.
 */
static void ksu_handle_zygote_setresuid_susfs(uid_t new_uid, bool is_zygote_next)
{
	if (is_isolated_process(new_uid) ||
	    (is_appuid(new_uid) && ksu_uid_should_umount(new_uid))) {
		susfs_set_current_proc_no_su();
		susfs_set_current_proc_umounted();
		if (is_zygote_next)
			susfs_set_current_proc_umounted_for_zygote_next();
		ksu_handle_extra_susfs_work();
		return;
	}

	/* Process is not umounted but root is not allowed for it either */
	if (!ksu_is_allow_uid_for_current(new_uid))
		susfs_set_current_proc_no_su();
}
#endif

int ksu_handle_setresuid(uid_t old_uid, uid_t new_uid)
{
    // we rely on the fact that zygote always call setresuid(3) with same uids

    pr_info("handle_setresuid from %d to %d\n", old_uid, new_uid);

    if (unlikely(is_uid_manager(new_uid))) {

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 10, 0)
        if (current->seccomp.mode == SECCOMP_MODE_FILTER && current->seccomp.filter) {
            ksu_seccomp_allow_cache(current->seccomp.filter, __NR_reboot);
        }
#else
		disable_seccomp();
#endif

#ifdef KSU_KPROBES_HOOK
        ksu_set_task_tracepoint_flag(current);
#endif

        pr_info("install fd for manager: %d\n", new_uid);
        ksu_install_fd();
        return 0;
    }

    if (ksu_is_allow_uid_for_current(new_uid)) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 10, 0)
        if (current->seccomp.mode == SECCOMP_MODE_FILTER && current->seccomp.filter) {
            ksu_seccomp_allow_cache(current->seccomp.filter, __NR_reboot);
        }
#else
		disable_seccomp();
#endif

#ifdef KSU_KPROBES_HOOK
		ksu_set_task_tracepoint_flag(current);
#endif
	} else {
#ifdef KSU_KPROBES_HOOK
		ksu_clear_task_tracepoint_flag_if_needed(current);
#endif
    }

    // Handle kernel umount
    ksu_handle_umount(old_uid, new_uid);

#ifdef CONFIG_KSU_SUSFS
    // Only zygote (and webview zygote) spawned processes inherit the ksu mounts
    if (current_uid().val == 0) {
        if (is_zygote(current_cred()))
            ksu_handle_zygote_setresuid_susfs(new_uid, false);
        else if (new_uid == WEBVIEW_ZYGOTE_UID)
            ksu_handle_zygote_setresuid_susfs(new_uid, true);
    }
#endif

    return 0;
}

void __init ksu_setuid_hook_init(void)
{
	ksu_kernel_umount_init();
}

void __exit ksu_setuid_hook_exit(void)
{
	pr_info("ksu_core_exit\n");
	ksu_kernel_umount_exit();
}