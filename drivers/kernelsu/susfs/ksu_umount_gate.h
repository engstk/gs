/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __SUSFS_KSU_UMOUNT_GATE_H
#define __SUSFS_KSU_UMOUNT_GATE_H

#include <linux/cred.h>
#include <linux/sched.h>
#include <linux/types.h>

/* Set once, by ksu_umount_gate.c's init, from whether KernelSU's symbol was found: false = the gates
 * ask KernelSU, true = answer the pre-#34 way (uid >= 10000) without calling anything.  Read by the
 * gates, never recomputed, and never a loader parameter: the only thing that matters is one fact
 * about the device, and it is established where the module can still see the whole picture. */
extern bool susfs_ksu_umount_gate_off;

/* Defined in ksu_umount_gate.c: the one indirect call, through the address resolved at load. */
bool susfs_ksu_umount_ask(uid_t uid);

/* Upstream's susfs_is_current_proc_umounted_app(): app uid AND KernelSU would umount for it.  The
 * uid half is upstream's literal 10000; the flag half is the predicate that flag is set from, so a
 * su-granted app, the manager and a profile with "umount modules" off are not hidden from. */
static inline bool susfs_is_current_proc_umounted_app(void)
{
	uid_t uid = current_uid().val;

	if (uid < 10000)
		return false;
	if (READ_ONCE(susfs_ksu_umount_gate_off))
		return true;	/* nothing resolved to ask: hide from app uids, as this module did before #34 */

	return susfs_ksu_umount_ask(uid);
}

/* Upstream's susfs_is_current_proc_umounted(): the same umount answer WITHOUT the app-uid half,
 * which is what its UID_UMOUNTED_PROC rule scheme asks for (and what makes that scheme cover
 * init-derived processes too).  There is deliberately no uid fallback when KernelSU's symbol did
 * not resolve: there would be nothing to ask, and answering "true" would hide from every process
 * alive - false is what the upstream flag does on a kernel without the SUSFS patch anyway. */
static inline bool susfs_is_current_proc_umounted(void)
{
	if (READ_ONCE(susfs_ksu_umount_gate_off))
		return false;

	return susfs_ksu_umount_ask(current_uid().val);
}

int susfs_ksu_umount_gate_init(void);

#endif /* __SUSFS_KSU_UMOUNT_GATE_H */
