// SPDX-License-Identifier: GPL-2.0
/*
 * susfs_open_redirect.c - redirect open of a target path to another path (SUSFS OPEN_REDIRECT feature), LKM port.
 * Hook: path_openat / do_sys_openat2 / do_filp_open are LTO-inlined into the syscall entry, so none can be kprobed; the
 * only out-of-line symbol on the user-open path is vfs_open(path, file) (measured: 123/123 hits for `cat`).  vfs_open is
 * the inode layer - d_inode is resolved - so rules match by (target_ino, target_dev) exactly like upstream.
 * Interrupt context: handlers must not sleep, so both paths are kern_path()'d at RULE-ADD time (proc write or
 * supercall, process context) and cached in the entry; a handler only matches (ino, dev) and swaps the pointer.  No
 * kretprobe needed - the cached references pin the files for the entry's lifetime, as upstream's re-walk does.
 * uid_scheme: enum UID_SCHEME (susfs_abi.h:67-73), all five values with upstream's predicates (susfs.c:941-964); two of
 * the five need state an LKM cannot read - see or_uid_matches() / or_in_su_domain().
 * Reverse disguise: upstream registers TWO hash entries per rule (susfs.c:844-863), the second with
 * reversed_lookup_only = true and the two pathnames swapped, and every "where did this file come from" reporter answers
 * from it - vfs_readlink() patch:510-548, do_proc_readlink() (/proc/<pid>/fd/N, exe, cwd, root) patch:1062-1083, fdinfo
 * seq_show() (mnt_id + ino) patch:1145-1217, show_map_vma() (maps dev:ino + name) patch:1257-1288, vfs_statfs()
 * (statfs/fstatfs) patch:2038-2056.  Gate: SUSFS_IS_INODE_OPEN_REDIRECT (susfs_def.h:148-151) = inode flag *and*
 * susfs_is_current_proc_umounted_app(), never the rule's uid_scheme - so even a scheme-0 rule is disguised for app
 * processes (or_reverse_visible() keeps that gate through susfs_is_current_proc_umounted_app()).
 * Reachability: none of those five is reachable from an LKM here (the first two and seq_show() are static; the
 * maps/fdinfo numbers are locals a kprobe cannot see).  Covered instead: point the caller at the *target's* path
 * (d_path(), vfs_statfs()), and where no shared helper exists rewrite the line the function already formatted, from a
 * kretprobe on its return - show_map_vma()'s line carries "maj:min ino" AND the name, both from the redirected file,
 * and the name cannot be reached that way (seq_file_path() -> seq_path() -> __d_path() is LTO-inlined: a probe on it
 * registers and never fires - measured).
 * Never silent: registration outcome and hit counts are logged and shown by /proc/susfs_open_redirect, because
 * registering only proves the symbol exists - this feature has hit that wall twice (show_vma_header_prefix, then
 * __d_path: both registered, both stayed at 0).
 *
 * /proc/susfs_open_redirect: add_open_redirect <target> <redirected> <uid_scheme> | del <target> | clear
 */
#include <linux/module.h>
#include <linux/kprobes.h>
#include <linux/fs.h>
#include <linux/cred.h>
#include <linux/namei.h>
#include <linux/dcache.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/uaccess.h>
#include "mount.h"		/* fs/mount.h: real_mount() -> mnt_id */
#include <linux/atomic.h>	/* reverse-disguise hit counters */
#include <linux/mm.h>		/* struct vm_area_struct (the maps reverse face) */
#include <linux/kdev_t.h>	/* MAJOR/MINOR, to render dev:ino the way proc does */
#include <linux/kernel.h>	/* scnprintf, for the same rendering */
#include <linux/security.h>	/* security_secctx_to_secid */
#include "susfs_abi.h"
#include "susfs_log.h"
#include "susfs.h"		/* susfs_expose_proc, sus_path_lsm_active */
#include "symbol_resolver.h"	/* find_kernel_symbol_exact */
#include "ksu_umount_gate.h"	/* susfs_is_current_proc_umounted_app (issue #34) */
#include "susfs_kprobe.h"

#define SUS_OR_MAX 64
/* The ABI fields are char[256]; matching that width stops a legal long path from being truncated into a rule for a
 * different path. */
#define OR_PATH_MAX 256

/* UID_SCHEME lives in susfs_abi.h, mirroring upstream susfs.h, where the enum sits next to the ABI structs. */

/* FUSE is the one filesystem upstream refuses outright (susfs.c:824-829): the daemon resolves the name itself, so a
 * kernel-side swap does nothing or makes the request happen twice.  susfs_def.h:49-51 carries the constant for the same
 * reason: neither <linux/magic.h> (absent from this tree) nor <uapi/linux/magic.h> defines it; fs/fuse/fuse_i.h does. */
#ifndef FUSE_SUPER_MAGIC
#define FUSE_SUPER_MAGIC 0x65735546
#endif

/* Upstream's app threshold (susfs_def.h:122-125: TIF_PROC_UMOUNTED && current_uid().val >= 10000) is not a macro any
 * more: both gates that used it now go through susfs_is_current_proc_umounted_app(), whose uid half is that same literal
 * 10000 (ksu_umount_gate.h) and whose other half is KernelSU's answer. */

/* SELinux context of the su/ksu domain, resolved to a sid at init.  Upstream gets the sid from KernelSU itself
 * (susfs_set_sid(KERNEL_SU_CONTEXT, &susfs_ksu_sid), 10_enable_susfs_for_ksu.patch:2496); an LKM has to resolve the
 * string.  "u:r:ksu:s0" is the SukiSU variant this device runs (KERNEL_SU_DOMAIN "ksu"), stock KernelSU uses
 * "u:r:su:s0" - override with susfs_guard_lkm.or_su_ctx.  Kept separate from sus_mount's su_ctx and avc_spoof's
 * avc_su_ctx: parameters are per name, and defaulting to the wrong domain must not change other features' gating. */
static char or_su_ctx[128] = "u:r:ksu:s0";
module_param_string(or_su_ctx, or_su_ctx, sizeof(or_su_ctx), 0644);

static u32 or_su_sid;

/* security_cred_getsecid() is an EXPORT_SYMBOL, but GKI's module symbol list is not guaranteed to
 * carry it, so it is resolved in kallsyms like sus_mount.c does.  The wrapper needs __nocfi: kCFI
 * validates the type hash at a call through a function pointer. */
static void (*or_cred_getsecid)(const struct cred *cred, u32 *secid);

struct sus_or_entry {
	char target_pathname[OR_PATH_MAX];
	char redirected_pathname[OR_PATH_MAX];
	unsigned long target_ino;
	dev_t target_dev;
	/* Reverse direction: the redirected inode is the lookup key, and target_path is what the reporters above show instead. */
	unsigned long redirected_ino;
	dev_t redirected_dev;
	/* Reverse direction, second number: fdinfo also prints mnt_id, and for the redirected file that is the mount the
	 * redirection really opened - which can differ from the target's (e.g. /system/etc/hosts vs
	 * /data/local/tmp/hosts).  Cached at add time: the reporter has only numbers to work with. */
	unsigned long target_mnt_id;
	/* Cached at add time, base references held for the entry's lifetime. */
	struct path target_path;
	struct path redirected_path;
	int uid_scheme;
	/* Set while the slot is being rewritten or has been deleted.  The reader checks this with
	 * READ_ONCE and the writer clears it LAST, so false means the rest of the entry is complete. */
	bool dead;
};

static struct sus_or_entry or_entries[SUS_OR_MAX];
static int nor;
static DEFINE_MUTEX(or_lock);

/* Reverse-disguise bookkeeping.  The counters are the only way to tell a hook that never fires from one that fires and
 * matches nothing: a kprobe registers against a symbol's out-of-line copy, which GKI's full LTO may leave with no live
 * call sites (measured: five probes registered, zero hits). */
static atomic_t or_rev_dpath_hits = ATOMIC_INIT(0);
static atomic_t or_rev_statfs_hits = ATOMIC_INIT(0);

/* Cached paths are per-entry, released once at unload (file-level note on the rule array).  The handlers run in interrupt
 * context with no lock and hand &e->redirected_path / &e->target_path straight to vfs_open()/d_path()/vfs_statfs(), which
 * read or path_get() it, so freeing an old path on replace/delete raced a concurrent open into a use-after-free (upstream
 * avoids that with SRCU plus a re-walk).  A "retired paths" side list was tried and removed: it duplicated the struct
 * path - one reference, two owners - so unload released it twice and the device died on rmmod.  A deleted rule keeps its
 * paths: dead entries are never reused, stay out of every lookup, and exit releases them. */
static void or_resolve_su_sid(void)
{
	int err;

	if (or_su_sid)
		return;
	if (!or_su_ctx[0])
		return;
	err = security_secctx_to_secid(or_su_ctx, strlen(or_su_ctx), &or_su_sid);
	if (err) {
		pr_warn("open_redirect: secctx_to_secid(%s) failed %d\n",
			or_su_ctx, err);
		or_su_sid = 0;
		return;
	}
	SUSFS_LOGI("open_redirect: su ctx \"%s\" -> sid %u (stock KernelSU uses \"u:r:su:s0\", override with susfs_guard_lkm.or_su_ctx)\n",
		or_su_ctx, or_su_sid);
}

/* Upstream susfs_is_current_ksu_domain() = (current_sid() == susfs_ksu_sid) (10_enable_susfs_for_ksu.patch:2484-2486);
 * current_sid() lives in SELinux's private objsec.h, so the LSM-agnostic security_cred_getsecid() is used instead. */
static __nocfi bool or_in_su_domain(void)
{
	u32 sid = 0;

	/* Unresolved symbol or unresolvable context: "not su" would be a guess, and for schemes 1/2 that guess redirects
	 * the very process the rule exists to spare.  or_add() refuses those schemes instead. */
	if (!or_cred_getsecid || !or_su_sid)
		return false;
	/* interrupt context: reading current->cred and walking the (static) LSM hook list never sleeps. */
	or_cred_getsecid(current_cred(), &sid);
	return sid == or_su_sid;
}

/* Upstream's reverse-disguise gate, verbatim in shape: SUSFS_IS_INODE_OPEN_REDIRECT (susfs_def.h:148-151) = flag bit AND
 * susfs_is_current_proc_umounted_app().  TIF_PROC_UMOUNTED is set by the SUSFS-patched KernelSU, which this kernel does not
 * have, so the app half is KernelSU's own ksu_uid_should_umount() answer (ksu_umount_gate.h, issue #34) rather than the
 * `uid >= 10000` proxy that also covered the manager and su-granted apps. */
static bool or_reverse_visible(void)
{
	return susfs_is_current_proc_umounted_app();
}

/* uid_scheme decision, mirroring upstream's switch in susfs_open_redirect_spoof_do_sys_openat() (susfs.c:941-964). */
static bool or_uid_matches(int scheme)
{
	switch (scheme) {
	case UID_NON_APP_PROC:			/* susfs.c:942-945 */
		return current_uid().val % 100000 < 10000;
	case UID_ROOT_PROC_EXCEPT_SU_PROC:	/* susfs.c:946-949 */
		return current_uid().val == 0 && !or_in_su_domain();
	case UID_NON_SU_PROC:			/* susfs.c:950-953 */
		return !or_in_su_domain();
	case UID_UMOUNTED_APP_PROC:		/* susfs.c:954-957 */
		/* Upstream: TIF_PROC_UMOUNTED && uid >= 10000 (susfs_def.h:122-125).  The flag is set
		 * by the SUSFS-patched KernelSU and this kernel has no such patch, so the same
		 * question is put to KernelSU by uid instead (ksu_umount_gate.h, issue #34).  What
		 * that substitution cannot reproduce is the flag's per-THREAD grain: a process of an
		 * umounted uid that was not forked from zygote answers yes here and no upstream. */
		return susfs_is_current_proc_umounted_app();
	case UID_UMOUNTED_PROC:			/* susfs.c:958-961 */
		/* Upstream: TIF_PROC_UMOUNTED alone, with no uid condition at all - which is how it
		 * covers init-derived processes.  Same substitution as above, and the uid half is
		 * deliberately NOT added here: that is the whole difference between this scheme and
		 * the one above. */
		return susfs_is_current_proc_umounted();
	default:				/* susfs.c:962-963 */
		return false;
	}
}

static struct sus_or_entry *or_find_by_path(const char *target)
{
	int i;

	for (i = 0; i < nor; i++) {
		if (READ_ONCE(or_entries[i].dead))
			continue;
		if (!strcmp(or_entries[i].target_pathname, target))
			return &or_entries[i];
	}
	return NULL;
}

static struct sus_or_entry *or_find_by_inode(unsigned long ino, dev_t dev)
{
	int i;

	for (i = 0; i < nor; i++) {
		/* dead is cleared LAST by the writer, so skipping dead entries also skips any entry whose
		 * fields are still being written. */
		if (READ_ONCE(or_entries[i].dead))
			continue;
		smp_rmb();
		if (or_entries[i].target_ino == ino &&
		    or_entries[i].target_dev == dev)
			return &or_entries[i];
	}
	return NULL;
}

/* Reverse direction: keyed on the redirected (really opened) inode, published like or_find_by_inode(). */
static struct sus_or_entry *or_find_by_redirected_inode(unsigned long ino, dev_t dev)
{
	int i;

	for (i = 0; i < nor; i++) {
		if (READ_ONCE(or_entries[i].dead))
			continue;
		smp_rmb();
		if (or_entries[i].redirected_ino == ino &&
		    or_entries[i].redirected_dev == dev)
			return &or_entries[i];
	}
	return NULL;
}

/* Reverse direction for the one caller that has only numbers: /proc/<pid>/fdinfo/N prints "mnt_id:\t<i>" and "ino:\t<j>"
 * for the file an fd points at and no device, so this lookup is by ino alone; two rules sharing that ino refuses to
 * answer (a missed disguise beats disguising an unrelated file).  On success: the target's ino and mount id (0 unknown). */
bool susfs_open_redirect_spoof_ids(unsigned long ino, unsigned long *out_ino,
				   unsigned long *out_mnt_id)
{
	struct sus_or_entry *e = NULL;
	int i, hits = 0;

	if (!ino || !out_ino || !or_reverse_visible())
		return false;
	for (i = 0; i < nor; i++) {
		if (READ_ONCE(or_entries[i].dead))
			continue;
		smp_rmb();
		if (or_entries[i].redirected_ino != ino)
			continue;
		e = &or_entries[i];
		if (++hits > 1)
			return false;
	}
	if (hits != 1)
		return false;
	*out_ino = e->target_ino;
	if (out_mnt_id)
		*out_mnt_id = e->target_mnt_id;
	return true;
}

/* Is `target` another rule's redirected path?  Upstream refuses to touch such a name (susfs.c:867-881): that name
 * belongs to the reverse entry of an existing rule, and replacing it would silently break that rule's disguise. */
static bool or_is_redirected_path(const char *target)
{
	int i;

	for (i = 0; i < nor; i++) {
		if (READ_ONCE(or_entries[i].dead))
			continue;
		if (!strcmp(or_entries[i].redirected_pathname, target))
			return true;
	}
	return false;
}

/* ---- forward: vfs_open(path, file) - swap the path on match ----
 * Runs in interrupt context: no sleeping, no kern_path here.  Upstream leaves the lookup loop entirely when the inode
 * matches but the scheme does not (goto out_srcu_read_unlock, susfs.c:945/949/953/957/961), so there a non-matching
 * entry also suppresses the remaining same-inode entries; here the first live (ino, dev) match is the only candidate -
 * the same outcome for distinct inodes, while rules sharing one inode (hard links) differ only in which entry wins
 * (upstream: newest hash_add_rcu first, here: slot order). */
static int or_vfs_open_pre(struct kprobe *kp, struct pt_regs *regs)
{
	const struct path *path = (const struct path *)regs->regs[0];
	struct inode *inode;
	struct sus_or_entry *e;

	/* IS_ERR_OR_NULL on the same principle as the sus_path name handlers: a kprobe runs before the
	 * callee, so a caller that leaves argument checking to it hands us an error pointer. */
	if (IS_ERR_OR_NULL(path) || !path->dentry)
		return 0;
	inode = d_backing_inode(path->dentry);
	if (!inode)
		return 0;

	e = or_find_by_inode(inode->i_ino, inode->i_sb->s_dev);
	if (!e)
		return 0;
	if (!or_uid_matches(e->uid_scheme))
		return 0;

	/* vfs_open does file->f_path = *path; do_dentry_open path_get()s it. */
	regs->regs[0] = (unsigned long)&e->redirected_path;
	return 0;
}

/* ---- reverse: d_path(path, buf, buflen) ----
 * Covers readlink("/proc/<pid>/fd/N"): proc_pid_readlink() -> do_proc_readlink() -> d_path(&path, tmp, PAGE_SIZE)
 * (fs/proc/base.c, upstream: patch:1062-1083).  Divergence: upstream replays the literal string given at add time, while
 * d_path() renders the canonical name of the cached target path in the *reader's* namespace - a rule registered through a
 * symlink (or another mount namespace) can read back differently.
 * The /proc/<pid>/maps NAME column is NOT here: show_map_vma() prints it with seq_file_path() -> seq_path(), which calls
 * __d_path() directly, never d_path() (fs/seq_file.c); a probe on __d_path registers cleanly and never fires here (full
 * LTO inlines the primitive; measured dpath_seq=0 while the maps line still named the redirected file), so the name is
 * rewritten out of the already-printed line - see or_maps_ret(). */
static bool or_dpath_swap(struct pt_regs *regs)
{
	const struct path *path = (const struct path *)regs->regs[0];
	struct inode *inode;
	struct sus_or_entry *e;

	if (!READ_ONCE(nor) || IS_ERR_OR_NULL(path) || !path->dentry)
		return false;
	if (!or_reverse_visible())
		return false;
	inode = d_backing_inode(path->dentry);
	if (!inode)
		return false;

	e = or_find_by_redirected_inode(inode->i_ino, inode->i_sb->s_dev);
	if (!e)
		return false;

	regs->regs[0] = (unsigned long)&e->target_path;
	return true;
}

static int or_dpath_pre(struct kprobe *kp, struct pt_regs *regs)
{
	if (or_dpath_swap(regs))
		atomic_inc(&or_rev_dpath_hits);
	return 0;
}

/* ---- reverse: vfs_statfs(path, buf) ----
 * Upstream answers statfs()/fstatfs() of the redirected file with the target's kstatfs snapshot (susfs.c:1029-1046, taken
 * with vfs_statfs() at add time, susfs.c:851); swapping in the cached target path computes the same from the live target. */
static int or_vfs_statfs_pre(struct kprobe *kp, struct pt_regs *regs)
{
	const struct path *path = (const struct path *)regs->regs[0];
	struct inode *inode;
	struct sus_or_entry *e;

	if (!READ_ONCE(nor) || IS_ERR_OR_NULL(path) || !path->dentry)
		return 0;
	if (!or_reverse_visible())
		return 0;
	inode = d_backing_inode(path->dentry);
	if (!inode)
		return 0;

	e = or_find_by_redirected_inode(inode->i_ino, inode->i_sb->s_dev);
	if (!e)
		return 0;

	atomic_inc(&or_rev_statfs_hits);
	regs->regs[0] = (unsigned long)&e->target_path;
	return 0;
}

static struct kprobe kp_or = {
	.symbol_name = "vfs_open",
	.pre_handler = or_vfs_open_pre,
};

static struct kprobe kp_or_dpath = {
	.symbol_name = "d_path",
	.pre_handler = or_dpath_pre,
};


static struct kprobe kp_or_vfs_statfs = {
	.symbol_name = "vfs_statfs",
	.pre_handler = or_vfs_statfs_pre,
};

/* ---- reverse face 3: the dev:ino columns of /proc/<pid>/maps (and smaps) ----
 * The first attempt put this on show_vma_header_prefix() - args 6 and 7 of that call ARE the two columns - and it
 * registered and never fired once (measured: the vma_hdr counter stayed 0 over every run; clang's full LTO leaves no
 * out-of-line copy).  So the already-formatted line is rewritten instead: its two numbers come from vma->vm_file, i.e.
 * from the REDIRECTED inode, and replacing the "<maj>:<min> <ino>" run with the target's keeps the line consistent with
 * the name face 1 (d_path) already disguises - without it a detector reads the target's name next to the redirected
 * file's device, which no file on this system can produce.  The run is rendered as fs/proc/task_mmu.c does it
 * (seq_put_hex_ll for major/minor: lowercase, min width 2; seq_put_decimal_ull for the ino), both surrounding spaces
 * included, so pgoff and name stay safe. */
static atomic_t or_rev_maps_hits = ATOMIC_INIT(0);
static atomic_t or_rev_maps_rewrites = ATOMIC_INIT(0);	/* the maj:min ino run */
static atomic_t or_rev_maps_names = ATOMIC_INIT(0);	/* the name column */

struct or_maps_args {
	struct seq_file *m;
	struct vm_area_struct *vma;
};

static int or_maps_entry(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct or_maps_args *a = (struct or_maps_args *)ri->data;

	a->m = (struct seq_file *)regs->regs[0];
	a->vma = (struct vm_area_struct *)regs->regs[1];
	return 0;
}

/* Replace the first occurrence of old[0..old_len) in the seq_file buffer with new[0..new_len); growing is allowed as
 * long as the buffer has room, and without room the line is left alone rather than truncated. */
static bool or_buf_replace(struct seq_file *m, const char *old, size_t old_len,
			   const char *new, size_t new_len)
{
	char *buf = m->buf;
	size_t count = m->count, i, pos = 0;

	if (!old_len || !new_len || old_len > count)
		return false;
	for (i = 0; i + old_len <= count; i++) {
		if (!memcmp(buf + i, old, old_len)) {
			pos = i;
			break;
		}
	}
	if (i + old_len > count)
		return false;
	if (new_len > old_len && count + (new_len - old_len) >= m->size)
		return false;
	if (new_len != old_len)
		memmove(buf + pos + new_len, buf + pos + old_len, count - (pos + old_len));
	memcpy(buf + pos, new, new_len);
	m->count = count - old_len + new_len;
	return true;
}

static int or_maps_ret(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	const struct or_maps_args *a = (const struct or_maps_args *)ri->data;
	struct seq_file *m = a->m;
	struct vm_area_struct *vma = a->vma;
	struct inode *inode;
	struct sus_or_entry *e;
	char old[48], new[48];
	int old_len, new_len;

	if (!susfs_ptr_plausible(m) || !susfs_ptr_plausible(vma) ||
	    !m->buf || !m->count || !vma->vm_file)
		return 0;
	if (!or_reverse_visible())
		return 0;
	inode = file_inode(vma->vm_file);
	if (!inode)
		return 0;

	e = or_find_by_redirected_inode(inode->i_ino, inode->i_sb->s_dev);
	if (!e)
		return 0;

	atomic_inc(&or_rev_maps_hits);

	old_len = scnprintf(old, sizeof(old), "%02x:%02x %lu",
			    (unsigned int)MAJOR(inode->i_sb->s_dev),
			    (unsigned int)MINOR(inode->i_sb->s_dev),
			    (unsigned long)inode->i_ino);
	new_len = scnprintf(new, sizeof(new), "%02x:%02x %lu",
			    (unsigned int)MAJOR(e->target_dev),
			    (unsigned int)MINOR(e->target_dev),
			    (unsigned long)e->target_ino);
	/* Keep the column width: the kernel padded the name out to a fixed column, so a shorter run would pull the name
	 * left - a line that does not line up with its neighbours is visible on its own. */
	while (new_len < old_len && new_len < (int)sizeof(new) - 1)
		new[new_len++] = ' ';
	if (old_len > 0 && new_len > 0 &&
	    or_buf_replace(m, old, (size_t)old_len, new, (size_t)new_len))
		atomic_inc(&or_rev_maps_rewrites);

	/* The name column as well: show_map_vma() prints it via seq_file_path()/seq_path()/__d_path(), and (see the d_path
	 * block above) a probe on that primitive never fires here - so the rendered name is matched as the REGISTERED
	 * redirected path, and a rule through a symlink or another mount namespace misses instead of mislabelling a file. */
	if (e->redirected_pathname[0] && e->target_pathname[0]) {
		size_t rlen = strlen(e->redirected_pathname);
		size_t tlen = strlen(e->target_pathname);

		if (or_buf_replace(m, e->redirected_pathname, rlen,
				   e->target_pathname, tlen))
			atomic_inc(&or_rev_maps_names);
	}
	return 0;
}

static struct kretprobe kr_or_maps = {
	.kp.symbol_name = "show_map_vma",	/* fs/proc/task_mmu.c */
	.entry_handler = or_maps_entry,
	.handler = or_maps_ret,
	.data_size = sizeof(struct or_maps_args),
	.maxactive = 16,
};
static bool or_maps_registered;

/* ---- reverse face 4: /proc/<pid>/fdinfo/N ----
 * fdinfo prints "ino:\t<i>" for the file an fd points at - for a rule, the REDIRECTED one - so a detector holding an fd
 * on the target is handed the inode of the file the redirection really opened.  Upstream rewrites it in the same function
 * it rewrites mnt_id in (susfs_open_redirect_spoof_seq_show, patch:1171-1200).
 * It belongs to THIS feature, not to sus_mount's: it has to fire as soon as one rule exists, whether or not the
 * mount-hiding switch is on.  Measured with the first version (a sus_mount seq_show kretprobe, registered only when that
 * feature is enabled): with a rule present and hide off, fdinfo kept naming the redirected inode and the probe had
 * entry=0.  fdinfo has no device column, so the lookup is by ino alone and refuses when two rules share a redirected ino;
 * state is per-instance (ri->data) because seq_show() may sleep in seq_printf() and the task can migrate CPUs. */
static atomic_t or_rev_fdinfo_hits = ATOMIC_INIT(0);
static atomic_t or_rev_fdinfo_rewrites = ATOMIC_INIT(0);

static int or_fdinfo_entry(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct seq_file **slot = (struct seq_file **)ri->data;

	*slot = (struct seq_file *)regs->regs[0];
	return 0;
}

/* Find `label` in the already formatted buffer and parse the decimal that follows it; false when
 * the label is absent or has no digits. */
static bool or_fdinfo_find_dec(struct seq_file *m, const char *label, size_t label_len,
			       size_t *out_pos, size_t *out_len, unsigned long *out_val)
{
	char *buf = m->buf;
	size_t count = m->count, i, pos = 0, len = 0;
	unsigned long v = 0;

	for (i = 0; i + label_len < count; i++) {
		if (!memcmp(buf + i, label, label_len)) {
			pos = i + label_len;
			break;
		}
	}
	if (!pos)
		return false;
	while (pos + len < count && len < 10 &&
	       buf[pos + len] >= '0' && buf[pos + len] <= '9') {
		v = v * 10 + (unsigned long)(buf[pos + len] - '0');
		len++;
	}
	if (!len)
		return false;
	*out_pos = pos;
	*out_len = len;
	*out_val = v;
	return true;
}

/* Write new_val over the len digits at pos, growing or shrinking as needed.  The replacement can be LONGER (measured:
 * 926498 -> 10166500 was refused by an earlier shrink-only version, so the hook reported hits with zero rewrites);
 * growing needs room in the seq_file buffer, and without room the line is left alone rather than truncated. */
static bool or_fdinfo_write_dec(struct seq_file *m, size_t pos, size_t len,
				unsigned long new_val)
{
	char digits[12];
	size_t count = m->count, i, n = 0;
	unsigned int v = (unsigned int)new_val;

	while (v) {
		digits[n++] = (char)('0' + v % 10);
		v /= 10;
	}
	if (!n)
		return false;
	if (n > len && count + (n - len) >= m->size)
		return false;
	for (i = 0; i < n / 2; i++) {
		char t = digits[i];

		digits[i] = digits[n - 1 - i];
		digits[n - 1 - i] = t;
	}
	if (n != len)
		memmove(m->buf + pos + n, m->buf + pos + len, count - (pos + len));
	memcpy(m->buf + pos, digits, n);
	m->count = count - len + n;
	return true;
}

static int or_fdinfo_ret(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct seq_file *m = *(struct seq_file **)ri->data;
	size_t pos, len;
	unsigned long old = 0, new_ino = 0, new_mnt = 0;
	int rewrites = 0;

	if (!m || (long)regs_return_value(regs) != 0)
		return 0;
	if (!m->buf || !m->count)
		return 0;
	if (!or_reverse_visible())
		return 0;

	atomic_inc(&or_rev_fdinfo_hits);

	/* The ino is the rule's key and the same rule knows the target's mount id, so one lookup answers both lines.  ino
	 * first: it sits after mnt_id in the line, so shrinking or growing it cannot move that one. */
	if (or_fdinfo_find_dec(m, "ino:\t", 5, &pos, &len, &old) &&
	    old && susfs_open_redirect_spoof_ids(old, &new_ino, &new_mnt) &&
	    new_ino != old && or_fdinfo_write_dec(m, pos, len, new_ino))
		rewrites++;

	/* mnt_id, when a rule matched.  sus_mount rewrites this same label from ITS table and both probes are on the same
	 * function, so for an fd that is both "inside a hidden mount" and "the redirected file" the two return handlers race
	 * for which id wins - cosmetic (both are ids the caller could have been shown), and invisible in either module alone. */
	if (new_mnt && or_fdinfo_find_dec(m, "mnt_id:\t", 8, &pos, &len, &old) &&
	    old != new_mnt && or_fdinfo_write_dec(m, pos, len, new_mnt))
		rewrites++;

	if (rewrites)
		atomic_inc(&or_rev_fdinfo_rewrites);
	return 0;
}

static struct kretprobe kr_or_fdinfo = {
	.kp.symbol_name = "seq_show",		/* fs/proc/fd.c */
	.entry_handler = or_fdinfo_entry,
	.handler = or_fdinfo_ret,
	.data_size = sizeof(struct seq_file *),
	.maxactive = 16,
};
static bool or_fdinfo_registered;

static bool or_registered;
static bool or_dpath_registered;
static bool or_statfs_registered;

/* Set by susfs_open_redirect_exit() while it holds or_lock; registration refuses afterwards.
 * The /proc node does NOT hold a module reference (proc_create(..., NULL, ...) takes no owner),
 * so a write that is already inside or_proc_write() can reach or_register() while the module is
 * being torn down: without this flag the forward probe would be registered again after
 * or_unregister() cleared or_registered, and its handler would outlive the module. */
static bool or_exiting;

/* The forward hook is the feature: a rule that cannot fire is worse than no rule, so its
 * registration failure is reported to the caller. */
static int or_register(void)
{
	int rc;

	if (or_exiting)
		return -ENODEV;
	if (or_registered)
		return 0;
	rc = register_kprobe(&kp_or);
	if (rc) {
		/* Every later rule retries this registration, and a failure that happened after the
		 * symbol was resolved leaves .addr set, so the retry would be refused with -EINVAL
		 * and the forward hook - the feature - could never come up - see susfs_kprobe.h. */
		susfs_kp_forget_addr(&kp_or);
		return rc;
	}
	or_registered = true;
	SUSFS_LOGI("susfs_open_redirect: hook installed (vfs_open)\n");
	return 0;
}

/* Reverse-disguise hooks: best effort.  The forward redirect is already live and each of these only closes one report
 * path, so a failure must not reject the rule - but never silent either: registering proves the symbol exists, not that
 * the kernel's call sites reach it (GKI's full LTO inlines across translation units), hence the hit counters read back
 * from /proc/susfs_open_redirect.  Called from the rule-management paths (process context, may sleep). */
static void or_register_reverse(void)
{
	int rc;

	if (or_exiting)
		return;

	if (!or_dpath_registered) {
		rc = register_kprobe(&kp_or_dpath);
		if (rc) {
			susfs_kp_forget_addr(&kp_or_dpath);
			pr_warn("open_redirect: register_kprobe(d_path) failed %d - readlink not disguised (or already inlined)\n",
				rc);
		} else {
			or_dpath_registered = true;
			SUSFS_LOGI("susfs_open_redirect: reverse hook installed (d_path)\n");
		}
	}

	if (!or_statfs_registered) {
		rc = register_kprobe(&kp_or_vfs_statfs);
		if (rc) {
			susfs_kp_forget_addr(&kp_or_vfs_statfs);
			pr_warn("open_redirect: register_kprobe(vfs_statfs) failed %d - statfs not disguised (or already inlined)\n",
				rc);
		} else {
			or_statfs_registered = true;
			SUSFS_LOGI("susfs_open_redirect: reverse hook installed (vfs_statfs)\n");
		}
	}
	if (!or_maps_registered) {
		rc = register_kretprobe(&kr_or_maps);
		if (rc) {
			susfs_krp_forget_addr(&kr_or_maps);
			pr_warn("open_redirect: register_kretprobe(show_map_vma) failed %d - the maps dev:ino stays the redirected file's\n",
				rc);
		} else {
			or_maps_registered = true;
			SUSFS_LOGI("susfs_open_redirect: reverse hook installed (show_map_vma)\n");
		}
	}
	if (!or_fdinfo_registered) {
		rc = register_kretprobe(&kr_or_fdinfo);
		if (rc) {
			susfs_krp_forget_addr(&kr_or_fdinfo);
			pr_warn("open_redirect: register_kretprobe(seq_show) failed %d - fdinfo names the redirected inode\n",
				rc);
		} else {
			or_fdinfo_registered = true;
			SUSFS_LOGI("susfs_open_redirect: reverse hook installed (seq_show/fdinfo)\n");
		}
	}
}

/* Caller MUST hold or_lock: disarming outside it is what let a concurrent or_register() put the
 * probes back after they were removed - and those probes would then point into a module that is
 * about to be freed.  susfs_open_redirect_exit() takes the lock and sets or_exiting before it
 * calls this, so no registration can slip in between. */
static void or_unregister(void)
{
	if (or_fdinfo_registered) {
		unregister_kretprobe(&kr_or_fdinfo);
		susfs_krp_forget_addr(&kr_or_fdinfo);
		or_fdinfo_registered = false;
	}
	if (or_maps_registered) {
		unregister_kretprobe(&kr_or_maps);
		susfs_krp_forget_addr(&kr_or_maps);
		or_maps_registered = false;
	}
	if (or_statfs_registered) {
		unregister_kprobe(&kp_or_vfs_statfs);
		susfs_kp_forget_addr(&kp_or_vfs_statfs);
		or_statfs_registered = false;
	}
	if (or_dpath_registered) {
		unregister_kprobe(&kp_or_dpath);
		susfs_kp_forget_addr(&kp_or_dpath);
		or_dpath_registered = false;
	}

	if (!or_registered)
		return;
	unregister_kprobe(&kp_or);
	susfs_kp_forget_addr(&kp_or);
	or_registered = false;
	SUSFS_LOGI("susfs_open_redirect: hook removed\n");
}

/* ---- /proc/susfs_open_redirect ---- */
static int or_proc_show(struct seq_file *m, void *v);
static int or_proc_open(struct inode *inode, struct file *file);
static ssize_t or_proc_write(struct file *file, const char __user *buf,
			     size_t len, loff_t *off);

static const struct proc_ops or_proc_ops = {
	.proc_open = or_proc_open,
	.proc_read = seq_read,
	.proc_write = or_proc_write,
	.proc_lseek = seq_lseek,
	.proc_release = single_release,
};

static struct proc_dir_entry *or_proc_entry;

int susfs_open_redirect_init(void)
{
	or_cred_getsecid =
		(void *)find_kernel_symbol_exact("security_cred_getsecid");
	if (!or_cred_getsecid)
		pr_warn("open_redirect: security_cred_getsecid not found - schemes 1/2 will be refused\n");
	or_resolve_su_sid();

	/* Only the /proc node is optional.  The vfs_open hook is registered by or_add() - i.e. by the supercall as well - so
	 * this gate must never return early and skip other work.  0777 so DAC passes and sus_path's LSM layer answers ENOENT;
	 * without that layer the node would be world-writable, so it is not created at all (see susfs_kstat_init()). */
	if (susfs_control_node_allowed()) {
		or_proc_entry = proc_create("susfs_open_redirect", 0777, NULL,
					    &or_proc_ops);
		if (!or_proc_entry)
			pr_warn("proc_create(susfs_open_redirect) failed\n");
	} else {
		SUSFS_LOGI("susfs_open_redirect: /proc node not created (expose_proc=%d lsm=%d)\n",
			(int)susfs_expose_proc, (int)sus_path_lsm_active());
	}

	SUSFS_LOGI("susfs_open_redirect: %d rules (hook %s, proc %d)\n", nor,
		or_registered ? "armed" : "lazy", or_proc_entry != NULL);
	return 0;
}

void susfs_open_redirect_exit(void)
{
	int i;

	/* "Stop accepting registrations" and "drop the probes" are one critical section: a /proc
	 * write holds no module reference, so it can be sitting inside or_proc_write() right now,
	 * and it would otherwise walk into or_register() after or_unregister() had cleared
	 * or_registered - re-arming kp_or with a handler that outlives the module. */
	mutex_lock(&or_lock);
	or_exiting = true;
	or_unregister();
	mutex_unlock(&or_lock);

	if (or_proc_entry) {
		proc_remove(or_proc_entry);
		or_proc_entry = NULL;
	}

	/* Nothing can reach these any more: the kprobes are already gone.  Every entry is released exactly once here - dead
	 * ones included, which is what makes "a deleted rule keeps its paths" safe. */
	for (i = 0; i < nor; i++) {
		path_put(&or_entries[i].redirected_path);
		or_entries[i].redirected_path.dentry = NULL;
		or_entries[i].redirected_path.mnt = NULL;
		path_put(&or_entries[i].target_path);
		or_entries[i].target_path.dentry = NULL;
		or_entries[i].target_path.mnt = NULL;
		or_entries[i].dead = true;
	}
	nor = 0;
}

static int or_proc_show(struct seq_file *m, void *v)
{
	int i;

	mutex_lock(&or_lock);
	if (nor == 0) {
		seq_puts(m, "(empty)\n");
	} else {
		for (i = 0; i < nor; i++) {
			if (READ_ONCE(or_entries[i].dead))
				continue;
			seq_printf(m, "%s -> %s uid=%d (ino=%lu dev=%lu mnt=%lu | rev: ino=%lu dev=%lu)\n",
				   or_entries[i].target_pathname,
				   or_entries[i].redirected_pathname,
				   or_entries[i].uid_scheme,
				   or_entries[i].target_ino,
				   (unsigned long)or_entries[i].target_dev,
				   or_entries[i].target_mnt_id,
				   or_entries[i].redirected_ino,
				   (unsigned long)or_entries[i].redirected_dev);
		}
	}
	/* "registered" is not "reached": a hook whose counter stays 0 across a real read means GKI inlined its call sites
	 * and that surface is NOT disguised - hence the counters below (fdinfo's surface and provenance are in the face-4
	 * block above).  mnt_id is NOT rewritten here: that id belongs to sus_mount's table. */
	seq_printf(m, "hooks: open=%d dpath=%d statfs=%d maps=%d fdinfo=%d | rev hits: dpath=%d statfs=%d maps=%d/%d/%d fdinfo=%d/%d | su_sid=%u\n",
		   or_registered, or_dpath_registered, or_statfs_registered,
		   or_maps_registered, or_fdinfo_registered,
		   atomic_read(&or_rev_dpath_hits),
		   atomic_read(&or_rev_statfs_hits),
		   atomic_read(&or_rev_maps_hits),
		   atomic_read(&or_rev_maps_rewrites),
		   atomic_read(&or_rev_maps_names),
		   atomic_read(&or_rev_fdinfo_hits),
		   atomic_read(&or_rev_fdinfo_rewrites),
		   or_su_sid);
	mutex_unlock(&or_lock);
	return 0;
}

static int or_proc_open(struct inode *inode, struct file *file)
{
	/* 0777 is deliberate (the ENOENT contract comes from sus_path's hidden set, not from the mode), so refuse non-root
	 * callers here too - see the note in susfs_enable_log.c's log_proc_open(). */
	if (current_uid().val != 0)
		return -ENOENT;
	return single_open(file, or_proc_show, NULL);
}

static int split_ws(char *buf, char **argv, int max)
{
	int argc = 0;
	char *p = buf;

	while (argc < max) {
		while (*p == ' ' || *p == '\t' || *p == '\n')
			p++;
		if (*p == '\0')
			break;
		argv[argc++] = p;
		while (*p && *p != ' ' && *p != '\t' && *p != '\n')
			p++;
		if (*p)
			*p++ = '\0';
	}
	return argc;
}

static int or_add(const char *target, const char *redirected, int scheme)
{
	struct sus_or_entry *e;
	struct path tp, rp;
	struct inode *ti, *ri;
	int rc;

	/* upstream susfs.c:792-796 */
	if (scheme < UID_NON_APP_PROC || scheme > UID_UMOUNTED_PROC)
		return -EINVAL;

	/* Both come from char[256] ABI fields (supercall) or a NUL-terminated command buffer (proc write); reject the
	 * unterminated case instead of letting strcmp()/kern_path() read past the struct or truncate a path into a rule. */
	if (!susfs_abi_path_ok(target, OR_PATH_MAX) ||
	    !susfs_abi_path_ok(redirected, OR_PATH_MAX))
		return -ENAMETOOLONG;

	rc = kern_path(target, LOOKUP_FOLLOW, &tp);
	if (rc)
		return rc;
	ti = d_backing_inode(tp.dentry);
	if (!ti) {
		path_put(&tp);
		return -ENOENT;
	}

	/* resolve redirected and CACHE it (base ref kept for entry lifetime) */
	rc = kern_path(redirected, LOOKUP_FOLLOW, &rp);
	if (rc) {
		path_put(&tp);
		return rc;
	}
	ri = d_backing_inode(rp.dentry);
	if (!ri) {
		path_put(&rp);
		path_put(&tp);
		return -ENOENT;
	}

	/* upstream susfs.c:824-829 - FUSE is refused outright, on either side, and rejecting is the whole handling: no
	 * silent rewrite, no partial rule.  (d_sb is the dentry's superblock: what upstream reads through inode->i_sb.) */
	if (tp.dentry->d_sb->s_magic == FUSE_SUPER_MAGIC ||
	    rp.dentry->d_sb->s_magic == FUSE_SUPER_MAGIC) {
		pr_warn("open_redirect: FUSE fs is not supported for open_redirect feature\n");
		path_put(&rp);
		path_put(&tp);
		return -EINVAL;
	}

	/* Schemes 1 and 2 are decisions about the KernelSU su domain.  Upstream always has that sid (KernelSU hands it
	 * over at setuid-hook setup), an LKM resolves the context itself - and if it does not resolve, "not in su domain"
	 * is true for the su process too, i.e. the one process the rule exists to spare would be redirected.  Refuse. */
	if (scheme == UID_ROOT_PROC_EXCEPT_SU_PROC ||
	    scheme == UID_NON_SU_PROC) {
		or_resolve_su_sid();
		if (!or_su_sid) {
			pr_warn("open_redirect: scheme %d needs a resolvable su domain - set or_su_ctx=u:r:su:s0 (currently \"%s\")\n",
				scheme, or_su_ctx);
			path_put(&rp);
			path_put(&tp);
			return -EOPNOTSUPP;
		}
	}

	/* Register the hooks BEFORE touching any entry: a rule that is listed but cannot fire (hook missing) silently does
	 * nothing while looking configured - worse than no rule at all. */
	rc = or_register();
	if (rc) {
		path_put(&rp);
		path_put(&tp);
		pr_warn("open_redirect: hook registration failed %d\n", rc);
		return rc;
	}
	or_register_reverse();

	/* upstream susfs.c:867-881: a name that another rule already uses as its redirected path belongs to that rule's
	 * reverse entry and must not be taken over. */
	e = or_find_by_path(target);
	if (!e && or_is_redirected_path(target)) {
		pr_warn("open_redirect: '%s' cannot be added because it is used for reversed lookup only\n",
			target);
		path_put(&rp);
		path_put(&tp);
		return -EINVAL;
	}

	/* Capacity is checked before the rewrite retires anything: with a full table, failing after the
	 * WRITE_ONCE(e->dead, true) below would return -ENOSPC *and* silently kill the redirection that
	 * was working.  A retired slot is never reused either: reuse would overwrite path fields a reader
	 * may still hold and discard the reference the dead entry owns.  Rules are configuration, so the
	 * array growing is fine. */
	if (nor >= SUS_OR_MAX) {
		path_put(&rp);
		path_put(&tp);
		return -ENOSPC;
	}

	if (e) {
		/* Rewriting a rule: mark the old entry dead and leave its paths alone - they stay for the module's life and
		 * unload releases each entry exactly once.  or_del() says why those fields must not be cleared while a reader
		 * may hold them; the entry-array note above covers the retired-list double-free measured on rmmod. */
		WRITE_ONCE(e->dead, true);
		smp_wmb();
		e = NULL;
	}

	e = &or_entries[nor++];
	/* Take the slot, then mark it "not published" before a single field lands in it.  The
	 * array is static, so a never-used slot already has dead == false - which means the
	 * WRITE_ONCE(e->dead, false) below is a no-op for a fresh slot and the "cleared LAST, so
	 * false means the rest of the entry is complete" invariant never held: nor++ publishes
	 * the slot while target_ino/target_dev are still zero, and those two fields are written
	 * BEFORE the two struct path fields.  A lockless reader (or_find_by_inode() and friends,
	 * called from the kprobes) could therefore match a real (ino, dev) and hand
	 * &e->redirected_path - still { NULL, NULL } - to vfs_open(), or &e->target_path to
	 * d_path()/vfs_statfs().  vfs_open() does d_backing_inode(path->dentry) immediately, so
	 * that is a NULL dereference in the kernel.  uid_scheme is also still 0 there, which is
	 * UID_NON_APP_PROC, so even root's own open of the target passes the gate. */
	WRITE_ONCE(e->dead, true);
	smp_wmb();		/* the flag must be visible before the fields it guards */
	strscpy(e->target_pathname, target, OR_PATH_MAX);
	strscpy(e->redirected_pathname, redirected, OR_PATH_MAX);
	e->target_ino = ti->i_ino;
	e->target_dev = ti->i_sb->s_dev;
	e->target_mnt_id = (unsigned long)real_mount(tp.mnt)->mnt_id;
	e->redirected_ino = ri->i_ino;
	e->redirected_dev = ri->i_sb->s_dev;
	e->redirected_path = rp;   /* transfer the cached references */
	e->target_path = tp;
	e->uid_scheme = scheme;
	smp_wmb();
	WRITE_ONCE(e->dead, false);	/* publish last: readers key off this */

	return 0;			/* both path references now belong to e */
}

/* Only the rules whose target path matches are dropped; the reverse entry is not
 * a separate object here, so it goes with the rule by definition. */
static void or_del(const char *target)
{
	struct sus_or_entry *e;

	e = or_find_by_path(target);
	if (!e)
		return;

	/* Dead, and that is all.  A reader that has already passed its `dead` check still holds a pointer to these fields and
	 * hands them to vfs_open()/d_path()/vfs_statfs(), which dereference path->dentry at once (fs/open.c:1033,
	 * fs/d_path.c:282, fs/statfs.c:90) - clearing them is a NULL-dereference oops any app can reach, since the control
	 * node is 0777 (or_uid_matches() is consulted later, in the probe).  So they stay, pinned until unload. */
	WRITE_ONCE(e->dead, true);
	smp_wmb();

	e->target_pathname[0] = '\0';
	e->redirected_pathname[0] = '\0';
}

/* Slots are never compacted (that array move was itself part of the race).  The kprobes stay registered for the whole
 * module lifetime: unregistering and re-registering them was observed to leave the hook silently gone after a burst of
 * add/del cycles, while an empty rule table already makes the lookups miss - so staying registered costs nothing. */

static ssize_t or_proc_write(struct file *file, const char __user *buf,
			     size_t len, loff_t *off)
{
	char cmd[640];
	char *argv[8];
	int argc, err;
	long scheme;

	/* Same gate as or_proc_open(): an fd opened before the opener dropped privileges must not become a way in. */
	if (current_uid().val != 0)
		return -ENOENT;

	if (len >= sizeof(cmd))
		len = sizeof(cmd) - 1;
	if (copy_from_user(cmd, buf, len))
		return -EFAULT;
	cmd[len] = 0;

	argc = split_ws(cmd, argv, 8);
	if (argc == 0)
		return len;

	mutex_lock(&or_lock);
	err = -EINVAL;

	if (!strcmp(argv[0], "add_open_redirect") && argc == 4) {
		if (kstrtol(argv[3], 10, &scheme))
			err = -EINVAL;
		else
			err = or_add(argv[1], argv[2], (int)scheme);
	} else if (!strcmp(argv[0], "del") && argc == 2) {
		or_del(argv[1]);
		err = 0;
	} else if (!strcmp(argv[0], "clear")) {
		int i;

		for (i = 0; i < nor; i++) {
			if (READ_ONCE(or_entries[i].dead))
				continue;
			or_del(or_entries[i].target_pathname);
		}
		err = 0;
	}

	mutex_unlock(&or_lock);

	if (err) {
		pr_warn("open_redirect proc write '%s' -> err %d\n", argv[0], err);
		return err;	/* surface the failure; success keeps returning len */
	}
	return len;
}

/* supercall: CMD_SUSFS_ADD_OPEN_REDIRECT */
void susfs_open_redirect_supercall(void __user **arg)
{
	struct st_susfs_open_redirect info = {0};
	int err;

	if (copy_from_user(&info, (void __user *)*arg, sizeof(info))) {
		info.err = -EFAULT;
		goto out;
	}

	mutex_lock(&or_lock);
	err = or_add(info.target_pathname, info.redirected_pathname,
		     info.uid_scheme);
	mutex_unlock(&or_lock);
	info.err = err;
out:
	/* upstream writes back only ->err for input-type commands */
	if (copy_to_user(&((struct st_susfs_open_redirect __user *)*arg)->err,
			 &info.err, sizeof(info.err)))
		pr_warn("open_redirect supercall copy_to_user failed\n");
}
