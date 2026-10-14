// SPDX-License-Identifier: GPL-2.0
/*
 * susfs_opath.c - hide sus_path's files from open(..., O_PATH).
 *
 * Why the LSM layer cannot see an O_PATH open
 * -------------------------------------------
 * do_dentry_open() answers O_PATH before anything that could refuse: it sets
 * f_mode = FMODE_PATH | FMODE_OPENED and f_op = &empty_fops and returns, and that return is
 * BEFORE security_file_open() (fs/open.c:801-805 against :832 in the 5.15 tree this was
 * written against).  Neither that early return nor the final-component walk of an O_PATH
 * lookup makes a permission or LSM call, so a path sus_path answers ENOENT for still yields a
 * usable descriptor: the fd cannot be read, but it proves the file exists
 * (fstatat(AT_EMPTY_PATH), /proc/self/fd/N, an O_PATH fd as an *at() dirfd, ...), and that is
 * all a detector needs.
 *
 * The only place left to answer is AFTER the kernel has made its own decision, so this layer
 * post-checks: the open runs exactly as the kernel chose to run it, and if the file it
 * produced is one of sus_path's, the descriptor is taken away again and the syscall is
 * answered -ENOENT.  That is why the sys_call_table entries are the mechanism here (see
 * susfs_fp_hook.c for why the table and not an inline hook, and for the ordering rules).
 *
 * Why f_mode and not the flags
 * ----------------------------
 * O_PATH is decided from the file the kernel produced, not from what the caller asked for:
 * do_dentry_open() sets FMODE_PATH for an O_PATH open and for nothing else, so the bit IS the
 * kernel's conclusion.  Reading the flags instead would mean reading user memory - openat2
 * passes a struct open_how, so the flags, the mode and the resolve field all have to be
 * copied in and validated first, and a caller can change them between the copy and the open -
 * and it would have to be done twice, once per ABI (the 32-bit layouts differ).  None of that
 * is needed: by the time this code runs, the question has already been answered.
 *
 * Why the inode and not a path
 * ----------------------------
 * The dentry/inode pair in f_path is what the kernel resolved, under the caller's own root,
 * cwd and mount namespace.  Re-resolving a path string here would be a second lookup that a
 * rename/rmdir/mount in between can point somewhere else - the TOCTOU this whole layer exists
 * to avoid - and the path string is not even available: it would have to be read out of the
 * caller's registers.  sus_path decides by identity, so the inode is the whole input.
 *
 * What this file must NOT do: no path resolution, no user memory access, no namespace work,
 * and no instruction rewriting anywhere (only the data of the table entries - a rewritten
 * .cfi_jt stub was measured as an unrecoverable "Oops - FPAC", see susfs_fp_hook.c).
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/errno.h>
#include <linux/fs.h>		/* struct file, FMODE_PATH */
#include <linux/file.h>		/* fput() */
#include <linux/dcache.h>	/* d_inode() */
#include <linux/atomic.h>
#include <linux/cred.h>		/* current_uid(), for the control node */
#include <linux/moduleparam.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/fcntl.h>	/* O_PATH, for the wrapper's flags fast path */
#include <asm/unistd.h>		/* __NR_openat, __NR_openat2, __NR_syscalls */
#include <asm/ptrace.h>		/* struct pt_regs: the wrappers read the caller's argument
				 * registers.  Written out because nothing else here reaches it -
				 * susfs_fp_hook.h only forward-declares the struct, and none of
				 * <linux/fs.h>/<linux/cred.h>/<linux/mm.h> pulls asm/ptrace.h in
				 * (the kprobe layers get it through <linux/kprobes.h>, sus_path.c
				 * through <asm/syscall.h>). */

#include "symbol_resolver.h"
#include "susfs_log.h"
#include "susfs.h"		/* susfs_control_node_allowed(), sus_path_inode_hidden_public() */
#include "susfs_opath.h"
#include "susfs_fp_hook.h"

/* The AArch32 numbers.  No arm64 header defines them as __NR_*: they are what
 * arch/arm64/include/asm/unistd32.h is generated from, i.e.
 * arch/arm/tools/syscall.tbl:19 (`5  common  open  sys_open`) and :339
 * (`322  common  openat  sys_openat`).  The native numbers come from
 * include/uapi/asm-generic/unistd.h:183 (openat 56) and :854 (openat2 437). */
#define SUSFS_COMPAT_NR_OPEN		5
#define SUSFS_COMPAT_NR_OPENAT		322
/* The AArch32 openat2 slot carries the same number as the native one but is a DIFFERENT array
 * element: arch/arm64/include/asm/unistd32.h:884-885 registers it as
 * `__SYSCALL(__NR_openat2, sys_openat2)` - the NATIVE implementation, not a compat wrapper - and
 * arch/arm64/kernel/sys32.c:130 turns that into
 * `compat_sys_call_table[437] = __arm64_sys_openat2`.  Patching sys_call_table[437] therefore
 * does not patch this element, and a 32-bit task calling openat2(..., O_PATH) would walk past
 * the layer entirely.  It needs its own entry, its own wrapper and its own original slot even
 * though both slots hold the same function. */
#define SUSFS_COMPAT_NR_OPENAT2		437

/* The BTI landing pad an indirect call into this module has to land on.  fp_has_landing_pad()
 * in susfs_fp_hook.c is static and is what susfs_fp_install() refuses a wrapper with; the same
 * test is written out here so opath_dump can report it on the device for a wrapper that is not
 * installed at all - a dump whose answer only exists when the hook is already live would be
 * useless for the step it is meant for. */
#define SUSFS_ARM64_BTI_C	0xd503245fu

static inline bool opath_has_landing_pad(const void *fn)
{
	return fn && READ_ONCE(*(const u32 *)fn) == SUSFS_ARM64_BTI_C;
}

/* Resolved BY NAME at init and cached, exactly like sus_open_redirect.c does it: fget_raw() is
 * an EXPORT_SYMBOL (fs/file.c:927-931) but GKI's module symbol list is not a promise, and
 * close_fd_get_file() (fs/file.c:795-805) is not exported at all - it is a global function,
 * so kallsyms has it and the module's own resolver can name it.  Both are called through these
 * pointers, so every function that calls them carries __nocfi.
 * susfs_opath_init() installs no table entry while either is unresolved: a wrapper that cannot
 * finish its post-check would deny nothing and only add a fault path, so the layer stays off
 * instead (the counters and the log say which name was missing). */
static struct file *(*opath_fget_raw)(unsigned int fd);
static int (*opath_close_fd_get_file)(unsigned int fd, struct file **res);
/* Which of the two names the kernel above answered to (see susfs_opath_init): only the log
 * needs it, and a log that prints a pointer without the name it came from cannot tell
 * close_fd_get_file from file_close_fd on a kernel where one of them is missing. */
static const char *opath_close_fd_name = "close_fd_get_file";

/* What the layer did, not what it is configured to do: a wrapper that never runs and one that
 * runs and matches nothing look identical from the outside, and only these separate them. */
static atomic_t n_opath_seen = ATOMIC_INIT(0);	/* wrapper calls, hidden or not */
static atomic_t n_opath_opath = ATOMIC_INIT(0);	/* of those, the O_PATH ones */
static atomic_t n_opath_hidden = ATOMIC_INIT(0);	/* of those, sus_path said hidden */
static atomic_t n_opath_deny = ATOMIC_INIT(0);	/* of those, the fd was taken away */
static atomic_t n_opath_err = ATOMIC_INIT(0);	/* lookups that failed, or an fd not ours */

int opath_test;
module_param_named(opath_test, opath_test, int, 0644);

int opath_dump;
module_param_named(opath_dump, opath_dump, int, 0644);

/* Set by susfs_opath_exit() before it touches anything; read by the arm path.  There is no
 * lock around it, and that is deliberate - see the note in susfs_opath_exit(). */
static bool opath_exiting;

/* The post-check every wrapper funnels into.
 *
 * Context: the syscall of the task that opened the file, i.e. ordinary process context - not a
 * tracepoint's atomic section.  That is what makes the layer possible at all: close_fd_get_file()
 * takes files->file_lock and sus_path_inode_hidden_public() takes sus_path_lock, and neither may
 * be taken from the contexts the kprobe layers have to live with. */
static __nocfi long susfs_opath_post(long ret)
{
	struct file *f, *victim;
	bool hidden;

	/* Only a successful open produced an fd; an error is nobody's business here. */
	if (ret < 0)
		return ret;

	/* fget_raw(), not fget(): fget() is __fget(fd, FMODE_PATH, 1) (fs/file.c:921-925) and that
	 * mask is a REJECTION mask - __fget_files_rcu() drops any file whose f_mode carries one of
	 * those bits.  do_dentry_open() gives an O_PATH file exactly FMODE_PATH | FMODE_OPENED
	 * (fs/open.c:801-805), so fget() answers NULL for precisely the files this layer has to
	 * look at, and the check below would never see one.  fget_raw() passes mask 0
	 * (fs/file.c:927-931) and takes any fd. */
	f = opath_fget_raw((unsigned int)ret);
	if (!f)
		return ret;

	if (!(f->f_mode & FMODE_PATH)) {
		/* Not an O_PATH open: leave the answer untouched - but drop the reference
		 * first, or every ordinary open would leak one. */
		fput(f);
		return ret;
	}
	atomic_inc(&n_opath_opath);

	hidden = sus_path_inode_hidden_public(d_inode(f->f_path.dentry));

	/* Release before deciding: the deny path takes an fd-table lock, and holding a file
	 * reference across it buys nothing (the file is in this task's table and cannot go
	 * away while its own syscall is running). */
	fput(f);

	if (!hidden)
		return ret;
	atomic_inc(&n_opath_hidden);

	/* Take the descriptor away and report the failure the LSM layers would have reported:
	 * returning -ENOENT while leaving a usable O_PATH fd behind would be a worse leak than
	 * the one being closed.  A failure here means the fd is not ours any more, which cannot
	 * happen inside this syscall - so the original answer is kept rather than promised away,
	 * and the counter says it happened. */
	if (opath_close_fd_get_file((unsigned int)ret, &victim)) {
		atomic_inc(&n_opath_err);
		return ret;
	}

	/* fput() and not filp_close(): close_fd_get_file()'s comment asks for filp_close()
	 * first, and for an O_PATH file that reduces to exactly this call - do_dentry_open()
	 * set f_op = &empty_fops, so f_op->flush is NULL, and a file that was never opened for
	 * reading can hold neither a POSIX lock nor a dnotify mark, which are the other two
	 * things filp_close() would run before fput(). */
	fput(victim);

	atomic_inc(&n_opath_deny);
	return -ENOENT;
}

/* One wrapper and one original slot PER TABLE ENTRY, which is what the SUSFS_FP_WRAPPER macro
 * did in susfs_fp_hook.c before that layer was reduced to install/remove: a shared slot cannot
 * work here, because the compat entries have different originals AND a different calling
 * convention - a wrapper that read the native slot on behalf of a 32-bit task would hand it a
 * native syscall, i.e. a different syscall with a different argument layout.  Each wrapper
 * reads only its own slot.
 * __nocfi is mandatory on both the wrapper and susfs_opath_post(): the wrapper is reached
 * through an indirect call out of the kernel's table, and it calls the original and the two
 * resolved kernel functions the same way.
 * The NULL test on the slot is not about the publish order - susfs_fp_install() publishes the
 * original before it writes the table, so a live entry always has one - it is what turns a
 * future mistake there into one failed open (-ENOSYS) instead of a jump to address 0. */
/* The third parameter is the REGISTER INDEX that holds this entry's flags (-1 = "not in a
 * register", see openat2 below), because the register is NOT the same for every entry:
 * arm64 puts a syscall's arguments in regs->regs[0..5] for native and compat alike
 * (arch/arm64/include/asm/syscall_wrapper.h:13-16, used for COMPAT_SYSCALL_DEFINEx at :27), so
 * the index is just the argument number counting from 0:
 *   - openat (fs/open.c:1336) and the AArch32 openat (fs/open.c:1383) are (dfd, filename,
 *     flags, mode): flags is argument 3 -> regs->regs[2];
 *   - the AArch32 open (fs/open.c:1374) is COMPAT_SYSCALL_DEFINE3: there is no dirfd, so the
 *     arguments are (filename, flags, mode) and the flags are argument 2 -> regs->regs[1].
 *     Reading regs[2] there would test the MODE, which is 0 or 0644/0755 in practice, and the
 *     layer would quietly skip every 32-bit open() it exists to catch.
 *   - openat2 (fs/open.c:1344) has a struct open_how __user * as argument 3: no flags to read,
 *     so it passes -1 and always runs the full post-check.  A fast path there would need a
 *     copy_from_user() for a syscall libc never issues by itself, and a failed copy would have
 *     to fall back to the full check anyway.
 * With a readable register the flags test runs BEFORE fget_raw(), so an ordinary open pays one
 * register read and one taken branch instead of an fget_raw()/fput() pair.  The skip is exact
 * rather than a shortcut - do_dentry_open() sets FMODE_PATH only for an O_PATH open
 * (fs/open.c:801-805), so an open whose flags lack O_PATH cannot return the kind of file this
 * layer looks at.  O_PATH is 010000000 for both ABIs (include/uapi/asm-generic/fcntl.h:85; the
 * ARM overrides in arch/arm64/include/uapi/asm/fcntl.h:23-26 exist BECAUSE of the 32-bit ABI and
 * leave O_PATH alone), and the 32-bit flags reach build_open_how() untranslated
 * (fs/open.c:1374-1377), so one constant is right for both sides.
 * n_opath_seen is bumped here rather than in susfs_opath_post() so that a skipped ordinary open
 * still shows up as "a wrapper ran" - that counter is what tells a device bring-up apart
 * "the entry is not reached at all" from "the entry is reached and the O_PATH test says no". */
#define SUSFS_OPATH_WRAPPER(fn, slot, flags_reg)			\
	static __nocfi long fn(const struct pt_regs *regs)		\
	{								\
		susfs_syscall_fn_t orig = READ_ONCE(slot);		\
		long ret;						\
									\
		if (!orig)						\
			return -ENOSYS;					\
		ret = orig(regs);					\
		atomic_inc(&n_opath_seen);				\
		if ((flags_reg) >= 0 && !(regs->regs[flags_reg] & O_PATH))	\
			return ret;					\
		return susfs_opath_post(ret);				\
	}

static susfs_syscall_fn_t opath_orig_openat;
static susfs_syscall_fn_t opath_orig_openat2;
static susfs_syscall_fn_t opath_orig_compat_open;
static susfs_syscall_fn_t opath_orig_compat_openat;
static susfs_syscall_fn_t opath_orig_compat_openat2;

SUSFS_OPATH_WRAPPER(susfs_opath_openat, opath_orig_openat, 2)
SUSFS_OPATH_WRAPPER(susfs_opath_openat2, opath_orig_openat2, -1)
SUSFS_OPATH_WRAPPER(susfs_opath_compat_open, opath_orig_compat_open, 1)
SUSFS_OPATH_WRAPPER(susfs_opath_compat_openat, opath_orig_compat_openat, 2)
SUSFS_OPATH_WRAPPER(susfs_opath_compat_openat2, opath_orig_compat_openat2, -1)

/* The five entries.  nr < 0 means "no native entry": arm64 has no native open at all, and for
 * the AArch32 open(5) the native number 5 is setxattr (include/uapi/asm-generic/unistd.h:47) -
 * so the compat-only hooks carry their index in nr_compat and leave the native table alone.
 * openat2 is the one syscall that needs an entry in BOTH tables (see SUSFS_COMPAT_NR_OPENAT2),
 * which is why it appears twice: same number, two array elements, two hooks.
 * The combinations, one line each (nr / nr_compat), which is also what struct susfs_fp_hook
 * documents:
 *   openat        :  56 / 0   - native only; the AArch32 openat is a different number (322) and
 *                               its own entry below.
 *   openat2       : 437 / 0   - native only.  A 32-bit task never reads this table - it
 *                               dispatches through compat_sys_call_table
 *                               (arch/arm64/kernel/syscall.c:185-189) - and the kernel fills
 *                               that table's slot 437 with __arm64_sys_openat2 as well
 *                               (arch/arm64/include/asm/unistd32.h:884-885).  Same function,
 *                               DIFFERENT array element: patching the native slot leaves the
 *                               32-bit one untouched, which is why the fifth line below exists.
 *   compat open   :  -1 / 5   - compat only: there is no native open to patch.
 *   compat openat :  -1 / 322 - compat only, same reason; native openat is 56.
 *   compat openat2:  -1 / 437 - compat only, same number as the native slot but a different
 *                               element (SUSFS_COMPAT_NR_OPENAT2).
 *
 * __NR_openat2 is used under #ifdef: the number only exists in a kernel that has the syscall,
 * and the index handed to the table must be the kernel's own idea of it, never a constant
 * written here.  A kernel without it simply has one entry fewer, the layer still arms, and the
 * log says so - nothing else in this file depends on that entry. */
static struct susfs_fp_hook opath_hooks[] = {
	{
		.nr		= __NR_openat,
		.name		= "opath/openat",
		.sym		= "__arm64_sys_openat",
		.wrapper	= susfs_opath_openat,
		.orig_slot	= &opath_orig_openat,
	},
#ifdef __NR_openat2
	{
		.nr		= __NR_openat2,
		.name		= "opath/openat2",
		.sym		= "__arm64_sys_openat2",
		.wrapper	= susfs_opath_openat2,
		.orig_slot	= &opath_orig_openat2,
	},
	/* The 32-bit side of the same syscall is a separate table element - see
	 * SUSFS_COMPAT_NR_OPENAT2 - so it gets a hook of its own rather than an nr_compat on the
	 * one above: the two are independent elements and either can be missing on a kernel of
	 * its own, which is exactly what per-hook install/logging is for. */
	{
		.nr		= -1,
		.nr_compat	= SUSFS_COMPAT_NR_OPENAT2,
		.name		= "opath/compat openat2",
		.sym		= "__arm64_sys_openat2",
		.wrapper	= susfs_opath_compat_openat2,
		.orig_slot_compat = &opath_orig_compat_openat2,
	},
#endif
	{
		.nr		= -1,
		.nr_compat	= SUSFS_COMPAT_NR_OPEN,
		.name		= "opath/compat open",
		.sym		= "__arm64_compat_sys_open",
		.wrapper	= susfs_opath_compat_open,
		.orig_slot_compat = &opath_orig_compat_open,
	},
	{
		.nr		= -1,
		.nr_compat	= SUSFS_COMPAT_NR_OPENAT,
		.name		= "opath/compat openat",
		.sym		= "__arm64_compat_sys_openat",
		.wrapper	= susfs_opath_compat_openat,
		.orig_slot_compat = &opath_orig_compat_openat,
	},
};

/* Table entries are data, so this is a plain read - what it is for is telling "our wrapper is
 * in there" from "the kernel's own stub is in there", which the address alone cannot answer on
 * a kernel whose symbols are hidden from a non-root reader. */
static void opath_dump_entry(const char *table_name, unsigned long table, int nr,
			     const char *sym)
{
	char cfi_name[128];
	susfs_syscall_fn_t entry;
	unsigned long plain, cfi;

	if (!table || nr < 0) {
		pr_warn("opath dump: %s[%d] %s: no table (0x%lx) or no index\n",
			table_name, nr, sym, table);
		return;
	}
	entry = READ_ONCE(((susfs_syscall_fn_t *)table)[nr]);
	plain = find_kernel_symbol_exact(sym);
	snprintf(cfi_name, sizeof(cfi_name), "%s.cfi_jt", sym);
	cfi = find_kernel_symbol_exact(cfi_name);

	pr_info("opath dump: %s[%d] %s: entry=%px plain=%px cfi_jt=%px -> %s\n",
		table_name, nr, sym, (void *)entry, (void *)plain, (void *)cfi,
		entry == (susfs_syscall_fn_t)cfi ? "cfi_jt match" :
		(entry == (susfs_syscall_fn_t)plain ? "plain match" : "neither"));
}

static void susfs_opath_dump_all(void)
{
	int i;

	pr_info("opath dump: sys_call_table=%px compat_sys_call_table=%px, %u entries defined here\n",
		(void *)susfs_fp_syscall_table(), (void *)susfs_fp_compat_syscall_table(),
		(unsigned int)ARRAY_SIZE(opath_hooks));

	for (i = 0; i < (int)ARRAY_SIZE(opath_hooks); i++) {
		struct susfs_fp_hook *h = &opath_hooks[i];

		pr_info("opath dump: [%d] %s nr=%d nr_compat=%d wrapper=%px bti_c=%d\n",
			i + 1, h->name, h->nr, h->nr_compat,
			(void *)h->wrapper, (int)opath_has_landing_pad((const void *)h->wrapper));

		/* susfs_fp_dump_entry() prints the native table only, so the compat entries are
		 * printed here - through the accessor, because the table pointer itself is
		 * private to susfs_fp_hook.c. */
		if (h->nr >= 0)
			susfs_fp_dump_entry(h->nr, h->sym);
		else
			opath_dump_entry("compat_sys_call_table",
					 susfs_fp_compat_syscall_table(),
					 h->nr_compat, h->sym);
	}
}

/* ---- /proc/susfs_opath ---- */
static int opath_proc_show(struct seq_file *m, void *v);
static int opath_proc_open(struct inode *inode, struct file *file);

static const struct proc_ops opath_proc_ops = {
	.proc_open = opath_proc_open,
	.proc_read = seq_read,
	.proc_lseek = seq_lseek,
	.proc_release = single_release,
};

static struct proc_dir_entry *opath_proc_entry;

static int opath_proc_show(struct seq_file *m, void *v)
{
	int i;

	for (i = 0; i < (int)ARRAY_SIZE(opath_hooks); i++) {
		struct susfs_fp_hook *h = &opath_hooks[i];

		seq_printf(m, "[%d] %s nr=%d nr_compat=%d installed=%d wrapper=%px orig=%px orig_compat=%px\n",
			   i + 1, h->name, h->nr, h->nr_compat, (int)h->installed,
			   (void *)h->wrapper, (void *)h->orig, (void *)h->orig_compat);
	}

	/* No "armed" flag of its own: `installed` above is the state, one line per entry.  The
	 * counters are what a bring-up is judged by - seen without opath means the wrapper runs
	 * and every open it sees is not an O_PATH one, and hidden without deny would mean the fd
	 * was not taken away. */
	seq_printf(m, "seen=%d opath=%d hidden=%d deny=%d err=%d (opath_test=%d opath_dump=%d)\n",
		   atomic_read(&n_opath_seen), atomic_read(&n_opath_opath),
		   atomic_read(&n_opath_hidden), atomic_read(&n_opath_deny),
		   atomic_read(&n_opath_err), opath_test, opath_dump);
	return 0;
}

static int opath_proc_open(struct inode *inode, struct file *file)
{
	/* Root-only, with 0777 on the node on purpose: DAC has to pass so that sus_path's LSM
	 * layer is the only thing answering a non-root reader (ENOENT), see susfs_main.c and
	 * susfs_kstat_init().  Created only when that layer is up (susfs_control_node_allowed). */
	if (current_uid().val != 0)
		return -ENOENT;
	return single_open(file, opath_proc_show, NULL);
}

int susfs_opath_init(void)
{
	int i, attempted = 0, armed = 0, err;

	if (opath_exiting) {
		pr_warn("opath: init while the layer is being torn down - not arming\n");
		return -ENODEV;
	}

	opath_fget_raw = (void *)find_kernel_symbol_exact("fget_raw");

	/* One function, two names: 6.11 reworked the fd-table internals, so what 5.15 calls
	 * close_fd_get_file() (fs/file.c:795-805) is file_close_fd() from 6.12 on
	 * (fs/file.c:784-791) - the same "take the fd out of the table, hand the caller the file,
	 * it fputs it" contract, with the locking still inside.  This is not a cosmetic rename for
	 * us: the CI's by-name step measures close_fd_get_file as 1 on 5.10/5.15/6.1/6.6 and 0 on
	 * 6.12/6.18, and that 0 is this layer refusing to install on those kernels. */
	opath_close_fd_get_file = (void *)find_kernel_symbol_exact("close_fd_get_file");
	opath_close_fd_name = "close_fd_get_file";
	if (!opath_close_fd_get_file) {
		opath_close_fd_get_file = (void *)find_kernel_symbol_exact("file_close_fd");
		opath_close_fd_name = "file_close_fd";
	}

	if (!opath_fget_raw || !opath_close_fd_get_file) {
		/* Refusing to install beats installing a wrapper that cannot finish: without
		 * these two the post-check could not take a descriptor away, so the layer
		 * would only have added a fault path to every open on the system.  Both names
		 * are printed, because "the name is missing" is only useful with which one. */
		pr_warn("opath: fget_raw=%px close_fd_get_file=%px file_close_fd=%px - a name was not resolved, no table entry is installed and O_PATH stays visible\n",
			(void *)opath_fget_raw,
			(void *)find_kernel_symbol_exact("close_fd_get_file"),
			(void *)find_kernel_symbol_exact("file_close_fd"));
		atomic_inc(&n_opath_err);
		return -ENOENT;
	}

	err = susfs_fp_init();
	if (err) {
		pr_warn("opath: susfs_fp_init failed %d - the layer stays off\n", err);
		return err;
	}

	if (opath_dump) {
		susfs_opath_dump_all();
		/* Nothing is installed on purpose, and the layer is still "armed" for the
		 * layer table: this mode exists to read the device's own answers (entry
		 * values, symbols, the landing pad) before any entry is replaced. */
		SUSFS_LOGI("opath: opath_dump=%d - diagnostics only, nothing installed\n", opath_dump);
		return 0;
	}

	for (i = 0; i < (int)ARRAY_SIZE(opath_hooks); i++) {
		struct susfs_fp_hook *h = &opath_hooks[i];

		if (opath_test && opath_test != i + 1) {
			SUSFS_LOGI("opath: [%d] %s skipped (opath_test=%d)\n",
				i + 1, h->name, opath_test);
			continue;
		}
		attempted++;

		/* One entry at a time and never fatal for the others: the remaining entries
		 * still answer the kernel's own way, which is what makes a first bring-up
		 * readable instead of all-or-nothing. */
		err = susfs_fp_install(h);
		if (err) {
			pr_warn("opath: [%d] %s not installed (%d) - that ABI stays visible\n",
				i + 1, h->name, err);
			continue;
		}
		armed++;
	}

	if (!attempted) {
		pr_warn("opath: opath_test=%d selects none of the %u entries - the layer stays off\n",
			opath_test, (unsigned int)ARRAY_SIZE(opath_hooks));
		return -EINVAL;
	}
	if (!armed) {
		/* Non-zero so the layer table records "not armed"; the caller's exit is
		 * idempotent, so the entries that did go in are taken back out. */
		pr_warn("opath: none of the %d selected table entries could be installed - O_PATH stays visible\n",
			attempted);
		return -ENOENT;
	}
	if (armed < attempted)
		pr_warn("opath: %d of %d selected table entries installed - O_PATH is answered only for those (the log above names the rest)\n",
			armed, attempted);

	if (susfs_control_node_allowed()) {
		opath_proc_entry = proc_create("susfs_opath", 0777, NULL, &opath_proc_ops);
		if (!opath_proc_entry)
			pr_warn("opath: proc_create(susfs_opath) failed\n");
	} else {
		SUSFS_LOGI("opath: /proc node not created (expose_proc=%d lsm=%d)\n",
			(int)susfs_expose_proc, (int)sus_path_lsm_active());
	}

	SUSFS_LOGI("opath armed: %d/%d entries, proc=%d, fget_raw=%px %s=%px\n",
		armed, attempted, opath_proc_entry != NULL,
		(void *)opath_fget_raw, opath_close_fd_name,
		(void *)opath_close_fd_get_file);
	return 0;
}

void susfs_opath_exit(void)
{
	int i;

	/* Idempotent: the flag is what makes it so, and it matters because this exit runs for
	 * BOTH paths that can reach it - the rollback of a failed load and the unload of a
	 * loaded module - and the drain below is a synchronize_rcu_tasks() that must not be
	 * repeated for no reason.
	 *
	 * No lock around the flag, and none of the *_exiting-plus-mutex discipline
	 * susfs_open_redirect.c needs: there, or_register() is reachable from a /proc write
	 * whose fd holds no module reference, so a write already inside the handler can re-arm
	 * a probe after the module has been freed.  This layer has no such path - its only arm
	 * entry point is susfs_opath_init(), reached from susfs_init() before the module is
	 * reachable by any caller and never again: no supercall, no /proc write and no other
	 * layer installs a table entry here.  The flag is kept so the invariant is stated in
	 * code rather than in a comment, and so a future arm path has to be added on purpose. */
	if (opath_exiting)
		return;
	opath_exiting = true;

	for (i = 0; i < (int)ARRAY_SIZE(opath_hooks); i++)
		susfs_fp_remove(&opath_hooks[i]);

	/* AFTER every entry is restored, never before: this waits until no CPU can still be
	 * inside a wrapper, and an entry that still pointed at one of them would send the next
	 * caller into module text the kernel is about to free.  Restoring the entries stops new
	 * callers; only the drain covers the caller that already picked the wrapper out of the
	 * table. */
	susfs_fp_drain();

	if (opath_proc_entry) {
		proc_remove(opath_proc_entry);
		opath_proc_entry = NULL;
	}

	SUSFS_LOGI("opath disarmed: seen=%d opath=%d hidden=%d deny=%d err=%d\n",
		atomic_read(&n_opath_seen), atomic_read(&n_opath_opath),
		atomic_read(&n_opath_hidden), atomic_read(&n_opath_deny),
		atomic_read(&n_opath_err));
}
