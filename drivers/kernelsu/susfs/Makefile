# susfs - SUSFS loadable kernel module (LKM)
#
# Build against DDK kernel headers (same image that builds kernelsu.ko):
#   make -C $KDIR M=$PWD ARCH=arm64 CC=clang LLVM=1 LLVM_IAS=1 modules
#
# Only the shipping module is built, and this objs list is the whole of it: the probe/test
# modules that were used while working the hooks out are not in this tree any more.

obj-m += susfs_guard_lkm.o

susfs_guard_lkm-objs := susfs_main.o patch_memory.o symbol_resolver.o lsm_hook.o \
              susfs_uname.o susfs_kstat.o sus_map.o sus_path.o sus_mount.o \
              spoof_cmdline.o susfs_open_redirect.o susfs_enable_log.o \
              susfs_avc_spoof.o susfs_supercall.o susfs_hide_syms.o imports_guard.o \
              ksu_umount_gate.o susfs_fp_hook.o susfs_opath.o

# 5.14+ replaced __flush_dcache_area/__flush_icache_range with
# dcache_clean_inval_poc/caches_clean_inval_pou.  Detect which to use.
#
# The detection uses `grep -l` (a filename, or nothing) rather than an exit status: the old
# `grep -q ...; echo $$?` form returned 2 when srctree was empty - and 2 is TRUE in
# `#if KSU_NEW_DCACHE_FLUSH`, so an unset srctree silently selected the 5.14+ spelling on
# every kernel and left an undefined dcache_clean_inval_poc in the module.  Fail loudly
# instead of guessing.
#
# `srctree` is set only when kbuild reaches this file (make -C $KDIR M=$PWD ...).  The check for
# it used to be a parse-time $(error), which aborted make before any goal was chosen and so made
# the `all:` entry point below - and KDIR's default - unreachable.  It now lives in the `all:`
# recipe, i.e. it fires when the build is actually attempted.
KSU_SRCTREE_MISSING := $(if $(srctree),0,1)
KSU_HAS_OLD_DCACHE := $(shell grep -l __flush_dcache_area $(srctree)/arch/arm64/include/asm/cacheflush.h 2>/dev/null)
ifneq ($(KSU_HAS_OLD_DCACHE),)
KSU_NEW_DCACHE_FLUSH := 0
else
KSU_NEW_DCACHE_FLUSH := 1
endif
ccflags-y += -DKSU_NEW_DCACHE_FLUSH=$(KSU_NEW_DCACHE_FLUSH)

# Match SukiSU's build flags: upstream code declares after statements and
# casts symbol addresses (unsigned long) to function pointers.
ccflags-y += -Wno-strict-prototypes -Wno-int-conversion -Wno-gcc-compat -Wno-missing-prototypes
ccflags-y += -Wno-declaration-after-statement -Wno-unused-function

# fs/mount.h (struct mount + real_mount) is a private header; its includes are
# all public, so -I$(srctree)/fs is enough to reach it via #include "mount.h".
ccflags-y += -I$(srctree)/fs

# Stack protector: arm64 got its per-task canary (read from sp_el0, no symbol involved) in 5.11,
# and the module inherits the kernel's mode.  Below that the kernel uses the global
# __stack_chk_guard, which the module then references - and that is the name `ksud insmod` cannot
# resolve (its kallsyms walk stops at the first record that is not three fields, while the bundled
# susfs_insmod reads the file to the end and does find it), so the load dies with
# "Unknown symbol __stack_chk_guard".  Nothing is lost where the kernel predates the canary: the
# guard would only protect this module's own stack.
KSU_KERNEL_HAS_PER_TASK_GUARD := $(shell [ "$(VERSION)" -gt 5 ] && echo yes)
ifeq ($(VERSION),5)
KSU_KERNEL_HAS_PER_TASK_GUARD := $(shell [ "$(PATCHLEVEL)" -ge 11 ] && echo yes)
endif
ifneq ($(KSU_KERNEL_HAS_PER_TASK_GUARD),yes)
ccflags-y += -fno-stack-protector
endif

# SELinux private headers are not needed: the LSM layer reaches SELinux through the live
# security_hook_heads / static_calls_table (see kernel/lsm_hook.c), not through ss/ or flask.h,
# so the -I lines that used to sit here "for when the feature lands" are gone with it.

KDIR ?= /lib/modules/$(shell uname -r)/build

all:
ifeq ($(KSU_SRCTREE_MISSING),1)
	@echo "srctree is not set - build this module through kbuild: make -C \$${KDIR} M=\$${PWD} modules" >&2
	@exit 1
else
	$(MAKE) -C $(KDIR) M=$(PWD) modules
endif

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean
