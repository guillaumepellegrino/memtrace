// Auto-generated using './src/syscall_table.sh > src/syscall_table.c'
#include "syscall.h"

const syscall_table_t syscall_table[] = {
#ifdef SYS_FAST_atomic_update
    {"FAST_atomic_update", SYS_FAST_atomic_update},
#endif
#ifdef SYS_FAST_cmpxchg
    {"FAST_cmpxchg", SYS_FAST_cmpxchg},
#endif
#ifdef SYS_FAST_cmpxchg64
    {"FAST_cmpxchg64", SYS_FAST_cmpxchg64},
#endif
#ifdef SYS__llseek
    {"_llseek", SYS__llseek},
#endif
#ifdef SYS__newselect
    {"_newselect", SYS__newselect},
#endif
#ifdef SYS__sysctl
    {"_sysctl", SYS__sysctl},
#endif
#ifdef SYS_accept
    {"accept", SYS_accept},
#endif
#ifdef SYS_accept4
    {"accept4", SYS_accept4},
#endif
#ifdef SYS_access
    {"access", SYS_access},
#endif
#ifdef SYS_acct
    {"acct", SYS_acct},
#endif
#ifdef SYS_acl_get
    {"acl_get", SYS_acl_get},
#endif
#ifdef SYS_acl_set
    {"acl_set", SYS_acl_set},
#endif
#ifdef SYS_add_key
    {"add_key", SYS_add_key},
#endif
#ifdef SYS_adjtimex
    {"adjtimex", SYS_adjtimex},
#endif
#ifdef SYS_afs_syscall
    {"afs_syscall", SYS_afs_syscall},
#endif
#ifdef SYS_alarm
    {"alarm", SYS_alarm},
#endif
#ifdef SYS_alloc_hugepages
    {"alloc_hugepages", SYS_alloc_hugepages},
#endif
#ifdef SYS_arc_gettls
    {"arc_gettls", SYS_arc_gettls},
#endif
#ifdef SYS_arc_settls
    {"arc_settls", SYS_arc_settls},
#endif
#ifdef SYS_arc_usr_cmpxchg
    {"arc_usr_cmpxchg", SYS_arc_usr_cmpxchg},
#endif
#ifdef SYS_arch_prctl
    {"arch_prctl", SYS_arch_prctl},
#endif
#ifdef SYS_arm_fadvise64_64
    {"arm_fadvise64_64", SYS_arm_fadvise64_64},
#endif
#ifdef SYS_arm_sync_file_range
    {"arm_sync_file_range", SYS_arm_sync_file_range},
#endif
#ifdef SYS_atomic_barrier
    {"atomic_barrier", SYS_atomic_barrier},
#endif
#ifdef SYS_atomic_cmpxchg_32
    {"atomic_cmpxchg_32", SYS_atomic_cmpxchg_32},
#endif
#ifdef SYS_attrctl
    {"attrctl", SYS_attrctl},
#endif
#ifdef SYS_bdflush
    {"bdflush", SYS_bdflush},
#endif
#ifdef SYS_bind
    {"bind", SYS_bind},
#endif
#ifdef SYS_bpf
    {"bpf", SYS_bpf},
#endif
#ifdef SYS_break
    {"break", SYS_break},
#endif
#ifdef SYS_breakpoint
    {"breakpoint", SYS_breakpoint},
#endif
#ifdef SYS_brk
    {"brk", SYS_brk},
#endif
#ifdef SYS_cachectl
    {"cachectl", SYS_cachectl},
#endif
#ifdef SYS_cacheflush
    {"cacheflush", SYS_cacheflush},
#endif
#ifdef SYS_cachestat
    {"cachestat", SYS_cachestat},
#endif
#ifdef SYS_capget
    {"capget", SYS_capget},
#endif
#ifdef SYS_capset
    {"capset", SYS_capset},
#endif
#ifdef SYS_chdir
    {"chdir", SYS_chdir},
#endif
#ifdef SYS_chmod
    {"chmod", SYS_chmod},
#endif
#ifdef SYS_chown
    {"chown", SYS_chown},
#endif
#ifdef SYS_chown32
    {"chown32", SYS_chown32},
#endif
#ifdef SYS_chroot
    {"chroot", SYS_chroot},
#endif
#ifdef SYS_clock_adjtime
    {"clock_adjtime", SYS_clock_adjtime},
#endif
#ifdef SYS_clock_adjtime64
    {"clock_adjtime64", SYS_clock_adjtime64},
#endif
#ifdef SYS_clock_getres
    {"clock_getres", SYS_clock_getres},
#endif
#ifdef SYS_clock_getres_time64
    {"clock_getres_time64", SYS_clock_getres_time64},
#endif
#ifdef SYS_clock_gettime
    {"clock_gettime", SYS_clock_gettime},
#endif
#ifdef SYS_clock_gettime64
    {"clock_gettime64", SYS_clock_gettime64},
#endif
#ifdef SYS_clock_nanosleep
    {"clock_nanosleep", SYS_clock_nanosleep},
#endif
#ifdef SYS_clock_nanosleep_time64
    {"clock_nanosleep_time64", SYS_clock_nanosleep_time64},
#endif
#ifdef SYS_clock_settime
    {"clock_settime", SYS_clock_settime},
#endif
#ifdef SYS_clock_settime64
    {"clock_settime64", SYS_clock_settime64},
#endif
#ifdef SYS_clone
    {"clone", SYS_clone},
#endif
#ifdef SYS_clone2
    {"clone2", SYS_clone2},
#endif
#ifdef SYS_clone3
    {"clone3", SYS_clone3},
#endif
#ifdef SYS_close
    {"close", SYS_close},
#endif
#ifdef SYS_close_range
    {"close_range", SYS_close_range},
#endif
#ifdef SYS_cmpxchg_badaddr
    {"cmpxchg_badaddr", SYS_cmpxchg_badaddr},
#endif
#ifdef SYS_connect
    {"connect", SYS_connect},
#endif
#ifdef SYS_copy_file_range
    {"copy_file_range", SYS_copy_file_range},
#endif
#ifdef SYS_creat
    {"creat", SYS_creat},
#endif
#ifdef SYS_create_module
    {"create_module", SYS_create_module},
#endif
#ifdef SYS_delete_module
    {"delete_module", SYS_delete_module},
#endif
#ifdef SYS_dipc
    {"dipc", SYS_dipc},
#endif
#ifdef SYS_dup
    {"dup", SYS_dup},
#endif
#ifdef SYS_dup2
    {"dup2", SYS_dup2},
#endif
#ifdef SYS_dup3
    {"dup3", SYS_dup3},
#endif
#ifdef SYS_epoll_create
    {"epoll_create", SYS_epoll_create},
#endif
#ifdef SYS_epoll_create1
    {"epoll_create1", SYS_epoll_create1},
#endif
#ifdef SYS_epoll_ctl
    {"epoll_ctl", SYS_epoll_ctl},
#endif
#ifdef SYS_epoll_ctl_old
    {"epoll_ctl_old", SYS_epoll_ctl_old},
#endif
#ifdef SYS_epoll_pwait
    {"epoll_pwait", SYS_epoll_pwait},
#endif
#ifdef SYS_epoll_pwait2
    {"epoll_pwait2", SYS_epoll_pwait2},
#endif
#ifdef SYS_epoll_wait
    {"epoll_wait", SYS_epoll_wait},
#endif
#ifdef SYS_epoll_wait_old
    {"epoll_wait_old", SYS_epoll_wait_old},
#endif
#ifdef SYS_eventfd
    {"eventfd", SYS_eventfd},
#endif
#ifdef SYS_eventfd2
    {"eventfd2", SYS_eventfd2},
#endif
#ifdef SYS_exec_with_loader
    {"exec_with_loader", SYS_exec_with_loader},
#endif
#ifdef SYS_execv
    {"execv", SYS_execv},
#endif
#ifdef SYS_execve
    {"execve", SYS_execve},
#endif
#ifdef SYS_execveat
    {"execveat", SYS_execveat},
#endif
#ifdef SYS_exit
    {"exit", SYS_exit},
#endif
#ifdef SYS_exit_group
    {"exit_group", SYS_exit_group},
#endif
#ifdef SYS_faccessat
    {"faccessat", SYS_faccessat},
#endif
#ifdef SYS_faccessat2
    {"faccessat2", SYS_faccessat2},
#endif
#ifdef SYS_fadvise64
    {"fadvise64", SYS_fadvise64},
#endif
#ifdef SYS_fadvise64_64
    {"fadvise64_64", SYS_fadvise64_64},
#endif
#ifdef SYS_fallocate
    {"fallocate", SYS_fallocate},
#endif
#ifdef SYS_fanotify_init
    {"fanotify_init", SYS_fanotify_init},
#endif
#ifdef SYS_fanotify_mark
    {"fanotify_mark", SYS_fanotify_mark},
#endif
#ifdef SYS_fchdir
    {"fchdir", SYS_fchdir},
#endif
#ifdef SYS_fchmod
    {"fchmod", SYS_fchmod},
#endif
#ifdef SYS_fchmodat
    {"fchmodat", SYS_fchmodat},
#endif
#ifdef SYS_fchmodat2
    {"fchmodat2", SYS_fchmodat2},
#endif
#ifdef SYS_fchown
    {"fchown", SYS_fchown},
#endif
#ifdef SYS_fchown32
    {"fchown32", SYS_fchown32},
#endif
#ifdef SYS_fchownat
    {"fchownat", SYS_fchownat},
#endif
#ifdef SYS_fcntl
    {"fcntl", SYS_fcntl},
#endif
#ifdef SYS_fcntl64
    {"fcntl64", SYS_fcntl64},
#endif
#ifdef SYS_fdatasync
    {"fdatasync", SYS_fdatasync},
#endif
#ifdef SYS_fgetxattr
    {"fgetxattr", SYS_fgetxattr},
#endif
#ifdef SYS_finit_module
    {"finit_module", SYS_finit_module},
#endif
#ifdef SYS_flistxattr
    {"flistxattr", SYS_flistxattr},
#endif
#ifdef SYS_flock
    {"flock", SYS_flock},
#endif
#ifdef SYS_fork
    {"fork", SYS_fork},
#endif
#ifdef SYS_fp_udfiex_crtl
    {"fp_udfiex_crtl", SYS_fp_udfiex_crtl},
#endif
#ifdef SYS_free_hugepages
    {"free_hugepages", SYS_free_hugepages},
#endif
#ifdef SYS_fremovexattr
    {"fremovexattr", SYS_fremovexattr},
#endif
#ifdef SYS_fsconfig
    {"fsconfig", SYS_fsconfig},
#endif
#ifdef SYS_fsetxattr
    {"fsetxattr", SYS_fsetxattr},
#endif
#ifdef SYS_fsmount
    {"fsmount", SYS_fsmount},
#endif
#ifdef SYS_fsopen
    {"fsopen", SYS_fsopen},
#endif
#ifdef SYS_fspick
    {"fspick", SYS_fspick},
#endif
#ifdef SYS_fstat
    {"fstat", SYS_fstat},
#endif
#ifdef SYS_fstat64
    {"fstat64", SYS_fstat64},
#endif
#ifdef SYS_fstatat64
    {"fstatat64", SYS_fstatat64},
#endif
#ifdef SYS_fstatfs
    {"fstatfs", SYS_fstatfs},
#endif
#ifdef SYS_fstatfs64
    {"fstatfs64", SYS_fstatfs64},
#endif
#ifdef SYS_fsync
    {"fsync", SYS_fsync},
#endif
#ifdef SYS_ftime
    {"ftime", SYS_ftime},
#endif
#ifdef SYS_ftruncate
    {"ftruncate", SYS_ftruncate},
#endif
#ifdef SYS_ftruncate64
    {"ftruncate64", SYS_ftruncate64},
#endif
#ifdef SYS_futex
    {"futex", SYS_futex},
#endif
#ifdef SYS_futex_requeue
    {"futex_requeue", SYS_futex_requeue},
#endif
#ifdef SYS_futex_time64
    {"futex_time64", SYS_futex_time64},
#endif
#ifdef SYS_futex_wait
    {"futex_wait", SYS_futex_wait},
#endif
#ifdef SYS_futex_waitv
    {"futex_waitv", SYS_futex_waitv},
#endif
#ifdef SYS_futex_wake
    {"futex_wake", SYS_futex_wake},
#endif
#ifdef SYS_futimesat
    {"futimesat", SYS_futimesat},
#endif
#ifdef SYS_get_kernel_syms
    {"get_kernel_syms", SYS_get_kernel_syms},
#endif
#ifdef SYS_get_mempolicy
    {"get_mempolicy", SYS_get_mempolicy},
#endif
#ifdef SYS_get_robust_list
    {"get_robust_list", SYS_get_robust_list},
#endif
#ifdef SYS_get_thread_area
    {"get_thread_area", SYS_get_thread_area},
#endif
#ifdef SYS_get_tls
    {"get_tls", SYS_get_tls},
#endif
#ifdef SYS_getcpu
    {"getcpu", SYS_getcpu},
#endif
#ifdef SYS_getcwd
    {"getcwd", SYS_getcwd},
#endif
#ifdef SYS_getdents
    {"getdents", SYS_getdents},
#endif
#ifdef SYS_getdents64
    {"getdents64", SYS_getdents64},
#endif
#ifdef SYS_getdomainname
    {"getdomainname", SYS_getdomainname},
#endif
#ifdef SYS_getdtablesize
    {"getdtablesize", SYS_getdtablesize},
#endif
#ifdef SYS_getegid
    {"getegid", SYS_getegid},
#endif
#ifdef SYS_getegid32
    {"getegid32", SYS_getegid32},
#endif
#ifdef SYS_geteuid
    {"geteuid", SYS_geteuid},
#endif
#ifdef SYS_geteuid32
    {"geteuid32", SYS_geteuid32},
#endif
#ifdef SYS_getgid
    {"getgid", SYS_getgid},
#endif
#ifdef SYS_getgid32
    {"getgid32", SYS_getgid32},
#endif
#ifdef SYS_getgroups
    {"getgroups", SYS_getgroups},
#endif
#ifdef SYS_getgroups32
    {"getgroups32", SYS_getgroups32},
#endif
#ifdef SYS_gethostname
    {"gethostname", SYS_gethostname},
#endif
#ifdef SYS_getitimer
    {"getitimer", SYS_getitimer},
#endif
#ifdef SYS_getpagesize
    {"getpagesize", SYS_getpagesize},
#endif
#ifdef SYS_getpeername
    {"getpeername", SYS_getpeername},
#endif
#ifdef SYS_getpgid
    {"getpgid", SYS_getpgid},
#endif
#ifdef SYS_getpgrp
    {"getpgrp", SYS_getpgrp},
#endif
#ifdef SYS_getpid
    {"getpid", SYS_getpid},
#endif
#ifdef SYS_getpmsg
    {"getpmsg", SYS_getpmsg},
#endif
#ifdef SYS_getppid
    {"getppid", SYS_getppid},
#endif
#ifdef SYS_getpriority
    {"getpriority", SYS_getpriority},
#endif
#ifdef SYS_getrandom
    {"getrandom", SYS_getrandom},
#endif
#ifdef SYS_getresgid
    {"getresgid", SYS_getresgid},
#endif
#ifdef SYS_getresgid32
    {"getresgid32", SYS_getresgid32},
#endif
#ifdef SYS_getresuid
    {"getresuid", SYS_getresuid},
#endif
#ifdef SYS_getresuid32
    {"getresuid32", SYS_getresuid32},
#endif
#ifdef SYS_getrlimit
    {"getrlimit", SYS_getrlimit},
#endif
#ifdef SYS_getrusage
    {"getrusage", SYS_getrusage},
#endif
#ifdef SYS_getsid
    {"getsid", SYS_getsid},
#endif
#ifdef SYS_getsockname
    {"getsockname", SYS_getsockname},
#endif
#ifdef SYS_getsockopt
    {"getsockopt", SYS_getsockopt},
#endif
#ifdef SYS_gettid
    {"gettid", SYS_gettid},
#endif
#ifdef SYS_gettimeofday
    {"gettimeofday", SYS_gettimeofday},
#endif
#ifdef SYS_getuid
    {"getuid", SYS_getuid},
#endif
#ifdef SYS_getuid32
    {"getuid32", SYS_getuid32},
#endif
#ifdef SYS_getunwind
    {"getunwind", SYS_getunwind},
#endif
#ifdef SYS_getxattr
    {"getxattr", SYS_getxattr},
#endif
#ifdef SYS_getxgid
    {"getxgid", SYS_getxgid},
#endif
#ifdef SYS_getxpid
    {"getxpid", SYS_getxpid},
#endif
#ifdef SYS_getxuid
    {"getxuid", SYS_getxuid},
#endif
#ifdef SYS_gtty
    {"gtty", SYS_gtty},
#endif
#ifdef SYS_idle
    {"idle", SYS_idle},
#endif
#ifdef SYS_init_module
    {"init_module", SYS_init_module},
#endif
#ifdef SYS_inotify_add_watch
    {"inotify_add_watch", SYS_inotify_add_watch},
#endif
#ifdef SYS_inotify_init
    {"inotify_init", SYS_inotify_init},
#endif
#ifdef SYS_inotify_init1
    {"inotify_init1", SYS_inotify_init1},
#endif
#ifdef SYS_inotify_rm_watch
    {"inotify_rm_watch", SYS_inotify_rm_watch},
#endif
#ifdef SYS_io_cancel
    {"io_cancel", SYS_io_cancel},
#endif
#ifdef SYS_io_destroy
    {"io_destroy", SYS_io_destroy},
#endif
#ifdef SYS_io_getevents
    {"io_getevents", SYS_io_getevents},
#endif
#ifdef SYS_io_pgetevents
    {"io_pgetevents", SYS_io_pgetevents},
#endif
#ifdef SYS_io_pgetevents_time64
    {"io_pgetevents_time64", SYS_io_pgetevents_time64},
#endif
#ifdef SYS_io_setup
    {"io_setup", SYS_io_setup},
#endif
#ifdef SYS_io_submit
    {"io_submit", SYS_io_submit},
#endif
#ifdef SYS_io_uring_enter
    {"io_uring_enter", SYS_io_uring_enter},
#endif
#ifdef SYS_io_uring_register
    {"io_uring_register", SYS_io_uring_register},
#endif
#ifdef SYS_io_uring_setup
    {"io_uring_setup", SYS_io_uring_setup},
#endif
#ifdef SYS_ioctl
    {"ioctl", SYS_ioctl},
#endif
#ifdef SYS_ioperm
    {"ioperm", SYS_ioperm},
#endif
#ifdef SYS_iopl
    {"iopl", SYS_iopl},
#endif
#ifdef SYS_ioprio_get
    {"ioprio_get", SYS_ioprio_get},
#endif
#ifdef SYS_ioprio_set
    {"ioprio_set", SYS_ioprio_set},
#endif
#ifdef SYS_ipc
    {"ipc", SYS_ipc},
#endif
#ifdef SYS_kcmp
    {"kcmp", SYS_kcmp},
#endif
#ifdef SYS_kern_features
    {"kern_features", SYS_kern_features},
#endif
#ifdef SYS_kexec_file_load
    {"kexec_file_load", SYS_kexec_file_load},
#endif
#ifdef SYS_kexec_load
    {"kexec_load", SYS_kexec_load},
#endif
#ifdef SYS_keyctl
    {"keyctl", SYS_keyctl},
#endif
#ifdef SYS_kill
    {"kill", SYS_kill},
#endif
#ifdef SYS_landlock_add_rule
    {"landlock_add_rule", SYS_landlock_add_rule},
#endif
#ifdef SYS_landlock_create_ruleset
    {"landlock_create_ruleset", SYS_landlock_create_ruleset},
#endif
#ifdef SYS_landlock_restrict_self
    {"landlock_restrict_self", SYS_landlock_restrict_self},
#endif
#ifdef SYS_lchown
    {"lchown", SYS_lchown},
#endif
#ifdef SYS_lchown32
    {"lchown32", SYS_lchown32},
#endif
#ifdef SYS_lgetxattr
    {"lgetxattr", SYS_lgetxattr},
#endif
#ifdef SYS_link
    {"link", SYS_link},
#endif
#ifdef SYS_linkat
    {"linkat", SYS_linkat},
#endif
#ifdef SYS_listen
    {"listen", SYS_listen},
#endif
#ifdef SYS_listxattr
    {"listxattr", SYS_listxattr},
#endif
#ifdef SYS_llistxattr
    {"llistxattr", SYS_llistxattr},
#endif
#ifdef SYS_llseek
    {"llseek", SYS_llseek},
#endif
#ifdef SYS_lock
    {"lock", SYS_lock},
#endif
#ifdef SYS_lookup_dcookie
    {"lookup_dcookie", SYS_lookup_dcookie},
#endif
#ifdef SYS_lremovexattr
    {"lremovexattr", SYS_lremovexattr},
#endif
#ifdef SYS_lseek
    {"lseek", SYS_lseek},
#endif
#ifdef SYS_lsetxattr
    {"lsetxattr", SYS_lsetxattr},
#endif
#ifdef SYS_lstat
    {"lstat", SYS_lstat},
#endif
#ifdef SYS_lstat64
    {"lstat64", SYS_lstat64},
#endif
#ifdef SYS_madvise
    {"madvise", SYS_madvise},
#endif
#ifdef SYS_map_shadow_stack
    {"map_shadow_stack", SYS_map_shadow_stack},
#endif
#ifdef SYS_mbind
    {"mbind", SYS_mbind},
#endif
#ifdef SYS_membarrier
    {"membarrier", SYS_membarrier},
#endif
#ifdef SYS_memfd_create
    {"memfd_create", SYS_memfd_create},
#endif
#ifdef SYS_memfd_secret
    {"memfd_secret", SYS_memfd_secret},
#endif
#ifdef SYS_memory_ordering
    {"memory_ordering", SYS_memory_ordering},
#endif
#ifdef SYS_migrate_pages
    {"migrate_pages", SYS_migrate_pages},
#endif
#ifdef SYS_mincore
    {"mincore", SYS_mincore},
#endif
#ifdef SYS_mkdir
    {"mkdir", SYS_mkdir},
#endif
#ifdef SYS_mkdirat
    {"mkdirat", SYS_mkdirat},
#endif
#ifdef SYS_mknod
    {"mknod", SYS_mknod},
#endif
#ifdef SYS_mknodat
    {"mknodat", SYS_mknodat},
#endif
#ifdef SYS_mlock
    {"mlock", SYS_mlock},
#endif
#ifdef SYS_mlock2
    {"mlock2", SYS_mlock2},
#endif
#ifdef SYS_mlockall
    {"mlockall", SYS_mlockall},
#endif
#ifdef SYS_mmap
    {"mmap", SYS_mmap},
#endif
#ifdef SYS_mmap2
    {"mmap2", SYS_mmap2},
#endif
#ifdef SYS_modify_ldt
    {"modify_ldt", SYS_modify_ldt},
#endif
#ifdef SYS_mount
    {"mount", SYS_mount},
#endif
#ifdef SYS_mount_setattr
    {"mount_setattr", SYS_mount_setattr},
#endif
#ifdef SYS_move_mount
    {"move_mount", SYS_move_mount},
#endif
#ifdef SYS_move_pages
    {"move_pages", SYS_move_pages},
#endif
#ifdef SYS_mprotect
    {"mprotect", SYS_mprotect},
#endif
#ifdef SYS_mpx
    {"mpx", SYS_mpx},
#endif
#ifdef SYS_mq_getsetattr
    {"mq_getsetattr", SYS_mq_getsetattr},
#endif
#ifdef SYS_mq_notify
    {"mq_notify", SYS_mq_notify},
#endif
#ifdef SYS_mq_open
    {"mq_open", SYS_mq_open},
#endif
#ifdef SYS_mq_timedreceive
    {"mq_timedreceive", SYS_mq_timedreceive},
#endif
#ifdef SYS_mq_timedreceive_time64
    {"mq_timedreceive_time64", SYS_mq_timedreceive_time64},
#endif
#ifdef SYS_mq_timedsend
    {"mq_timedsend", SYS_mq_timedsend},
#endif
#ifdef SYS_mq_timedsend_time64
    {"mq_timedsend_time64", SYS_mq_timedsend_time64},
#endif
#ifdef SYS_mq_unlink
    {"mq_unlink", SYS_mq_unlink},
#endif
#ifdef SYS_mremap
    {"mremap", SYS_mremap},
#endif
#ifdef SYS_msgctl
    {"msgctl", SYS_msgctl},
#endif
#ifdef SYS_msgget
    {"msgget", SYS_msgget},
#endif
#ifdef SYS_msgrcv
    {"msgrcv", SYS_msgrcv},
#endif
#ifdef SYS_msgsnd
    {"msgsnd", SYS_msgsnd},
#endif
#ifdef SYS_msync
    {"msync", SYS_msync},
#endif
#ifdef SYS_multiplexer
    {"multiplexer", SYS_multiplexer},
#endif
#ifdef SYS_munlock
    {"munlock", SYS_munlock},
#endif
#ifdef SYS_munlockall
    {"munlockall", SYS_munlockall},
#endif
#ifdef SYS_munmap
    {"munmap", SYS_munmap},
#endif
#ifdef SYS_name_to_handle_at
    {"name_to_handle_at", SYS_name_to_handle_at},
#endif
#ifdef SYS_nanosleep
    {"nanosleep", SYS_nanosleep},
#endif
#ifdef SYS_newfstatat
    {"newfstatat", SYS_newfstatat},
#endif
#ifdef SYS_nfsservctl
    {"nfsservctl", SYS_nfsservctl},
#endif
#ifdef SYS_ni_syscall
    {"ni_syscall", SYS_ni_syscall},
#endif
#ifdef SYS_nice
    {"nice", SYS_nice},
#endif
#ifdef SYS_old_adjtimex
    {"old_adjtimex", SYS_old_adjtimex},
#endif
#ifdef SYS_old_getpagesize
    {"old_getpagesize", SYS_old_getpagesize},
#endif
#ifdef SYS_oldfstat
    {"oldfstat", SYS_oldfstat},
#endif
#ifdef SYS_oldlstat
    {"oldlstat", SYS_oldlstat},
#endif
#ifdef SYS_oldolduname
    {"oldolduname", SYS_oldolduname},
#endif
#ifdef SYS_oldstat
    {"oldstat", SYS_oldstat},
#endif
#ifdef SYS_oldumount
    {"oldumount", SYS_oldumount},
#endif
#ifdef SYS_olduname
    {"olduname", SYS_olduname},
#endif
#ifdef SYS_open
    {"open", SYS_open},
#endif
#ifdef SYS_open_by_handle_at
    {"open_by_handle_at", SYS_open_by_handle_at},
#endif
#ifdef SYS_open_tree
    {"open_tree", SYS_open_tree},
#endif
#ifdef SYS_openat
    {"openat", SYS_openat},
#endif
#ifdef SYS_openat2
    {"openat2", SYS_openat2},
#endif
#ifdef SYS_or1k_atomic
    {"or1k_atomic", SYS_or1k_atomic},
#endif
#ifdef SYS_osf_adjtime
    {"osf_adjtime", SYS_osf_adjtime},
#endif
#ifdef SYS_osf_afs_syscall
    {"osf_afs_syscall", SYS_osf_afs_syscall},
#endif
#ifdef SYS_osf_alt_plock
    {"osf_alt_plock", SYS_osf_alt_plock},
#endif
#ifdef SYS_osf_alt_setsid
    {"osf_alt_setsid", SYS_osf_alt_setsid},
#endif
#ifdef SYS_osf_alt_sigpending
    {"osf_alt_sigpending", SYS_osf_alt_sigpending},
#endif
#ifdef SYS_osf_asynch_daemon
    {"osf_asynch_daemon", SYS_osf_asynch_daemon},
#endif
#ifdef SYS_osf_audcntl
    {"osf_audcntl", SYS_osf_audcntl},
#endif
#ifdef SYS_osf_audgen
    {"osf_audgen", SYS_osf_audgen},
#endif
#ifdef SYS_osf_chflags
    {"osf_chflags", SYS_osf_chflags},
#endif
#ifdef SYS_osf_execve
    {"osf_execve", SYS_osf_execve},
#endif
#ifdef SYS_osf_exportfs
    {"osf_exportfs", SYS_osf_exportfs},
#endif
#ifdef SYS_osf_fchflags
    {"osf_fchflags", SYS_osf_fchflags},
#endif
#ifdef SYS_osf_fdatasync
    {"osf_fdatasync", SYS_osf_fdatasync},
#endif
#ifdef SYS_osf_fpathconf
    {"osf_fpathconf", SYS_osf_fpathconf},
#endif
#ifdef SYS_osf_fstat
    {"osf_fstat", SYS_osf_fstat},
#endif
#ifdef SYS_osf_fstatfs
    {"osf_fstatfs", SYS_osf_fstatfs},
#endif
#ifdef SYS_osf_fstatfs64
    {"osf_fstatfs64", SYS_osf_fstatfs64},
#endif
#ifdef SYS_osf_fuser
    {"osf_fuser", SYS_osf_fuser},
#endif
#ifdef SYS_osf_getaddressconf
    {"osf_getaddressconf", SYS_osf_getaddressconf},
#endif
#ifdef SYS_osf_getdirentries
    {"osf_getdirentries", SYS_osf_getdirentries},
#endif
#ifdef SYS_osf_getdomainname
    {"osf_getdomainname", SYS_osf_getdomainname},
#endif
#ifdef SYS_osf_getfh
    {"osf_getfh", SYS_osf_getfh},
#endif
#ifdef SYS_osf_getfsstat
    {"osf_getfsstat", SYS_osf_getfsstat},
#endif
#ifdef SYS_osf_gethostid
    {"osf_gethostid", SYS_osf_gethostid},
#endif
#ifdef SYS_osf_getitimer
    {"osf_getitimer", SYS_osf_getitimer},
#endif
#ifdef SYS_osf_getlogin
    {"osf_getlogin", SYS_osf_getlogin},
#endif
#ifdef SYS_osf_getmnt
    {"osf_getmnt", SYS_osf_getmnt},
#endif
#ifdef SYS_osf_getrusage
    {"osf_getrusage", SYS_osf_getrusage},
#endif
#ifdef SYS_osf_getsysinfo
    {"osf_getsysinfo", SYS_osf_getsysinfo},
#endif
#ifdef SYS_osf_gettimeofday
    {"osf_gettimeofday", SYS_osf_gettimeofday},
#endif
#ifdef SYS_osf_kloadcall
    {"osf_kloadcall", SYS_osf_kloadcall},
#endif
#ifdef SYS_osf_kmodcall
    {"osf_kmodcall", SYS_osf_kmodcall},
#endif
#ifdef SYS_osf_lstat
    {"osf_lstat", SYS_osf_lstat},
#endif
#ifdef SYS_osf_memcntl
    {"osf_memcntl", SYS_osf_memcntl},
#endif
#ifdef SYS_osf_mincore
    {"osf_mincore", SYS_osf_mincore},
#endif
#ifdef SYS_osf_mount
    {"osf_mount", SYS_osf_mount},
#endif
#ifdef SYS_osf_mremap
    {"osf_mremap", SYS_osf_mremap},
#endif
#ifdef SYS_osf_msfs_syscall
    {"osf_msfs_syscall", SYS_osf_msfs_syscall},
#endif
#ifdef SYS_osf_msleep
    {"osf_msleep", SYS_osf_msleep},
#endif
#ifdef SYS_osf_mvalid
    {"osf_mvalid", SYS_osf_mvalid},
#endif
#ifdef SYS_osf_mwakeup
    {"osf_mwakeup", SYS_osf_mwakeup},
#endif
#ifdef SYS_osf_naccept
    {"osf_naccept", SYS_osf_naccept},
#endif
#ifdef SYS_osf_nfssvc
    {"osf_nfssvc", SYS_osf_nfssvc},
#endif
#ifdef SYS_osf_ngetpeername
    {"osf_ngetpeername", SYS_osf_ngetpeername},
#endif
#ifdef SYS_osf_ngetsockname
    {"osf_ngetsockname", SYS_osf_ngetsockname},
#endif
#ifdef SYS_osf_nrecvfrom
    {"osf_nrecvfrom", SYS_osf_nrecvfrom},
#endif
#ifdef SYS_osf_nrecvmsg
    {"osf_nrecvmsg", SYS_osf_nrecvmsg},
#endif
#ifdef SYS_osf_nsendmsg
    {"osf_nsendmsg", SYS_osf_nsendmsg},
#endif
#ifdef SYS_osf_ntp_adjtime
    {"osf_ntp_adjtime", SYS_osf_ntp_adjtime},
#endif
#ifdef SYS_osf_ntp_gettime
    {"osf_ntp_gettime", SYS_osf_ntp_gettime},
#endif
#ifdef SYS_osf_old_creat
    {"osf_old_creat", SYS_osf_old_creat},
#endif
#ifdef SYS_osf_old_fstat
    {"osf_old_fstat", SYS_osf_old_fstat},
#endif
#ifdef SYS_osf_old_getpgrp
    {"osf_old_getpgrp", SYS_osf_old_getpgrp},
#endif
#ifdef SYS_osf_old_killpg
    {"osf_old_killpg", SYS_osf_old_killpg},
#endif
#ifdef SYS_osf_old_lstat
    {"osf_old_lstat", SYS_osf_old_lstat},
#endif
#ifdef SYS_osf_old_open
    {"osf_old_open", SYS_osf_old_open},
#endif
#ifdef SYS_osf_old_sigaction
    {"osf_old_sigaction", SYS_osf_old_sigaction},
#endif
#ifdef SYS_osf_old_sigblock
    {"osf_old_sigblock", SYS_osf_old_sigblock},
#endif
#ifdef SYS_osf_old_sigreturn
    {"osf_old_sigreturn", SYS_osf_old_sigreturn},
#endif
#ifdef SYS_osf_old_sigsetmask
    {"osf_old_sigsetmask", SYS_osf_old_sigsetmask},
#endif
#ifdef SYS_osf_old_sigvec
    {"osf_old_sigvec", SYS_osf_old_sigvec},
#endif
#ifdef SYS_osf_old_stat
    {"osf_old_stat", SYS_osf_old_stat},
#endif
#ifdef SYS_osf_old_vadvise
    {"osf_old_vadvise", SYS_osf_old_vadvise},
#endif
#ifdef SYS_osf_old_vtrace
    {"osf_old_vtrace", SYS_osf_old_vtrace},
#endif
#ifdef SYS_osf_old_wait
    {"osf_old_wait", SYS_osf_old_wait},
#endif
#ifdef SYS_osf_oldquota
    {"osf_oldquota", SYS_osf_oldquota},
#endif
#ifdef SYS_osf_pathconf
    {"osf_pathconf", SYS_osf_pathconf},
#endif
#ifdef SYS_osf_pid_block
    {"osf_pid_block", SYS_osf_pid_block},
#endif
#ifdef SYS_osf_pid_unblock
    {"osf_pid_unblock", SYS_osf_pid_unblock},
#endif
#ifdef SYS_osf_plock
    {"osf_plock", SYS_osf_plock},
#endif
#ifdef SYS_osf_priocntlset
    {"osf_priocntlset", SYS_osf_priocntlset},
#endif
#ifdef SYS_osf_profil
    {"osf_profil", SYS_osf_profil},
#endif
#ifdef SYS_osf_proplist_syscall
    {"osf_proplist_syscall", SYS_osf_proplist_syscall},
#endif
#ifdef SYS_osf_reboot
    {"osf_reboot", SYS_osf_reboot},
#endif
#ifdef SYS_osf_revoke
    {"osf_revoke", SYS_osf_revoke},
#endif
#ifdef SYS_osf_sbrk
    {"osf_sbrk", SYS_osf_sbrk},
#endif
#ifdef SYS_osf_security
    {"osf_security", SYS_osf_security},
#endif
#ifdef SYS_osf_select
    {"osf_select", SYS_osf_select},
#endif
#ifdef SYS_osf_set_program_attributes
    {"osf_set_program_attributes", SYS_osf_set_program_attributes},
#endif
#ifdef SYS_osf_set_speculative
    {"osf_set_speculative", SYS_osf_set_speculative},
#endif
#ifdef SYS_osf_sethostid
    {"osf_sethostid", SYS_osf_sethostid},
#endif
#ifdef SYS_osf_setitimer
    {"osf_setitimer", SYS_osf_setitimer},
#endif
#ifdef SYS_osf_setlogin
    {"osf_setlogin", SYS_osf_setlogin},
#endif
#ifdef SYS_osf_setsysinfo
    {"osf_setsysinfo", SYS_osf_setsysinfo},
#endif
#ifdef SYS_osf_settimeofday
    {"osf_settimeofday", SYS_osf_settimeofday},
#endif
#ifdef SYS_osf_shmat
    {"osf_shmat", SYS_osf_shmat},
#endif
#ifdef SYS_osf_signal
    {"osf_signal", SYS_osf_signal},
#endif
#ifdef SYS_osf_sigprocmask
    {"osf_sigprocmask", SYS_osf_sigprocmask},
#endif
#ifdef SYS_osf_sigsendset
    {"osf_sigsendset", SYS_osf_sigsendset},
#endif
#ifdef SYS_osf_sigstack
    {"osf_sigstack", SYS_osf_sigstack},
#endif
#ifdef SYS_osf_sigwaitprim
    {"osf_sigwaitprim", SYS_osf_sigwaitprim},
#endif
#ifdef SYS_osf_sstk
    {"osf_sstk", SYS_osf_sstk},
#endif
#ifdef SYS_osf_stat
    {"osf_stat", SYS_osf_stat},
#endif
#ifdef SYS_osf_statfs
    {"osf_statfs", SYS_osf_statfs},
#endif
#ifdef SYS_osf_statfs64
    {"osf_statfs64", SYS_osf_statfs64},
#endif
#ifdef SYS_osf_subsys_info
    {"osf_subsys_info", SYS_osf_subsys_info},
#endif
#ifdef SYS_osf_swapctl
    {"osf_swapctl", SYS_osf_swapctl},
#endif
#ifdef SYS_osf_swapon
    {"osf_swapon", SYS_osf_swapon},
#endif
#ifdef SYS_osf_syscall
    {"osf_syscall", SYS_osf_syscall},
#endif
#ifdef SYS_osf_sysinfo
    {"osf_sysinfo", SYS_osf_sysinfo},
#endif
#ifdef SYS_osf_table
    {"osf_table", SYS_osf_table},
#endif
#ifdef SYS_osf_uadmin
    {"osf_uadmin", SYS_osf_uadmin},
#endif
#ifdef SYS_osf_usleep_thread
    {"osf_usleep_thread", SYS_osf_usleep_thread},
#endif
#ifdef SYS_osf_uswitch
    {"osf_uswitch", SYS_osf_uswitch},
#endif
#ifdef SYS_osf_utc_adjtime
    {"osf_utc_adjtime", SYS_osf_utc_adjtime},
#endif
#ifdef SYS_osf_utc_gettime
    {"osf_utc_gettime", SYS_osf_utc_gettime},
#endif
#ifdef SYS_osf_utimes
    {"osf_utimes", SYS_osf_utimes},
#endif
#ifdef SYS_osf_utsname
    {"osf_utsname", SYS_osf_utsname},
#endif
#ifdef SYS_osf_wait4
    {"osf_wait4", SYS_osf_wait4},
#endif
#ifdef SYS_osf_waitid
    {"osf_waitid", SYS_osf_waitid},
#endif
#ifdef SYS_pause
    {"pause", SYS_pause},
#endif
#ifdef SYS_pciconfig_iobase
    {"pciconfig_iobase", SYS_pciconfig_iobase},
#endif
#ifdef SYS_pciconfig_read
    {"pciconfig_read", SYS_pciconfig_read},
#endif
#ifdef SYS_pciconfig_write
    {"pciconfig_write", SYS_pciconfig_write},
#endif
#ifdef SYS_perf_event_open
    {"perf_event_open", SYS_perf_event_open},
#endif
#ifdef SYS_perfctr
    {"perfctr", SYS_perfctr},
#endif
#ifdef SYS_perfmonctl
    {"perfmonctl", SYS_perfmonctl},
#endif
#ifdef SYS_personality
    {"personality", SYS_personality},
#endif
#ifdef SYS_pidfd_getfd
    {"pidfd_getfd", SYS_pidfd_getfd},
#endif
#ifdef SYS_pidfd_open
    {"pidfd_open", SYS_pidfd_open},
#endif
#ifdef SYS_pidfd_send_signal
    {"pidfd_send_signal", SYS_pidfd_send_signal},
#endif
#ifdef SYS_pipe
    {"pipe", SYS_pipe},
#endif
#ifdef SYS_pipe2
    {"pipe2", SYS_pipe2},
#endif
#ifdef SYS_pivot_root
    {"pivot_root", SYS_pivot_root},
#endif
#ifdef SYS_pkey_alloc
    {"pkey_alloc", SYS_pkey_alloc},
#endif
#ifdef SYS_pkey_free
    {"pkey_free", SYS_pkey_free},
#endif
#ifdef SYS_pkey_mprotect
    {"pkey_mprotect", SYS_pkey_mprotect},
#endif
#ifdef SYS_poll
    {"poll", SYS_poll},
#endif
#ifdef SYS_ppoll
    {"ppoll", SYS_ppoll},
#endif
#ifdef SYS_ppoll_time64
    {"ppoll_time64", SYS_ppoll_time64},
#endif
#ifdef SYS_prctl
    {"prctl", SYS_prctl},
#endif
#ifdef SYS_pread64
    {"pread64", SYS_pread64},
#endif
#ifdef SYS_preadv
    {"preadv", SYS_preadv},
#endif
#ifdef SYS_preadv2
    {"preadv2", SYS_preadv2},
#endif
#ifdef SYS_prlimit64
    {"prlimit64", SYS_prlimit64},
#endif
#ifdef SYS_process_madvise
    {"process_madvise", SYS_process_madvise},
#endif
#ifdef SYS_process_mrelease
    {"process_mrelease", SYS_process_mrelease},
#endif
#ifdef SYS_process_vm_readv
    {"process_vm_readv", SYS_process_vm_readv},
#endif
#ifdef SYS_process_vm_writev
    {"process_vm_writev", SYS_process_vm_writev},
#endif
#ifdef SYS_prof
    {"prof", SYS_prof},
#endif
#ifdef SYS_profil
    {"profil", SYS_profil},
#endif
#ifdef SYS_pselect6
    {"pselect6", SYS_pselect6},
#endif
#ifdef SYS_pselect6_time64
    {"pselect6_time64", SYS_pselect6_time64},
#endif
#ifdef SYS_ptrace
    {"ptrace", SYS_ptrace},
#endif
#ifdef SYS_putpmsg
    {"putpmsg", SYS_putpmsg},
#endif
#ifdef SYS_pwrite64
    {"pwrite64", SYS_pwrite64},
#endif
#ifdef SYS_pwritev
    {"pwritev", SYS_pwritev},
#endif
#ifdef SYS_pwritev2
    {"pwritev2", SYS_pwritev2},
#endif
#ifdef SYS_query_module
    {"query_module", SYS_query_module},
#endif
#ifdef SYS_quotactl
    {"quotactl", SYS_quotactl},
#endif
#ifdef SYS_quotactl_fd
    {"quotactl_fd", SYS_quotactl_fd},
#endif
#ifdef SYS_read
    {"read", SYS_read},
#endif
#ifdef SYS_readahead
    {"readahead", SYS_readahead},
#endif
#ifdef SYS_readdir
    {"readdir", SYS_readdir},
#endif
#ifdef SYS_readlink
    {"readlink", SYS_readlink},
#endif
#ifdef SYS_readlinkat
    {"readlinkat", SYS_readlinkat},
#endif
#ifdef SYS_readv
    {"readv", SYS_readv},
#endif
#ifdef SYS_reboot
    {"reboot", SYS_reboot},
#endif
#ifdef SYS_recv
    {"recv", SYS_recv},
#endif
#ifdef SYS_recvfrom
    {"recvfrom", SYS_recvfrom},
#endif
#ifdef SYS_recvmmsg
    {"recvmmsg", SYS_recvmmsg},
#endif
#ifdef SYS_recvmmsg_time64
    {"recvmmsg_time64", SYS_recvmmsg_time64},
#endif
#ifdef SYS_recvmsg
    {"recvmsg", SYS_recvmsg},
#endif
#ifdef SYS_remap_file_pages
    {"remap_file_pages", SYS_remap_file_pages},
#endif
#ifdef SYS_removexattr
    {"removexattr", SYS_removexattr},
#endif
#ifdef SYS_rename
    {"rename", SYS_rename},
#endif
#ifdef SYS_renameat
    {"renameat", SYS_renameat},
#endif
#ifdef SYS_renameat2
    {"renameat2", SYS_renameat2},
#endif
#ifdef SYS_request_key
    {"request_key", SYS_request_key},
#endif
#ifdef SYS_restart_syscall
    {"restart_syscall", SYS_restart_syscall},
#endif
#ifdef SYS_riscv_flush_icache
    {"riscv_flush_icache", SYS_riscv_flush_icache},
#endif
#ifdef SYS_riscv_hwprobe
    {"riscv_hwprobe", SYS_riscv_hwprobe},
#endif
#ifdef SYS_rmdir
    {"rmdir", SYS_rmdir},
#endif
#ifdef SYS_rseq
    {"rseq", SYS_rseq},
#endif
#ifdef SYS_rt_sigaction
    {"rt_sigaction", SYS_rt_sigaction},
#endif
#ifdef SYS_rt_sigpending
    {"rt_sigpending", SYS_rt_sigpending},
#endif
#ifdef SYS_rt_sigprocmask
    {"rt_sigprocmask", SYS_rt_sigprocmask},
#endif
#ifdef SYS_rt_sigqueueinfo
    {"rt_sigqueueinfo", SYS_rt_sigqueueinfo},
#endif
#ifdef SYS_rt_sigreturn
    {"rt_sigreturn", SYS_rt_sigreturn},
#endif
#ifdef SYS_rt_sigsuspend
    {"rt_sigsuspend", SYS_rt_sigsuspend},
#endif
#ifdef SYS_rt_sigtimedwait
    {"rt_sigtimedwait", SYS_rt_sigtimedwait},
#endif
#ifdef SYS_rt_sigtimedwait_time64
    {"rt_sigtimedwait_time64", SYS_rt_sigtimedwait_time64},
#endif
#ifdef SYS_rt_tgsigqueueinfo
    {"rt_tgsigqueueinfo", SYS_rt_tgsigqueueinfo},
#endif
#ifdef SYS_rtas
    {"rtas", SYS_rtas},
#endif
#ifdef SYS_s390_guarded_storage
    {"s390_guarded_storage", SYS_s390_guarded_storage},
#endif
#ifdef SYS_s390_pci_mmio_read
    {"s390_pci_mmio_read", SYS_s390_pci_mmio_read},
#endif
#ifdef SYS_s390_pci_mmio_write
    {"s390_pci_mmio_write", SYS_s390_pci_mmio_write},
#endif
#ifdef SYS_s390_runtime_instr
    {"s390_runtime_instr", SYS_s390_runtime_instr},
#endif
#ifdef SYS_s390_sthyi
    {"s390_sthyi", SYS_s390_sthyi},
#endif
#ifdef SYS_sched_get_affinity
    {"sched_get_affinity", SYS_sched_get_affinity},
#endif
#ifdef SYS_sched_get_priority_max
    {"sched_get_priority_max", SYS_sched_get_priority_max},
#endif
#ifdef SYS_sched_get_priority_min
    {"sched_get_priority_min", SYS_sched_get_priority_min},
#endif
#ifdef SYS_sched_getaffinity
    {"sched_getaffinity", SYS_sched_getaffinity},
#endif
#ifdef SYS_sched_getattr
    {"sched_getattr", SYS_sched_getattr},
#endif
#ifdef SYS_sched_getparam
    {"sched_getparam", SYS_sched_getparam},
#endif
#ifdef SYS_sched_getscheduler
    {"sched_getscheduler", SYS_sched_getscheduler},
#endif
#ifdef SYS_sched_rr_get_interval
    {"sched_rr_get_interval", SYS_sched_rr_get_interval},
#endif
#ifdef SYS_sched_rr_get_interval_time64
    {"sched_rr_get_interval_time64", SYS_sched_rr_get_interval_time64},
#endif
#ifdef SYS_sched_set_affinity
    {"sched_set_affinity", SYS_sched_set_affinity},
#endif
#ifdef SYS_sched_setaffinity
    {"sched_setaffinity", SYS_sched_setaffinity},
#endif
#ifdef SYS_sched_setattr
    {"sched_setattr", SYS_sched_setattr},
#endif
#ifdef SYS_sched_setparam
    {"sched_setparam", SYS_sched_setparam},
#endif
#ifdef SYS_sched_setscheduler
    {"sched_setscheduler", SYS_sched_setscheduler},
#endif
#ifdef SYS_sched_yield
    {"sched_yield", SYS_sched_yield},
#endif
#ifdef SYS_seccomp
    {"seccomp", SYS_seccomp},
#endif
#ifdef SYS_security
    {"security", SYS_security},
#endif
#ifdef SYS_select
    {"select", SYS_select},
#endif
#ifdef SYS_semctl
    {"semctl", SYS_semctl},
#endif
#ifdef SYS_semget
    {"semget", SYS_semget},
#endif
#ifdef SYS_semop
    {"semop", SYS_semop},
#endif
#ifdef SYS_semtimedop
    {"semtimedop", SYS_semtimedop},
#endif
#ifdef SYS_semtimedop_time64
    {"semtimedop_time64", SYS_semtimedop_time64},
#endif
#ifdef SYS_send
    {"send", SYS_send},
#endif
#ifdef SYS_sendfile
    {"sendfile", SYS_sendfile},
#endif
#ifdef SYS_sendfile64
    {"sendfile64", SYS_sendfile64},
#endif
#ifdef SYS_sendmmsg
    {"sendmmsg", SYS_sendmmsg},
#endif
#ifdef SYS_sendmsg
    {"sendmsg", SYS_sendmsg},
#endif
#ifdef SYS_sendto
    {"sendto", SYS_sendto},
#endif
#ifdef SYS_set_mempolicy
    {"set_mempolicy", SYS_set_mempolicy},
#endif
#ifdef SYS_set_mempolicy_home_node
    {"set_mempolicy_home_node", SYS_set_mempolicy_home_node},
#endif
#ifdef SYS_set_robust_list
    {"set_robust_list", SYS_set_robust_list},
#endif
#ifdef SYS_set_thread_area
    {"set_thread_area", SYS_set_thread_area},
#endif
#ifdef SYS_set_tid_address
    {"set_tid_address", SYS_set_tid_address},
#endif
#ifdef SYS_set_tls
    {"set_tls", SYS_set_tls},
#endif
#ifdef SYS_setdomainname
    {"setdomainname", SYS_setdomainname},
#endif
#ifdef SYS_setfsgid
    {"setfsgid", SYS_setfsgid},
#endif
#ifdef SYS_setfsgid32
    {"setfsgid32", SYS_setfsgid32},
#endif
#ifdef SYS_setfsuid
    {"setfsuid", SYS_setfsuid},
#endif
#ifdef SYS_setfsuid32
    {"setfsuid32", SYS_setfsuid32},
#endif
#ifdef SYS_setgid
    {"setgid", SYS_setgid},
#endif
#ifdef SYS_setgid32
    {"setgid32", SYS_setgid32},
#endif
#ifdef SYS_setgroups
    {"setgroups", SYS_setgroups},
#endif
#ifdef SYS_setgroups32
    {"setgroups32", SYS_setgroups32},
#endif
#ifdef SYS_sethae
    {"sethae", SYS_sethae},
#endif
#ifdef SYS_sethostname
    {"sethostname", SYS_sethostname},
#endif
#ifdef SYS_setitimer
    {"setitimer", SYS_setitimer},
#endif
#ifdef SYS_setns
    {"setns", SYS_setns},
#endif
#ifdef SYS_setpgid
    {"setpgid", SYS_setpgid},
#endif
#ifdef SYS_setpgrp
    {"setpgrp", SYS_setpgrp},
#endif
#ifdef SYS_setpriority
    {"setpriority", SYS_setpriority},
#endif
#ifdef SYS_setregid
    {"setregid", SYS_setregid},
#endif
#ifdef SYS_setregid32
    {"setregid32", SYS_setregid32},
#endif
#ifdef SYS_setresgid
    {"setresgid", SYS_setresgid},
#endif
#ifdef SYS_setresgid32
    {"setresgid32", SYS_setresgid32},
#endif
#ifdef SYS_setresuid
    {"setresuid", SYS_setresuid},
#endif
#ifdef SYS_setresuid32
    {"setresuid32", SYS_setresuid32},
#endif
#ifdef SYS_setreuid
    {"setreuid", SYS_setreuid},
#endif
#ifdef SYS_setreuid32
    {"setreuid32", SYS_setreuid32},
#endif
#ifdef SYS_setrlimit
    {"setrlimit", SYS_setrlimit},
#endif
#ifdef SYS_setsid
    {"setsid", SYS_setsid},
#endif
#ifdef SYS_setsockopt
    {"setsockopt", SYS_setsockopt},
#endif
#ifdef SYS_settimeofday
    {"settimeofday", SYS_settimeofday},
#endif
#ifdef SYS_setuid
    {"setuid", SYS_setuid},
#endif
#ifdef SYS_setuid32
    {"setuid32", SYS_setuid32},
#endif
#ifdef SYS_setxattr
    {"setxattr", SYS_setxattr},
#endif
#ifdef SYS_sgetmask
    {"sgetmask", SYS_sgetmask},
#endif
#ifdef SYS_shmat
    {"shmat", SYS_shmat},
#endif
#ifdef SYS_shmctl
    {"shmctl", SYS_shmctl},
#endif
#ifdef SYS_shmdt
    {"shmdt", SYS_shmdt},
#endif
#ifdef SYS_shmget
    {"shmget", SYS_shmget},
#endif
#ifdef SYS_shutdown
    {"shutdown", SYS_shutdown},
#endif
#ifdef SYS_sigaction
    {"sigaction", SYS_sigaction},
#endif
#ifdef SYS_sigaltstack
    {"sigaltstack", SYS_sigaltstack},
#endif
#ifdef SYS_signal
    {"signal", SYS_signal},
#endif
#ifdef SYS_signalfd
    {"signalfd", SYS_signalfd},
#endif
#ifdef SYS_signalfd4
    {"signalfd4", SYS_signalfd4},
#endif
#ifdef SYS_sigpending
    {"sigpending", SYS_sigpending},
#endif
#ifdef SYS_sigprocmask
    {"sigprocmask", SYS_sigprocmask},
#endif
#ifdef SYS_sigreturn
    {"sigreturn", SYS_sigreturn},
#endif
#ifdef SYS_sigsuspend
    {"sigsuspend", SYS_sigsuspend},
#endif
#ifdef SYS_socket
    {"socket", SYS_socket},
#endif
#ifdef SYS_socketcall
    {"socketcall", SYS_socketcall},
#endif
#ifdef SYS_socketpair
    {"socketpair", SYS_socketpair},
#endif
#ifdef SYS_splice
    {"splice", SYS_splice},
#endif
#ifdef SYS_spu_create
    {"spu_create", SYS_spu_create},
#endif
#ifdef SYS_spu_run
    {"spu_run", SYS_spu_run},
#endif
#ifdef SYS_ssetmask
    {"ssetmask", SYS_ssetmask},
#endif
#ifdef SYS_stat
    {"stat", SYS_stat},
#endif
#ifdef SYS_stat64
    {"stat64", SYS_stat64},
#endif
#ifdef SYS_statfs
    {"statfs", SYS_statfs},
#endif
#ifdef SYS_statfs64
    {"statfs64", SYS_statfs64},
#endif
#ifdef SYS_statx
    {"statx", SYS_statx},
#endif
#ifdef SYS_stime
    {"stime", SYS_stime},
#endif
#ifdef SYS_stty
    {"stty", SYS_stty},
#endif
#ifdef SYS_subpage_prot
    {"subpage_prot", SYS_subpage_prot},
#endif
#ifdef SYS_swapcontext
    {"swapcontext", SYS_swapcontext},
#endif
#ifdef SYS_swapoff
    {"swapoff", SYS_swapoff},
#endif
#ifdef SYS_swapon
    {"swapon", SYS_swapon},
#endif
#ifdef SYS_switch_endian
    {"switch_endian", SYS_switch_endian},
#endif
#ifdef SYS_symlink
    {"symlink", SYS_symlink},
#endif
#ifdef SYS_symlinkat
    {"symlinkat", SYS_symlinkat},
#endif
#ifdef SYS_sync
    {"sync", SYS_sync},
#endif
#ifdef SYS_sync_file_range
    {"sync_file_range", SYS_sync_file_range},
#endif
#ifdef SYS_sync_file_range2
    {"sync_file_range2", SYS_sync_file_range2},
#endif
#ifdef SYS_syncfs
    {"syncfs", SYS_syncfs},
#endif
#ifdef SYS_sys_debug_setcontext
    {"sys_debug_setcontext", SYS_sys_debug_setcontext},
#endif
#ifdef SYS_sys_epoll_create
    {"sys_epoll_create", SYS_sys_epoll_create},
#endif
#ifdef SYS_sys_epoll_ctl
    {"sys_epoll_ctl", SYS_sys_epoll_ctl},
#endif
#ifdef SYS_sys_epoll_wait
    {"sys_epoll_wait", SYS_sys_epoll_wait},
#endif
#ifdef SYS_syscall
    {"syscall", SYS_syscall},
#endif
#ifdef SYS_sysfs
    {"sysfs", SYS_sysfs},
#endif
#ifdef SYS_sysinfo
    {"sysinfo", SYS_sysinfo},
#endif
#ifdef SYS_syslog
    {"syslog", SYS_syslog},
#endif
#ifdef SYS_sysmips
    {"sysmips", SYS_sysmips},
#endif
#ifdef SYS_tee
    {"tee", SYS_tee},
#endif
#ifdef SYS_tgkill
    {"tgkill", SYS_tgkill},
#endif
#ifdef SYS_time
    {"time", SYS_time},
#endif
#ifdef SYS_timer_create
    {"timer_create", SYS_timer_create},
#endif
#ifdef SYS_timer_delete
    {"timer_delete", SYS_timer_delete},
#endif
#ifdef SYS_timer_getoverrun
    {"timer_getoverrun", SYS_timer_getoverrun},
#endif
#ifdef SYS_timer_gettime
    {"timer_gettime", SYS_timer_gettime},
#endif
#ifdef SYS_timer_gettime64
    {"timer_gettime64", SYS_timer_gettime64},
#endif
#ifdef SYS_timer_settime
    {"timer_settime", SYS_timer_settime},
#endif
#ifdef SYS_timer_settime64
    {"timer_settime64", SYS_timer_settime64},
#endif
#ifdef SYS_timerfd
    {"timerfd", SYS_timerfd},
#endif
#ifdef SYS_timerfd_create
    {"timerfd_create", SYS_timerfd_create},
#endif
#ifdef SYS_timerfd_gettime
    {"timerfd_gettime", SYS_timerfd_gettime},
#endif
#ifdef SYS_timerfd_gettime64
    {"timerfd_gettime64", SYS_timerfd_gettime64},
#endif
#ifdef SYS_timerfd_settime
    {"timerfd_settime", SYS_timerfd_settime},
#endif
#ifdef SYS_timerfd_settime64
    {"timerfd_settime64", SYS_timerfd_settime64},
#endif
#ifdef SYS_times
    {"times", SYS_times},
#endif
#ifdef SYS_tkill
    {"tkill", SYS_tkill},
#endif
#ifdef SYS_truncate
    {"truncate", SYS_truncate},
#endif
#ifdef SYS_truncate64
    {"truncate64", SYS_truncate64},
#endif
#ifdef SYS_tuxcall
    {"tuxcall", SYS_tuxcall},
#endif
#ifdef SYS_udftrap
    {"udftrap", SYS_udftrap},
#endif
#ifdef SYS_ugetrlimit
    {"ugetrlimit", SYS_ugetrlimit},
#endif
#ifdef SYS_ulimit
    {"ulimit", SYS_ulimit},
#endif
#ifdef SYS_umask
    {"umask", SYS_umask},
#endif
#ifdef SYS_umount
    {"umount", SYS_umount},
#endif
#ifdef SYS_umount2
    {"umount2", SYS_umount2},
#endif
#ifdef SYS_uname
    {"uname", SYS_uname},
#endif
#ifdef SYS_unlink
    {"unlink", SYS_unlink},
#endif
#ifdef SYS_unlinkat
    {"unlinkat", SYS_unlinkat},
#endif
#ifdef SYS_unshare
    {"unshare", SYS_unshare},
#endif
#ifdef SYS_uselib
    {"uselib", SYS_uselib},
#endif
#ifdef SYS_userfaultfd
    {"userfaultfd", SYS_userfaultfd},
#endif
#ifdef SYS_usr26
    {"usr26", SYS_usr26},
#endif
#ifdef SYS_usr32
    {"usr32", SYS_usr32},
#endif
#ifdef SYS_ustat
    {"ustat", SYS_ustat},
#endif
#ifdef SYS_utime
    {"utime", SYS_utime},
#endif
#ifdef SYS_utimensat
    {"utimensat", SYS_utimensat},
#endif
#ifdef SYS_utimensat_time64
    {"utimensat_time64", SYS_utimensat_time64},
#endif
#ifdef SYS_utimes
    {"utimes", SYS_utimes},
#endif
#ifdef SYS_utrap_install
    {"utrap_install", SYS_utrap_install},
#endif
#ifdef SYS_vfork
    {"vfork", SYS_vfork},
#endif
#ifdef SYS_vhangup
    {"vhangup", SYS_vhangup},
#endif
#ifdef SYS_vm86
    {"vm86", SYS_vm86},
#endif
#ifdef SYS_vm86old
    {"vm86old", SYS_vm86old},
#endif
#ifdef SYS_vmsplice
    {"vmsplice", SYS_vmsplice},
#endif
#ifdef SYS_vserver
    {"vserver", SYS_vserver},
#endif
#ifdef SYS_wait4
    {"wait4", SYS_wait4},
#endif
#ifdef SYS_waitid
    {"waitid", SYS_waitid},
#endif
#ifdef SYS_waitpid
    {"waitpid", SYS_waitpid},
#endif
#ifdef SYS_write
    {"write", SYS_write},
#endif
#ifdef SYS_writev
    {"writev", SYS_writev},
#endif
    {NULL, 0},
};
