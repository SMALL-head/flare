//go:build ignore

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "container.h"

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, pid_t);
    __type(value, struct event_t);
} execs SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u32));
} events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, u32);
    __type(value, struct info);
} infos SEC(".maps");

struct {
    __uint(type , BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, char[160]);
    __type(value, bool);
} audit_files SEC(".maps");

static __always_inline bool str_eq(const char *str1, const char *str2, int len) {
    for (int i = 0; i < len; i++) {
        if (str1[i] != str2[i]) {
            return false;
        }
        if (str1[i] == '\0') {
            break;
        }
    }
    return true;
}

// SEC("tracepoint/syscalls/sys_enter_execve")
// int tracepoint_syscalls__intercept_tail(struct trace_event_raw_sys_enter *ctx) {
//     pid_t tid;
//     struct event_t event = {};
//     struct task_struct *task;
//     char *filename;

//     tid = (pid_t)bpf_get_current_pid_tgid();
//     task = (struct task_struct*)bpf_get_current_task();
//     // 执行操作的进程 id
//     event.ppid = (pid_t)BPF_CORE_READ(task, real_parent, tgid);
//     // 获取进程 id
//     event.pid = bpf_get_current_pid_tgid() >> 32;
//     // 执行 execve 的进程名称
//     bpf_get_current_comm(&event.comm, sizeof(event.comm));
//     // 从 ctx->args[0] 中获取被执行的程序的名称
//     filename = (char *)BPF_CORE_READ(ctx, args[0]);
//     bpf_probe_read_user_str(event.filename, sizeof(event.filename), filename);
//     const char* cmd = "/usr/bin/tail";
//     if (str_eq(event.filename, cmd, 14)) {
//         struct nsproxy* proxy = BPF_CORE_READ(task, nsproxy);
//         bpf_printk("%u", (unsigned int)BPF_CORE_READ(proxy, net_ns, ns.inum));
//         bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event, sizeof(event));
//     }
//     return 0;
// }

SEC("tracepoint/syscalls/sys_enter_execve")
int tracepoint_syscalls_interact_with_userspace(struct trace_event_raw_sys_enter *ctx) {
    char exec_filename[160];
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    char *ctx_args0 = (char *)BPF_CORE_READ(ctx, args[0]);
    const char *cmd = "/usr/bin/tail";
    bpf_probe_read_user_str(exec_filename, sizeof(exec_filename), ctx_args0);
    if (str_eq(exec_filename, cmd, 14)) {
        // 获取mnt命名空间的inode
        u32 key = 4026532680;
        struct nsproxy* proxy = BPF_CORE_READ(task, nsproxy);
        unsigned int mnt_ns_inode = (unsigned int)BPF_CORE_READ(proxy, mnt_ns, ns.inum);
        key = mnt_ns_inode;
        struct info *ptr = (struct info*)bpf_map_lookup_elem(&infos, &mnt_ns_inode);
        // struct info *ptr = bpf_map_lookup_elem(&infos, &key);
        if (!ptr) {
            // 打印没有找到的日志
            // bpf_printk("not found info in map: mnt_inode = %u", mnt_ns_inode);
            bpf_printk("not found info in map: mnt_inode = %u", key);
            return 0;
        }
        bpf_printk("tail in inode = %u is triggered", key);
        // bpf_printk("find info in map: msg = %s, number = %d, mnt_inode = %u", val->msg, val->number, mnt_ns_inode);
    }
    return 0;
}

char _license[] SEC("license") = "GPL";