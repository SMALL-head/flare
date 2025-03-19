//go:build ignore

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "common.h"
#include "fileAudit.h"

// 为了在go中调用event_t，出此下策
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, struct event_t);
} dummy SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u32));
} file_audit_events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 200); // 一台主机200个ns也算挺充足的
    __type(key, u32);
    __type(value, struct file_info_map);
} audit_files_map SEC(".maps");

static __always_inline int str_len(const char *str, int max_len) {
    int len = 0;
    while (len < max_len && str[len] != '\0') {
        len++;
    }
    return len;
}

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

SEC("lsm/file_open")
int BPF_PROG(lsm_file_open_container, struct file *file) {
    struct event_t event = {};
    // 获取上下文命令
    event.pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&event.comm, sizeof(event.comm));

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    struct nsproxy *proxy = BPF_CORE_READ(task, nsproxy);
    event.mnt_ns_inode = (unsigned int)BPF_CORE_READ(proxy, mnt_ns, ns.inum);

    // inode比较统一转化为unsigned int，otherwise会有出乎意料的比较结果false发生
    // if ((unsigned int)event.mnt_ns_inode != (unsigned int)4026532680) {
    //     // 我只想看特定的ns的日志，要不然日志太多不方便调试
    //     return 0;
    // }

    struct file_info_map *audit_files = bpf_map_lookup_elem(&audit_files_map, &event.mnt_ns_inode);

    if (!audit_files) {
        return 0;
    }

    // for (int i = 0; i < MAX_FILES_PER_NS; i++) {
    //     // 调试阶段，打打日志看看是个什么情况
    //     if (audit_files->files[i] == 0) {
    //         // break if the file_path is empty
    //         break;
    //     }
    //     bpf_printk("audit_files->files[%d].file_inode: %u", i, audit_files->files[i]);
    // }

    // 获取文件名称（利用入参file）
    struct qstr dname;
    dname = BPF_CORE_READ(file, f_path.dentry, d_name); // dname.name是一个指针，他的value本质上还是属于内核空间，因此这里不能直接拷贝，而要使用相关的内核信息读取函数
    bpf_probe_read_kernel(event.filename, sizeof(event.filename), dname.name);
    // unsigned int file_inode = (unsigned int)BPF_CORE_READ(file, f_inode, i_ino);
    // if (str_eq(event.filename, "a.txt", str_len("a.txt", MAX_FILRNAME_LEN))) {
    //     bpf_printk("file a.txt is opened. file inode = %d", file_inode);
    // }
    bool is_audit_file = false;
    unsigned int file_inode = (unsigned int)BPF_CORE_READ(file, f_inode, i_ino);
    event.file_inode = file_inode;
    for (int i = 0; i < MAX_FILES_PER_NS; i++) {
        if (audit_files->files[i] == 0) {
            // break if the file_path is empty
            break;
        }
        if (audit_files->files[i] == file_inode) {
            // 如果文件inode在审计列表中，那么记录审计事件
            struct qstr dname;
            dname = BPF_CORE_READ(file, f_path.dentry, d_name); // dname.name是一个指针，他的value本质上还是属于内核空间，因此这里不能直接拷贝，而要使用相关的内核信息读取函数
            bpf_probe_read_kernel(event.filename, sizeof(event.filename), dname.name);
            is_audit_file = true;
            break;
        }
    }

    // 获取文件打开的mode
    event.fmode = BPF_CORE_READ(file, f_mode);

    // 将事件提交到events中供用户态程序消费
    if (is_audit_file) {
        // 如果flare那边你看到了多次审计结果，那么你一定会溯源到这里来。 
        // 先说结论：一个命令可能会触发open多次。一个命令，例如'cat'，kernel function中可能涉及到对同一个文件的多次open操作。
        // 从审计的角度来说，这很多余，但是这是kernel的行为，我们无法改变。所以，如果你看到了多次审计结果，不要惊慌，这是正常的。
        // bpf_printk("send perf event");
        bpf_perf_event_output(ctx, &file_audit_events, BPF_F_CURRENT_CPU, &event, sizeof(event));
    }

    // return value将会控制该行为是否拦截
    return 0;
}

char _license[] SEC("license") = "GPL";
