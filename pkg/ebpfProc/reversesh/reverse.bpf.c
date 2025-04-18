//go:build ignore

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "reverse.h"

// key的比较方式是通过字节内容比较的。因此最好不要在key的结构体里面使用指针
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 20480);
    __type(key, struct fd_key_t);
    __type(value, struct fd_value_t);
} fd_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 20480);
    __type(key, struct fd_key_t);
    __type(value, struct fd_value_t);
} fd_map2 SEC(".maps");

// 为了在go中调用event_t，出此下策
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, u32);
    __type(value, struct event_t);

} dummy SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u32));
} events SEC(".maps");

static void get_file_path(const struct file *file, char *dst_buf, size_t sz) {
    struct qstr dname;
    // 注意，此时的dname虽然被拷贝至用户态了，但是他的dname.name仍然不能访问
    dname = BPF_CORE_READ(file, f_path.dentry, d_name);
    bpf_probe_read(dst_buf, sz, dname.name);
}

static __always_inline bool str_eq(const char *q1, const char *q2, size_t sz) {
    for (int i = 0; i < sz; i++) {
        if (q1[i] != q2[i]) {
            return false;
        }
        // 假设q1是短的那个
        if (q1[i] == '\0') {
            break;
        }
    }
    return true;
}

static __always_inline int str_len(const char* s, int max_len) {
    int i = 0;
    for (; i < max_len; i++) {
        if (s[i] == '\0') {
            return i;
        }
    }

    if (s[max_len - 1] != '\0')
        return max_len;
    return 0;
}

// 后面的参数是怎么知道的呢？
// 参考语雀文档:https://www.yuque.com/carlson-zyc/ai6czl/wdm0qlgwcwm4zbfw 中的1.7
SEC("kprobe/fd_install")
int BPF_KPROBE(kprobe__fd_install, unsigned int fd, struct file *file) {
    struct fd_key_t key = {0};
    struct fd_value_t value = {0};
    // struct event_t event = {0};
    key.fd = fd;
    key.pid = bpf_get_current_pid_tgid() >> 32;

    get_file_path(file, value.filename, sizeof(value.filename));
    char tcp_filename_prefix[4] = "TCP";

    // fd == 0,1,2的判断貌似不需要啊
    if (!(fd == 0 || fd == 1 || fd == 2 || str_eq(value.filename, tcp_filename_prefix, 4))) {
        // 不属于追踪的文件范畴
        return 0;
    }
    bpf_map_update_elem(&fd_map, &key, &value, BPF_ANY);
    // bpf_printk("[] fd_install: pid %d, fd %d, filename %s\n", key.pid, key.fd, value.filename); 

    return 0;
}

static bool handler_dup_event(struct trace_event_raw_sys_enter *ctx) {
    struct fd_key_t key1 = { 0 };
    struct fd_key_t key2 = { 0 };
    struct event_t event = { 0 };

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    if (task) {
        event.ppid = BPF_CORE_READ(task, real_parent, tgid);
    }

    // args第一个参数是oldfd，第二个参数是newfd
    // 可通过cat /sys/kernel/tracing/events/syscalls/sys_enter_dup2/format查看
    key1.pid = bpf_get_current_pid_tgid() >> 32;
    key2.pid = event.ppid;
    
    key1.fd = (u32)BPF_CORE_READ(ctx, args[0]);
    key2.fd = key1.fd;
    // key.fd = 3;
    struct fd_value_t *value1 = bpf_map_lookup_elem(&fd_map, &key1);
    struct fd_value_t *value2 = bpf_map_lookup_elem(&fd_map2, &key2);

    // event赋值
    event.pid = key1.pid;
    event.src_fd = (u32)BPF_CORE_READ(ctx, args[1]);
    event.dst_fd = key1.fd;

    if ( value2) {
        // 另一种重定向的检验， 例如 oldfd=219, newfd=0/1/2，需要在fd_map2中找匹配项
        // 二次重定向命中
        bpf_printk("dup2 - value2 enter: pid %d, fd %d, filename %s\n", key2.pid, key2.fd, value2->filename);
        u64 t = bpf_ktime_get_ns();
            event.trigger_time = t;
            
            bpf_get_current_comm(&event.comm, sizeof(event.comm));
            // 莫非在map里的值也属于kernel空间，所以这里的value也不能直接读取
            bpf_probe_read_kernel_str(&event.dst_fd_filename, sizeof(event.dst_fd_filename), value1->filename);
    
            // 实际编程的时候才发现这里很混乱，
            // 因为perfmap中的value的大小给的是指针的大小，那这里的最后的一个参数给的似乎就是event本身的大小了
            bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event, sizeof(event));
            return true;
    } 

    if (value1) {
        // 命中tcp文件，但是重定向的newfd不是0/1/2，而是另一个值，此时需要将相关信息放置在fd_map2中，例如oldfd=3, newfd=219
        bpf_printk("dup2 - value1 enter: pid %d, fd %d, filename %s\n", key1.pid, key1.fd, value1->filename);
        if (event.src_fd == 0 || event.src_fd == 1 || event.src_fd == 2) {
            u64 t = bpf_ktime_get_ns();
            event.trigger_time = t;
            
            bpf_get_current_comm(&event.comm, sizeof(event.comm));
            // 莫非在map里的值也属于kernel空间，所以这里的value也不能直接读取
            bpf_probe_read_kernel_str(&event.dst_fd_filename, sizeof(event.dst_fd_filename), value1->filename);
    
            // 实际编程的时候才发现这里很混乱，
            // 因为perfmap中的value的大小给的是指针的大小，那这里的最后的一个参数给的似乎就是event本身的大小了
            bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event, sizeof(event));
            return true;
        } else {
            bpf_printk("dup2 - value1 else branch: pid %d, fd %d, filename %s\n", key1.pid, key1.fd, value1->filename);
            struct fd_value_t v = {0};
            key2.fd = (u32)BPF_CORE_READ(ctx, args[1]);
            key2.pid = event.pid;
            bpf_probe_read_kernel_str(&v.filename, sizeof(v.filename), value1->filename);
            bpf_map_update_elem(&fd_map2, &key2, &v, BPF_ANY);
        }

        // 注：src重定向到dst文件上
        // if (!(event.src_fd == 0 || event.src_fd == 1 || event.src_fd == 2)) {
        //     return false;
        // }

        // if (
        //     !(event.dst_fd == 0 || event.dst_fd == 1 || event.dst_fd == 2)) {
        //     return false;
        // }
        // if (!(event.src_fd == 0 || event.src_fd == 1 || event.src_fd == 2) && 
        //     !(event.dst_fd == 0 || event.dst_fd == 1 || event.dst_fd == 2)) {
        //     return false;
        // }

    }

    return true;
}

SEC("tracepoint/syscalls/sys_enter_dup2")
int tracepoint_syscalls__sys_enter_dup2(struct trace_event_raw_sys_enter *ctx) {
    if (handler_dup_event(ctx)) {
        // bpf_send_signal(SIGKILL);
        return -1;
    }
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_dup3")
int tracepoint_syscalls__sys_enter_dup3(struct trace_event_raw_sys_enter *ctx) {
    if (handler_dup_event(ctx)) {
        // bpf_send_signal(SIGKILL);
        return -1;
    }
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_close")
int tracepoint_syscalls__sys_enter_close(struct trace_event_raw_sys_enter *ctx) {
    struct fd_key_t key = { 0 };

    key.pid = bpf_get_current_pid_tgid() >> 32;
    key.fd = (u32)BPF_CORE_READ(ctx, args[0]);

    bpf_map_delete_elem(&fd_map, &key);

    return 0;
}

char _license[] SEC("license") = "GPL";