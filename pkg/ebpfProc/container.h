//go:build ignore
#define SIGKILL 9

struct event_t {
    pid_t ppid;
    pid_t pid;
    unsigned int mnt_ns_inode;
    char comm[16];
    char filename[160];
};

struct info {
    char msg[16];
    int number;
};