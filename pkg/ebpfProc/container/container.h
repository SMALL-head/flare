//go:build ignore
#define SIGKILL 9
#define MAX_FILES_PER_NS 10

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

struct files_inode {
    unsigned int file_inode[MAX_FILES_PER_NS]
};