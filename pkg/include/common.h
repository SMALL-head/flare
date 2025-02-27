//go:build ignore
enum event_type {
    LOG_DATA1 = 1,
    LOG_DATA2 = 2,
    EVENT     = 3,
};

struct general_perf_event {
    int type;  // 用于标识事件类型
    union {
        struct {
            int type;
            char log[256];
        } log_data1;

        struct {
            int type;
            char log[256];
        } log_data2;

        struct {
            pid_t ppid;
            pid_t pid;
            int ret;
            char comm[16];
            char filename[160];
        } event_t;
    };
};

struct event_t {
    pid_t pid;
    int fmode;
    char comm[16];
    char filename[160];
};