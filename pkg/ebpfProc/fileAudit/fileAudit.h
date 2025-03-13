#define TASK_COMM_LEN 16
#define MAX_FILRNAME_LEN 160
#define MAX_FILES_PER_NS 10 // 每个ns最多审计10个文件

struct file_info_map {
    unsigned int files[MAX_FILES_PER_NS];
};