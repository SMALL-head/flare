package ns

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
)

var (
	ErrGetStat = errors.New("GetStat: file not found")
)

func mntNSPath(pid uint32) string {
	return fmt.Sprintf("/proc/%d/ns/mnt", pid)
}

func fileExist(path string) bool {
	// 检查路径是否存在
	_, err := os.Stat(path)
	if err == nil {
		return true
	}
	if os.IsNotExist(err) {
		return false
	}
	return true
}

// GetFileInodeInContainer 获取 pid 对应的mnt命名空间，pid应该是容器的进程对应的pid，可以通过docker inspect获取
func GetFileInodeInContainer(containerPid, filePath string) (uint32, error) {
	cmd := exec.Command("sudo", "nsenter", "--target", containerPid, "--mount", "stat", "--format", "%i", filePath)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return 0, err
	}

	inodeStr := strings.TrimSpace(string(output))
	inode, err := strconv.ParseUint(inodeStr, 10, 32)
	if err != nil {
		return 0, err
	}
	return uint32(inode), nil
}
