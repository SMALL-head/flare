package proc

import (
	"bufio"
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"

	"github.com/sirupsen/logrus"
)

var (
	nsDirNames = map[string]func(p *nsProxy, val uint32){
		"cgroup": func(p *nsProxy, val uint32) { p.cgroup = val },
		"ipc":    func(p *nsProxy, val uint32) { p.ipc = val },
		"mnt":    func(p *nsProxy, val uint32) { p.mnt = val },
		"net":    func(p *nsProxy, val uint32) { p.net = val },
		"pid":    func(p *nsProxy, val uint32) { p.pid = val },
		"uts":    func(p *nsProxy, val uint32) { p.uts = val },
		"time":   func(p *nsProxy, val uint32) { p.time = val },
	}
)

// nsProxy 存放各个命名空间对应的inode号
type nsProxy struct {
	cgroup uint32
	ipc    uint32
	mnt    uint32
	net    uint32
	pid    uint32
	uts    uint32
	time   uint32
}

type ProcInfo struct {
	Pid     string
	Ppid    string
	Name    string
	Nsproxy nsProxy
}

func (n *nsProxy) GetCgroup() uint32 {
	return n.cgroup
}
func (n *nsProxy) GetIpc() uint32 {
	return n.ipc
}
func (n *nsProxy) GetMnt() uint32 {
	return n.mnt
}
func (n *nsProxy) GetNet() uint32 {
	return n.net
}
func (n *nsProxy) GetPid() uint32 {
	return n.pid
}
func (n *nsProxy) GetUts() uint32 {
	return n.uts
}
func (n *nsProxy) GetTime() uint32 {
	return n.time
}

func GetProcInfo(pid string) (*ProcInfo, error) {
	procDirName := fmt.Sprintf("/proc/%s", pid)
	_, err := os.ReadDir(procDirName)
	if err != nil {
		// 目录不存在，应该直接返回
		return nil, err
	}
	// 读status文件获取pid，ppid和name信息
	file, err := os.Open(procDirName + "/status")
	if err != nil {
		// 这不会发生吧
		return nil, err
	}
	resInfo := &ProcInfo{}
	reader := bufio.NewReader(file)
	statusFileParser(reader, resInfo)
	nsParser(procDirName, resInfo)
	return resInfo, nil
}

func statusFileParser(reader *bufio.Reader, info *ProcInfo) error {
	s, _, err := reader.ReadLine()
	if err != nil {
		return err
	}
	// parse name
	lineS := string(s)
	splitRes := strings.Split(lineS, ":")
	info.Name = strings.TrimSpace(splitRes[1])

	// 跳过4行
	for range 4 {
		reader.ReadLine()
	}

	s, _, err = reader.ReadLine()
	if err != nil {
		return err
	}
	// parse pid
	lineS = string(s)
	splitRes = strings.Split(lineS, ":")
	info.Pid = strings.TrimSpace(splitRes[1])

	// parse ppid
	s, _, err = reader.ReadLine()
	if err != nil {
		return err
	}
	lineS = string(s)
	splitRes = strings.Split(lineS, ":")
	info.Ppid = strings.TrimSpace(splitRes[1])
	return nil
}

func nsParser(baseDir string, info *ProcInfo) {
	// 遍历所有的ns，将inode号写上
	for nsName, fillInFunc := range nsDirNames {
		ns := baseDir + "/ns/" + nsName
		linkContent, err := os.Readlink(ns)
		if err != nil {
			logrus.Errorf("[nsParser] - 获取命名空间%s失败, err = %s", ns, err)
			continue
		}
		pattern := regexp.MustCompile("^[a-z]+:\\[(\\d+)]$")

		matchStr := pattern.FindStringSubmatch(linkContent) // eg: ["cgroup:[4026531835]", "4026531835"]
		inodeNum, err := strconv.ParseUint(matchStr[1], 10, 32)
		if err != nil {
			logrus.Errorf("[nsParser] - 解析inode number错误, %s, err = %v", matchStr[1], err)
			continue
		}
		fillInFunc(&info.Nsproxy, uint32(inodeNum))
	}
}

func PrintNsInode(baseDir string) {
	for nsName := range nsDirNames {
		ns := baseDir + "/ns/" + nsName
		linkContent, err := os.Readlink(ns)
		if err != nil {
			logrus.Errorf("[PrintNsInode] - 获取命名空间%s失败, err = %s", ns, err)
			continue
		}

		logrus.Infof("nsName = %s, linkContent = %s", nsName, linkContent)
	}
}