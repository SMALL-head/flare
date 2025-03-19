package fileAudit

import (
	"bytes"
	"encoding/binary"
	"errors"
	"flare/pkg/singleton/ebpf/chann"
	"flare/pkg/utils/bpfgo"
	"os"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	"github.com/sirupsen/logrus"
)

var obj fileAuditObjects

func init() {
	if err := loadFileAuditObjects(&obj, nil); err != nil {
		logrus.Fatalf("failed to load fileAuditObjects: %v", err)
	}
}

func RunFileAuditProg() error {
	prog, err := link.AttachLSM(link.LSMOptions{
		Program: obj.fileAuditPrograms.LsmFileOpenContainer,
	})
	if err != nil {
		logrus.Fatalf("failed to attach lsm program: %v", err)
		return err
	}
	defer prog.Close()

	// 设置perf监听
	var event fileAuditEventT
	perfReader, err := perf.NewReader(obj.FileAuditEvents, os.Getpagesize())
	if err != nil {
		logrus.Fatalf("failed to get perf event reader: %v", err)
	}
	for {
		record, err := perfReader.Read()
		if err != nil {
			if errors.Is(err, perf.ErrClosed) {
				return err
			}
			logrus.Fatalf("failed to read record from perf reader: %v", err)
		}
		if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &event); err != nil {
			logrus.Errorf("failed to parse perf event: %s", err)
			continue
		}
		logrus.Printf("[ebpf perf event-fileAudit] - filename = %s, file_inode = %d, comm = %s",
			bpfgo.GoString(event.Filename[:]), event.FileInode, bpfgo.GoString(event.Comm[:]))
	}
}

func HandleAuditFileChan() {
	for {
		select {
		case e := <-chann.GetAddAuditFileChan():
			// TODO: 新增审计文件
			_ = AddAuditFileToMap(e.MntInode, e.FileInode)

		case e := <-chann.GetDeleteAuditFileChan():
			// TODO: 删除审计文件
			_ = DeleteAuditFileInMap(e.MntInode, e.FileInode)
		}
	}
}

func AddAuditFileToMap(mntInode uint32, fileInode uint32) error {
	var item fileAuditFileInfoMap
	err := obj.fileAuditMaps.AuditFilesMap.Lookup(mntInode, &item)
	if err != nil {
		logrus.Errorf("lookup audit file fail, err = %v", err)
		return err
	}
	var i int
	for i = range len(item.Files) {
		if item.Files[i] == 0 {
			item.Files[i] = fileInode
			break
		}
	}
	if i == len(item.Files) {
		logrus.Errorf("audit file map is full")
		return errors.New("audit file map is full")
	}
	logrus.Infof("准备在 i = %d处写文件%d", i, fileInode)
	err = obj.AuditFilesMap.Put(mntInode, &item) // 将item重写回去
	if err != nil {
		logrus.Errorf("add audit file fail, err = %v", err)
	}
	return nil
}

func DeleteAuditFileInMap(mntInode uint32, fileInode uint32) error {
	var item fileAuditFileInfoMap
	err := obj.fileAuditMaps.AuditFilesMap.Lookup(mntInode, &item)
	if err != nil {
		logrus.Errorf("lookup audit file fail, err = %v", err)
		return err
	}
	var i int
	for i = range len(item.Files) {
		if item.Files[i] == fileInode {
			item.Files[i] = 0
			break
		}
	}
	if i == len(item.Files) {
		logrus.Errorf("audit file not found")
		return errors.New("audit file not found")
	}
	err = obj.AuditFilesMap.Put(mntInode, &item) // 将item重写回去
	if err != nil {
		logrus.Errorf("delete audit file fail, err = %v", err)
	}
	return nil
}

// AddMntInodeToMap 创建审计文件的map，key为容器命名空间的Inode号，value为文件的inode号
func AddMntInodeToMap(mntInode uint32) error {
	value := &fileAuditFileInfoMap{}
	value.Files = [10]uint32{}
	if err := obj.fileAuditMaps.AuditFilesMap.Put(mntInode, value); err != nil {
		logrus.Errorf("add mnt inode to audit file map fail, err = %v", err)
		return err
	}
	return nil
}

func DeleteMntInodeInMap(mntInode uint32) error {
	if err := obj.fileAuditMaps.AuditFilesMap.Delete(mntInode); err != nil {
		logrus.Errorf("delete mnt inode in audit file map fail, err = %v", err)
		return err
	}
	return nil
}

func GetMntInodeMap(mntInode uint32) ([10]uint32, error) {
	value := &fileAuditFileInfoMap{}
	err := obj.fileAuditMaps.AuditFilesMap.Lookup(mntInode, value)
	if err != nil {
		return [10]uint32{}, err
	}
	//iter := obj.fileAuditMaps.AuditFilesMap.Iterate()
	//for iter.Next(key, value) {
	//	if key != 0 {
	//		logrus.Infof("key = %d, value = %v", key, value)
	//		file_inode_list := make([]uint32, 0)
	//		for _, each := range value.Files {
	//			if each != 0 {
	//				file_inode_list = append(file_inode_list, each)
	//			}
	//		}
	//		res := fmt.Sprintf("mnt inode = %d, file inode = %v", key, file_inode_list)
	//		mntInodeList = append(mntInodeList, res)
	//	}
	//}
	return value.Files, nil
}
