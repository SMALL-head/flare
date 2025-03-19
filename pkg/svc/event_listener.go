package svc

import (
	"context"
	xevent "flare/model/event"
	"flare/pkg/client"
	"flare/pkg/ebpfProc/container"
	"flare/pkg/ebpfProc/fileAudit"
	"flare/pkg/svc/status"

	"flare/pkg/proc"
	"fmt"

	"github.com/docker/docker/api/types/events"
	"github.com/sirupsen/logrus"
)

func ListenForCreatePodEvent(createPodChan chan xevent.PodInfo, stopPodChan chan xevent.PodInfo) {
	dclient, err := client.NewDockerClient()
	if err != nil {
		logrus.Fatalf("connect to docker failed, err = %v", err)
	}
	defer dclient.Close()

	eventChan, errChan := dclient.Events(context.Background(), events.ListOptions{})
	for {
		select {
		case event := <-eventChan:
			if event.Type == events.ContainerEventType && event.Action == events.ActionStart {
				logrus.Infof("get start container event: %s", event.Actor.ID) // 如果是容器事件，这里存放是容器的id
				containerInfo, err := dclient.ContainerInspect(context.Background(), event.Actor.ID)
				if err != nil {
					logrus.Errorf("container inspect err: %v", err)
					continue
				}
				var e xevent.PodInfo
				e.PodName = containerInfo.Name
				e.Pid = containerInfo.State.Pid
				createPodChan <- e // refer to HandleCreatePodEvent
				logrus.Infof("container started/created, name = %s, send to channel", containerInfo.Name)
			} else if event.Type == events.ContainerEventType && event.Action == events.ActionStop {
				// TODO: remove container info from ebpf map
				logrus.Infof("get stop container event: %s", event.Actor.ID) // 如果是容器事件，这里存放是容器的id
				containerInfo, err := dclient.ContainerInspect(context.Background(), event.Actor.ID)
				if err != nil {
					logrus.Errorf("container inspect err: %v", err)
					continue
				}
				var e xevent.PodInfo
				e.PodName = containerInfo.Name
				e.Pid = containerInfo.State.Pid
				stopPodChan <- e
				logrus.Infof("container stop, name = %s, send to channel", containerInfo.Name)

			}
		case err := <-errChan:
			logrus.Errorf("receive err from docker client: %v", err)
			return
		}
	}
}

func HandleCreatePodEvent(createPodChan chan xevent.PodInfo) {
	for e := range createPodChan {
		// 1. 根据pid获取进程ns信息
		info, err := proc.GetProcInfo(fmt.Sprintf("%d", e.Pid))
		if err != nil {
			logrus.Errorf("get proc info failed, container name = %s, err = %v", e.PodName, err)
			continue
		}
		mntInode := uint32(info.Nsproxy.GetMnt())
		status.PodNameMntInode[e.PodName] = mntInode
		// mntInode := uint32(4026532680)
		containerInfo := container.NewContainerInfo(e.PodName, mntInode)
		// 2. 将容器信息写入ebpf map， key为mnt命令空间的inode， value为容器的相关信息
		err = container.AddMapInfo(mntInode, containerInfo)
		if err != nil {
			logrus.Errorf("added container info to ebpf map failed, container name = %s, err = %v", e.PodName, err)
		} else {
			logrus.Infof("successfully added container info to ebpf map, container name = %s, mntInode = %d", e.PodName, mntInode)
		}
		err = fileAudit.AddMntInodeToMap(mntInode)
		if err != nil {
			logrus.Errorf("added mnt inode to audit file map failed, container name = %s, err = %v", e.PodName, err)
		} else {
			logrus.Infof("successfully added mnt inode to audit file map, container name = %s, mntInode = %d", e.PodName, mntInode)
		}
	}
}

func HandleStopPodEvent(stopPodChan chan xevent.PodInfo) {
	for e := range stopPodChan {
		// 1. stop事件无法通过docker inspect的方法获取pid然后在获取mntInode
		// 但是我们在创建容器的时候，在内存中存储了这个mntInode
		mntInode, exists := status.PodNameMntInode[e.PodName]
		if !exists {
			logrus.Errorf("未找到%s的mntInode", e.PodName)
			continue
		}
		delete(status.PodNameMntInode, e.PodName)

		// mntInode := uint32(4026532680)
		// 2. 从ebpf map中删除容器信息
		err := container.DeleteMapInfo(mntInode)
		if err != nil {
			logrus.Errorf("delete container info from ebpf map failed, container name = %s, err = %v", e.PodName, err)
		} else {
			logrus.Infof("delete container info from ebpf map, container name = %s, mntInode = %d", e.PodName, mntInode)
		}
		err = fileAudit.DeleteMntInodeInMap(mntInode)
		if err != nil {
			logrus.Errorf("delete mnt inode from audit file map failed, container name = %s, err = %v", e.PodName, err)
		} else {
			logrus.Infof("delete mnt inode from audit file map, container name = %s, mntInode = %d", e.PodName, mntInode)
		}
	}
}
