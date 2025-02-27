package svc

import (
	"context"
	xevent "flare/model/event"
	"flare/pkg/client"
	"flare/pkg/ebpfProc"
	"flare/pkg/proc"
	"fmt"

	"github.com/docker/docker/api/types/events"
	"github.com/sirupsen/logrus"
)

func ListenForCreatePodEvnet(createPodChan chan xevent.PodInfo, stopPodChan chan xevent.PodInfo) {
	client, err := client.NewDockerClient()
	if err != nil {
		logrus.Fatalf("connect to docker failed, err = %v", err)
	}
	defer client.Close()

	eventChan, errChan := client.Events(context.Background(), events.ListOptions{})
	for {
		select {
		case event := <-eventChan:
			if event.Type == events.ContainerEventType && event.Action == events.ActionStart {
				logrus.Infof("get start container event: %s", event.Actor.ID) // 如果是容器事件，这里存放是容器的id
				containerInfo, err := client.ContainerInspect(context.Background(), event.Actor.ID)
				if err != nil {
					logrus.Errorf("container inspect err: %v", err)
					continue
				}
				var e xevent.PodInfo
				e.PodName = containerInfo.Name
				e.Pid = containerInfo.State.Pid
				createPodChan <- e
				logrus.Infof("container started/ceated, name = %s, send to channel", containerInfo.Name)
			} else if event.Type == events.ContainerEventType && event.Action == events.ActionStop {
				// TODO: remove container info from ebpf map
				logrus.Infof("get start container event: %s", event.Actor.ID) // 如果是容器事件，这里存放是容器的id
				containerInfo, err := client.ContainerInspect(context.Background(), event.Actor.ID)
				if err != nil {
					logrus.Errorf("container inspect err: %v", err)
					continue
				}
				var e xevent.PodInfo
				e.PodName = containerInfo.Name
				e.Pid = containerInfo.State.Pid
				stopPodChan <- e
				logrus.Infof("container started/ceated, name = %s, send to channel", containerInfo.Name)

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
		}
		mntInode := uint32(info.Nsproxy.GetMnt())
		// mntInode := uint32(4026532680)
		containerInfo := ebpfProc.NewContainerInfo(e.PodName, mntInode)
		// 2. 将容器信息写入ebpf map， key为mnt命令空间的inode， value为容器的相关信息
		err = ebpfProc.AddMapInfo(mntInode, containerInfo)
		if err != nil {
			logrus.Errorf("add container info to ebpf map failed, container name = %s, err = %v", e.PodName, err)
		} else {
			logrus.Infof("add container info to ebpf map, container name = %s, mntInode = %d", e.PodName, mntInode)
		}
	}
}

func HandleStopPodEvent(stopPodChan chan xevent.PodInfo) {
	for e := range stopPodChan {
		// 1. 根据pid获取进程ns信息
		info, err := proc.GetProcInfo(fmt.Sprintf("%d", e.Pid))
		if err != nil {
			logrus.Errorf("get proc info failed, container name = %s, err = %v", e.PodName, err)
		}
		mntInode := uint32(info.Nsproxy.GetMnt())
		// mntInode := uint32(4026532680)
		// 2. 从ebpf map中删除容器信息
		err = ebpfProc.DeleteMapInfo(mntInode)
		if err != nil {
			logrus.Errorf("delete container info from ebpf map failed, container name = %s, err = %v", e.PodName, err)
		} else {
			logrus.Infof("delete container info from ebpf map, container name = %s, mntInode = %d", e.PodName, mntInode)
		}
	}
}
