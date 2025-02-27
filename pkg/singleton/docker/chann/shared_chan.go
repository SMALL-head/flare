package chann

import (
	"flare/model/event"
	"sync"
)

var (
	createPodEventChan     chan event.PodInfo
	createPodEventChanOnce sync.Once

	stopPodEventChan       chan event.PodInfo
	deletePodEventChanOnce sync.Once
)

// 获取createPodEventChan单例对象
func GetCreatePodEventChan() chan event.PodInfo {
	createPodEventChanOnce.Do(func() {
		createPodEventChan = make(chan event.PodInfo, 100)
	})
	return createPodEventChan
}

// 获取stopPodEventChan单例对象
func GetStopPodEventChan() chan event.PodInfo {
	deletePodEventChanOnce.Do(func() {
		stopPodEventChan = make(chan event.PodInfo, 100)
	})
	return stopPodEventChan
}
