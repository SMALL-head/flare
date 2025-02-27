package main

import (
	"flare/pkg/ebpfProc"
	"flare/pkg/singleton/docker/chann"
	"flare/pkg/svc"
	"flare/pkg/websever/ginserver"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/sirupsen/logrus"
)

func main() {
	stopCh := make(chan os.Signal, 1)

	signal.Notify(stopCh, os.Interrupt, syscall.SIGTERM)
	logrus.Info("start flare")
	// 监听docker事件
	go svc.ListenForCreatePodEvnet(chann.GetCreatePodEventChan(), chann.GetStopPodEventChan())
	// 处理docker事件
	go svc.HandleCreatePodEvent(chann.GetCreatePodEventChan())
	go svc.HandleStopPodEvent(chann.GetStopPodEventChan())

	time.Sleep(1 * time.Second)
	// 挂载ebpf程序
	logrus.Infof("准备挂载ebpf程序")
	go ebpfProc.RunContainerEbpf()

	// 处理ebpf事件，事件源又gin服务器提供
	logrus.Infof("准备启动事件channel处理器")
	go ebpfProc.HandleChan()

	// 启动web服务器
	cfg := ginserver.DefaultConfig()
	ginserver.StartGinServer(cfg)

	<-stopCh
	// gracefully quit
	logrus.Info("flare stop")
	close(chann.GetCreatePodEventChan())
	close(chann.GetStopPodEventChan())
}
