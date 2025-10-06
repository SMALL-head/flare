package main

import (
	"flare/pkg/ebpfProc/fileAudit"
	"flare/pkg/singleton/docker/chann"
	"flare/pkg/svc"
	"flare/pkg/webserver/ginserver"
	"flare/pkg/webserver/service"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/sirupsen/logrus"
)

func main() {
	stopCh := make(chan os.Signal, 1)

	signal.Notify(stopCh, os.Interrupt, syscall.SIGTERM)
	pwd, err := os.Getwd()
	if err != nil {
		logrus.Fatalf("get current working directory failed: %v", err)
	}

	logrus.Infof("start flare, curDir = %s", pwd)
	// 监听docker事件
	go svc.ListenForCreatePodEvent(chann.GetCreatePodEventChan(), chann.GetStopPodEventChan())
	// 处理docker事件
	go svc.HandleCreatePodEvent(chann.GetCreatePodEventChan())
	go svc.HandleStopPodEvent(chann.GetStopPodEventChan())

	time.Sleep(1 * time.Second)
	// 挂载ebpf程序
	logrus.Infof("准备挂载ebpf程序")
	// go ebpfProc.RunContainerEbpf()
	go fileAudit.RunFileAuditProg()

	// 处理ebpf事件，事件源由gin服务器提供
	logrus.Infof("准备启动事件channel处理器")
	go fileAudit.HandleAuditFileChan()

	// 启动web服务器
	cfg, err := ginserver.LoadConfig("application.yaml")
	if err != nil {
		logrus.Fatalf("load config failed: %v", err)
	}
	cfg.Host = "0.0.0.0"
	go ginserver.StartGinServer(cfg)

	<-stopCh
	// gracefully quit
	logrus.Info("flare stop")
	// 关闭reversesh插件
	service.Svc.DisableNamedPlugin("reverseSh")
	close(chann.GetCreatePodEventChan())
	close(chann.GetStopPodEventChan())
}
