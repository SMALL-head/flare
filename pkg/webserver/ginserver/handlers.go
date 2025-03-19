package ginserver

import (
	"flare/model/event"
	"flare/pkg/ebpfProc/fileAudit"
	"flare/pkg/ns"
	"flare/pkg/proc"
	echann "flare/pkg/singleton/ebpf/chann"
	wsvc "flare/pkg/webserver/service"
	"fmt"
	"github.com/gin-gonic/gin"
	"net/http"
)

// GetHello 处理根路径请求
func GetHello(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"message": "Hello, Gin!",
	})
}

func addAuditFileName(c *gin.Context) {
	var payload struct {
		Filename      string `json:"filename"`
		ContainerName string `json:"container_name"`
	}
	if err := c.BindJSON(&payload); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": err.Error(),
		})
		c.Abort()
		return
	}

	ch := echann.GetAddAuditFileChan()

	containerInfo, err := wsvc.DockerClient.ContainerInspect(c.Request.Context(), payload.ContainerName)
	if err != nil {
		c.JSON(http.StatusOK, gin.H{
			"error": err.Error(),
		})
		c.Abort()
		return
	}

	fileInode, err := ns.GetFileInodeInContainer(fmt.Sprintf("%d", containerInfo.State.Pid), payload.Filename)
	if err != nil {
		c.JSON(http.StatusOK, gin.H{
			"error": err.Error(),
		})
		c.Abort()
		return
	}

	// chan另一端的函数位置：main函数中的 fileAudit.HandleChan()
	info, err := proc.GetProcInfo(fmt.Sprintf("%d", containerInfo.State.Pid))
	if err != nil {
		c.JSON(http.StatusOK, gin.H{
			"error": err.Error(),
		})
		c.Abort()
		return
	}

	ch <- &event.FileNameEvent{
		Action:    event.AddAction,
		Filename:  payload.Filename,
		FileInode: fileInode,
		MntInode:  info.Nsproxy.GetMnt(),
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "接口调用成功",
	})
}

func deleteAuditFileName(c *gin.Context) {
	var payload struct {
		Filename      string `json:"filename"`
		ContainerName string `json:"container_name"`
	}
	if err := c.BindJSON(&payload); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": err.Error(),
		})
		c.Abort()
		return
	}

	ch := echann.GetDeleteAuditFileChan()
	containerInfo, err := wsvc.DockerClient.ContainerInspect(c.Request.Context(), payload.ContainerName)
	if err != nil {
		c.JSON(http.StatusOK, gin.H{
			"error": err.Error(),
		})
		c.Abort()
		return
	}

	fileInode, err := ns.GetFileInodeInContainer(fmt.Sprintf("%d", containerInfo.State.Pid), payload.Filename)
	if err != nil {
		c.JSON(http.StatusOK, gin.H{
			"error": err.Error(),
		})
		c.Abort()
		return
	}

	// chan另一端的函数位置：main函数中的 fileAudit.HandleChan()
	info, err := proc.GetProcInfo(fmt.Sprintf("%d", containerInfo.State.Pid))
	if err != nil {
		c.JSON(http.StatusOK, gin.H{
			"error": err.Error(),
		})
		c.Abort()
		return
	}

	ch <- &event.FileNameEvent{
		Action:    event.DeleteAction,
		Filename:  payload.Filename,
		FileInode: fileInode,
		MntInode:  info.Nsproxy.GetMnt(),
	}
	c.JSON(http.StatusOK, gin.H{
		"message": "接口调用成功",
	})
}

func getFileAuditMap(c *gin.Context) {
	var payload struct {
		MntInode uint32 `json:"mnt_inode" form:"mnt_inode"`
	}
	if err := c.BindQuery(&payload); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"message": "参数绑定错误: " + err.Error(),
		})
		c.Abort()
		return
	}
	res, err := fileAudit.GetMntInodeMap(payload.MntInode)
	if err != nil {
		c.JSON(http.StatusOK, gin.H{
			"message": "出错了, err = " + err.Error(),
		})
		c.Abort()
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"message": res,
	})
}
