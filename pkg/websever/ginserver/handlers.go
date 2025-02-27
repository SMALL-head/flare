package ginserver

import (
	"flare/model/event"
	echann "flare/pkg/singleton/ebpf/chann"
	"net/http"

	"github.com/gin-gonic/gin"
)

// GetHello 处理根路径请求
func GetHello(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"message": "Hello, Gin!",
	})
}

func addAuditFileName(c *gin.Context) {
	var payload struct {
		filename string `json:"filename"`
	}
	if err := c.BindJSON(&payload); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": err.Error(),
		})
		c.Abort()
		return
	}

	ch := echann.GetAddAuditFileChan()

	ch <- &event.FileNameEvent{
		Action:   event.AddAction,
		Filename: payload.filename,
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "接口调用成功",
	})
}
