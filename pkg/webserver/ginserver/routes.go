package ginserver

import (
	"github.com/gin-gonic/gin"
)

// RegisterRoutes 注册所有路由
func RegisterRoutes(r *gin.Engine) {
	// 配置基本路由
	r.GET("/hello", GetHello)

	eFile := r.Group("/ebpf/file")
	// 添加审计文件名
	eFile.POST("/addAuditFileName", addAuditFileName)

	// 删除审计文件名
	eFile.POST("/deleteAuditFileName", deleteAuditFileName)

	debugger := r.Group("/debug")
	{
		e := debugger.Group("/ebpf")
		{
			e.GET("/fileAudit/map", getFileAuditMap)
		}
	}
	ePlugin := r.Group("/ebpf/plugin")
	{
		ePlugin.POST("enable", enablePlugin)
		ePlugin.POST("disable", disablePlugin)
	}
}
