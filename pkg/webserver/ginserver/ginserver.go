package ginserver

import (
	"io"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"
)

// ServerConfig 用于配置 Gin 服务器
type ServerConfig struct {
	Host    string
	Port    string
	Mode    string
	Timeout time.Duration
}

// DefaultConfig 返回默认的服务器配置
func DefaultConfig() ServerConfig {
	return ServerConfig{
		Host:    "127.0.0.1",
		Port:    "8080",
		Mode:    gin.ReleaseMode,
		Timeout: 10 * time.Second,
	}
}

// StartGinServer 启动 Gin 服务器
func StartGinServer(config ServerConfig) {
	// 设置运行模式
	gin.SetMode(config.Mode)
	gin.DefaultWriter = io.Discard
	// 创建一个默认的 Gin 引擎
	r := gin.New()
	r.Use(gin.Recovery()) // gin server一定要有的东西

	// 注册路由
	RegisterRoutes(r)

	// 启动服务器并设置超时
	srv := &http.Server{
		Addr:         config.Host + ":" + config.Port,
		Handler:      r,
		ReadTimeout:  config.Timeout,
		WriteTimeout: config.Timeout,
	}

	logrus.Printf("Starting Gin server on %s:%s\n", config.Host, config.Port)

	// 启动服务器并捕获可能的错误
	if err := srv.ListenAndServe(); err != nil {
		logrus.Fatalf("Failed to start server: %v", err)
	}
}
