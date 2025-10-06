package ginserver

import (
	"io"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"
	"github.com/spf13/viper"
)

// ServerConfig 用于配置 Gin 服务器
type ServerConfig struct {
	Host    string        `yaml:"host" json:"host"`
	Port    string        `yaml:"port" json:"port"`
	Mode    string        `yaml:"mode" json:"mode"` // gin.DebugMode, gin.ReleaseMode, gin.TestMode
	Timeout time.Duration // 服务器超时时间，但是不参与序列化与反序列化
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

func LoadConfig(filePath string) (ServerConfig, error) {
	// 这里可以实现从配置文件加载配置的逻辑
	// 例如使用 viper 或者其他配置库
	v := viper.New()
	v.SetConfigFile(filePath)
	err := v.ReadInConfig()
	if err != nil {
		return DefaultConfig(), err
	}
	res := ServerConfig{}
	if err = v.Unmarshal(&res); err != nil {
		return DefaultConfig(), err
	}

	// 目前返回默认配置
	return res, nil
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

	// 手动启用 reverseSh 插件
	_ = Svc.EnableNamedPlugin("reverseSh")

	// 启动服务器并捕获可能的错误
	if err := srv.ListenAndServe(); err != nil {
		logrus.Fatalf("Failed to start server: %v", err)
	}
}
