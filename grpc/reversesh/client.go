package reversesh

import (
	"context"
	"flare/proto"
	"fmt"

	"github.com/spf13/viper"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

type Reply struct {
	CTIDs   []uint64 `json:"ctids"`
	Message string   `json:"message"`
	Syscall string   `json:"syscall"`
}

type ReverseShGrpcClient struct {
	conn   *grpc.ClientConn
	client proto.KernelTraceServiceClient
}

var (
	instance *ReverseShGrpcClient
)

func init() {
	// viper读取服务名
	v := viper.New()
	v.AddConfigPath(".")
	v.SetConfigFile("application.yaml")

	// pwd, _ := os.Getwd()
	// logrus.Infof("[init] - pwd = %s", pwd)

	if err := v.ReadInConfig(); err != nil {
		panic("Failed to read config file: " + err.Error())
	}
	serviceName := v.GetString("grpc.reverseSh.host")
	port := v.GetString("grpc.reverseSh.port")
	if serviceName == "" || port == "" {
		panic("Service name or port not configured in application.yaml")
	}
	c, err := grpc.NewClient(fmt.Sprintf("%s:%s", serviceName, port), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		panic("Failed to create gRPC client: " + err.Error())
	}
	instance = &ReverseShGrpcClient{
		conn:   c,
		client: proto.NewKernelTraceServiceClient(c),
	}

}

func GetInstance() *ReverseShGrpcClient {
	// init函数保证了这里不会是nil
	if instance == nil {
		panic("ReverseShGrpcClient not initialized")
	}
	return instance
}

func (c *ReverseShGrpcClient) Close() error {
	if c.conn != nil {
		return c.conn.Close()
	}
	return nil
}

func (c *ReverseShGrpcClient) GetMalCTIDRequest(nodeName string, pid uint32, timestamp uint64) (Reply, error) {
	reply, err := c.client.GetMalCTID(context.TODO(), &proto.GetMalCTIDRequest{
		Node:    nodeName,
		Pid:     pid,
		Timestp: timestamp,
	})
	if err != nil {
		return Reply{}, err
	}
	return Reply{
		CTIDs:   reply.Ctids,
		Message: reply.Message,
		Syscall: reply.Syscall,
	}, nil
}
