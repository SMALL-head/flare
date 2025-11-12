package client

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/spf13/viper"
)

type WebClientSet struct {
	FlareAdmin ClientWithHost
	ZeroTrust  ClientWithHost
}

type ClientWithHost struct {
	*http.Client
	BaseURL string
}

var (
	WebClientSetInstance *WebClientSet
	once                 sync.Once
)

func GetWebClientSet() *WebClientSet {
	once.Do(func() {
		v := viper.New()
		v.AddConfigPath(".")
		v.SetConfigFile("application.yaml")
		if err := v.ReadInConfig(); err != nil {
			panic("Failed to read config file: " + err.Error())
		}
		host := v.GetString("client.flareAdmin.host")
		port := v.GetString("client.flareAdmin.port")

		ztHost := v.GetString("client.zeroTrust.host")
		ztPort := v.GetString("client.zeroTrust.port")
		if host == "" || port == "" {
			panic("FlareAdmin host or port not configured in application.yaml")
		}
		WebClientSetInstance = &WebClientSet{
			FlareAdmin: ClientWithHost{
				Client: &http.Client{
					Transport: &http.Transport{},
					Timeout:   10 * time.Second,
				},
				BaseURL: fmt.Sprintf("http://%s:%s", host, port),
			},
			ZeroTrust: ClientWithHost{
				Client: &http.Client{
					Transport: &http.Transport{},
					Timeout:   10 * time.Second,
				},
				BaseURL: fmt.Sprintf("http://%s:%s", ztHost, ztPort),
			},
		}
	})

	return WebClientSetInstance
}

func (w *ClientWithHost) FlareAdminHello() {
	url := fmt.Sprintf("%s/debug/hello", w.BaseURL)
	resp, err := w.Get(url)
	if err != nil {
		logrus.Errorf("FlareAdminHello request failed: %v", err)
		return
	}
	if resp.StatusCode != http.StatusOK {
		logrus.Errorf("FlareAdminHello request failed, status code: %d", resp.StatusCode)
		return
	}

	respBodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		logrus.Errorf("Failed to read response body: %v", err)
		return
	}
	logrus.Infof("[FlareAdminHello] Response: %s", respBodyBytes)
	defer resp.Body.Close()
}

func (w *ClientWithHost) ReverseShRecord(ctids []uint64, msg string, syscall string, nodeName string) error {
	url := fmt.Sprintf("%s/reversesh/uploadRecord", w.BaseURL)
	// 构造请求体
	bodyInstace := struct {
		CTIDs   []uint64 `json:"ctids"`
		Message string   `json:"message"`
		Syscall string   `json:"syscall"`
		Node    string   `json:"node_name"`
	}{
		CTIDs:   ctids,
		Message: msg,
		Syscall: syscall,
		Node:    nodeName,
	}
	bodyJsonStr, err := json.Marshal(bodyInstace)
	if err != nil {
		logrus.Errorf("Failed to marshal request body: %v", err)
		return err
	}
	reader := strings.NewReader(string(bodyJsonStr))
	_, err = w.Post(url, "application/json", reader)
	if err != nil {
		logrus.Errorf("ReverseShRecord request failed: %v", err)
		return err
	}

	return nil
}

func (ws *WebClientSet) ZeroTrustNotifyReversesh(ctid uint64, msg string) error {
	url := fmt.Sprintf("%s/notify/kernel-func", ws.ZeroTrust.BaseURL)
	body := struct {
		CTID uint64 `json:"ctid"`
		Msg  string `json:"msg"`
	}{
		CTID: ctid,
		Msg:  msg,
	}
	bodyJsonStr, err := json.Marshal(body)
	if err != nil {
		logrus.Errorf("Failed to marshal request body: %v", err)
		return err
	}
	reader := strings.NewReader(string(bodyJsonStr))
	postResponse, err := ws.ZeroTrust.Post(url, "application/json", reader)
	if err != nil {
		logrus.Errorf("ZeroTrustNotifyReversesh request failed: %v", err)
		return err
	}
	defer postResponse.Body.Close()
	_, err = io.ReadAll(postResponse.Body)
	return nil
}
