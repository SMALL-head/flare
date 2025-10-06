package client

import (
	"fmt"
	"net/http"
	"testing"
	"time"
)

func TestFlareAdmin(t *testing.T) {
	host := "10.162.178.209"
	port := "8800"
	s := ClientWithHost{
		Client: &http.Client{
			Transport: &http.Transport{},
			Timeout:   10 * time.Second,
		},
		BaseURL: fmt.Sprintf("http://%s:%s", host, port),
	}
	s.FlareAdminHello()
}
