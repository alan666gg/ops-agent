package checks

import (
	"context"
	"net"
	"strings"
	"testing"
	"time"
)

func TestRedisCheckerPing(t *testing.T) {
	done := make(chan struct{})
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	checker := RedisChecker{
		NameLabel: "dependency_redis_cache",
		TargetURL: "redis://cache.internal:6379/0",
		Timeout:   2 * time.Second,
		Dial: func(context.Context, string, string) (net.Conn, error) {
			return clientConn, nil
		},
	}
	go func() {
		defer close(done)
		buf := make([]byte, 128)
		total := 0
		for total < len(buf) {
			n, err := serverConn.Read(buf[total:])
			total += n
			if strings.Contains(string(buf[:total]), "PING") {
				break
			}
			if err != nil {
				t.Errorf("read redis command: %v", err)
				return
			}
		}
		if !strings.Contains(string(buf[:total]), "PING") {
			t.Errorf("expected redis ping command, got %q", string(buf[:total]))
			return
		}
		_, _ = serverConn.Write([]byte("+PONG\r\n"))
	}()
	result := checker.Run(context.Background())
	if result.Severity != SeverityPass || result.Code != "OK" {
		t.Fatalf("unexpected redis result: %+v", result)
	}
	<-done
}

func TestMySQLCheckerHandshake(t *testing.T) {
	done := make(chan struct{})
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	checker := MySQLChecker{
		NameLabel: "dependency_mysql_primary",
		TargetURL: "mysql://db.internal:3306/app",
		Timeout:   2 * time.Second,
		Dial: func(context.Context, string, string) (net.Conn, error) {
			return clientConn, nil
		},
	}
	go func() {
		defer close(done)
		payload := []byte{0x0a}
		payload = append(payload, []byte("8.0.36-test\x00")...)
		header := []byte{byte(len(payload)), byte(len(payload) >> 8), byte(len(payload) >> 16), 0x00}
		_, _ = serverConn.Write(append(header, payload...))
	}()
	result := checker.Run(context.Background())
	if result.Severity != SeverityPass || result.Code != "OK" {
		t.Fatalf("unexpected mysql result: %+v", result)
	}
	<-done
}
