package checks

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"strings"
	"time"
)

type RedisChecker struct {
	NameLabel string
	TargetURL string
	Timeout   time.Duration
	Dial      func(context.Context, string, string) (net.Conn, error)
}

func (c RedisChecker) Name() string {
	if strings.TrimSpace(c.NameLabel) != "" {
		return c.NameLabel
	}
	return "redis_dependency"
}

func (c RedisChecker) Run(ctx context.Context) Result {
	parsed, err := url.Parse(strings.TrimSpace(c.TargetURL))
	if err != nil {
		return Result{Name: c.Name(), Code: "REDIS_CONFIG_INVALID", Message: err.Error(), Action: "check redis dependency config", Severity: SeverityWarn}
	}
	host := strings.TrimSpace(parsed.Hostname())
	port := strings.TrimSpace(parsed.Port())
	if host == "" {
		return Result{Name: c.Name(), Code: "REDIS_HOST_MISSING", Message: "redis host is empty", Action: "check redis dependency config", Severity: SeverityWarn}
	}
	if port == "" {
		port = "6379"
	}
	timeout := c.Timeout
	if timeout <= 0 {
		timeout = 3 * time.Second
	}
	dialer := net.Dialer{Timeout: timeout}
	conn, err := dialContext(c.Dial, dialer, ctx, "tcp", net.JoinHostPort(host, port))
	if err != nil {
		return Result{Name: c.Name(), Code: "REDIS_DIAL_FAILED", Message: err.Error(), Action: "check redis host/port/network", Severity: SeverityFail}
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))

	reader := bufio.NewReader(conn)
	if err := redisMaybeAuth(conn, reader, parsed); err != nil {
		return Result{Name: c.Name(), Code: "REDIS_AUTH_FAILED", Message: err.Error(), Action: "check redis auth and ACL configuration", Severity: SeverityFail}
	}
	if err := writeRESPCommand(conn, "PING"); err != nil {
		return Result{Name: c.Name(), Code: "REDIS_PING_WRITE_FAILED", Message: err.Error(), Action: "check redis server responsiveness", Severity: SeverityFail}
	}
	line, err := reader.ReadString('\n')
	if err != nil {
		return Result{Name: c.Name(), Code: "REDIS_PING_FAILED", Message: err.Error(), Action: "check redis server responsiveness", Severity: SeverityFail}
	}
	line = strings.TrimSpace(line)
	if !strings.HasPrefix(line, "+PONG") {
		return Result{Name: c.Name(), Code: "REDIS_BAD_RESPONSE", Message: defaultString(line, "unexpected redis PING response"), Action: "check redis service health and auth", Severity: SeverityFail}
	}
	return Result{Name: c.Name(), Code: "OK", Message: "redis responded to PING", Severity: SeverityPass}
}

type MySQLChecker struct {
	NameLabel string
	TargetURL string
	Timeout   time.Duration
	Dial      func(context.Context, string, string) (net.Conn, error)
}

func (c MySQLChecker) Name() string {
	if strings.TrimSpace(c.NameLabel) != "" {
		return c.NameLabel
	}
	return "mysql_dependency"
}

func (c MySQLChecker) Run(ctx context.Context) Result {
	parsed, err := url.Parse(strings.TrimSpace(c.TargetURL))
	if err != nil {
		return Result{Name: c.Name(), Code: "MYSQL_CONFIG_INVALID", Message: err.Error(), Action: "check mysql dependency config", Severity: SeverityWarn}
	}
	host := strings.TrimSpace(parsed.Hostname())
	port := strings.TrimSpace(parsed.Port())
	if host == "" {
		return Result{Name: c.Name(), Code: "MYSQL_HOST_MISSING", Message: "mysql host is empty", Action: "check mysql dependency config", Severity: SeverityWarn}
	}
	if port == "" {
		port = "3306"
	}
	timeout := c.Timeout
	if timeout <= 0 {
		timeout = 3 * time.Second
	}
	dialer := net.Dialer{Timeout: timeout}
	conn, err := dialContext(c.Dial, dialer, ctx, "tcp", net.JoinHostPort(host, port))
	if err != nil {
		return Result{Name: c.Name(), Code: "MYSQL_DIAL_FAILED", Message: err.Error(), Action: "check mysql host/port/network", Severity: SeverityFail}
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))

	header := make([]byte, 4)
	if _, err := io.ReadFull(conn, header); err != nil {
		return Result{Name: c.Name(), Code: "MYSQL_HANDSHAKE_FAILED", Message: err.Error(), Action: "check mysql handshake and server availability", Severity: SeverityFail}
	}
	length := int(uint24LE(header[:3]))
	if length <= 0 || length > 16*1024*1024 {
		return Result{Name: c.Name(), Code: "MYSQL_BAD_HANDSHAKE", Message: fmt.Sprintf("unexpected handshake length=%d", length), Action: "check mysql protocol endpoint", Severity: SeverityFail}
	}
	payload := make([]byte, length)
	if _, err := io.ReadFull(conn, payload); err != nil {
		return Result{Name: c.Name(), Code: "MYSQL_HANDSHAKE_FAILED", Message: err.Error(), Action: "check mysql handshake and server availability", Severity: SeverityFail}
	}
	if len(payload) == 0 {
		return Result{Name: c.Name(), Code: "MYSQL_BAD_HANDSHAKE", Message: "empty handshake payload", Action: "check mysql protocol endpoint", Severity: SeverityFail}
	}
	if payload[0] == 0xff {
		return Result{Name: c.Name(), Code: "MYSQL_ERROR_PACKET", Message: "received mysql error packet during handshake", Action: "check mysql listener and proxy", Severity: SeverityFail}
	}
	version := mysqlServerVersion(payload)
	msg := "mysql handshake received"
	if version != "" {
		msg += " version=" + version
	}
	return Result{Name: c.Name(), Code: "OK", Message: msg, Severity: SeverityPass}
}

func redisMaybeAuth(w io.Writer, reader *bufio.Reader, parsed *url.URL) error {
	if parsed == nil || parsed.User == nil {
		return nil
	}
	username := parsed.User.Username()
	password, hasPassword := parsed.User.Password()
	if username == "" && !hasPassword {
		return nil
	}
	args := []string{"AUTH"}
	if username != "" {
		args = append(args, username)
	}
	if hasPassword {
		args = append(args, password)
	}
	if err := writeRESPCommand(w, args...); err != nil {
		return err
	}
	line, err := reader.ReadString('\n')
	if err != nil {
		return err
	}
	line = strings.TrimSpace(line)
	if !strings.HasPrefix(line, "+OK") {
		return errors.New(defaultString(line, "redis AUTH rejected"))
	}
	return nil
}

func writeRESPCommand(w io.Writer, args ...string) error {
	if len(args) == 0 {
		return nil
	}
	if _, err := fmt.Fprintf(w, "*%d\r\n", len(args)); err != nil {
		return err
	}
	for _, arg := range args {
		if _, err := fmt.Fprintf(w, "$%d\r\n%s\r\n", len(arg), arg); err != nil {
			return err
		}
	}
	return nil
}

func mysqlServerVersion(payload []byte) string {
	if len(payload) < 2 {
		return ""
	}
	rest := payload[1:]
	if idx := strings.IndexByte(string(rest), 0x00); idx >= 0 {
		return strings.TrimSpace(string(rest[:idx]))
	}
	if len(rest) > 40 {
		rest = rest[:40]
	}
	return strings.TrimSpace(string(rest))
}

func uint24LE(data []byte) uint32 {
	if len(data) < 3 {
		return 0
	}
	tmp := append(data[:3], 0)
	return binary.LittleEndian.Uint32(tmp)
}

func dialContext(fn func(context.Context, string, string) (net.Conn, error), dialer net.Dialer, ctx context.Context, network, address string) (net.Conn, error) {
	if fn != nil {
		return fn(ctx, network, address)
	}
	return dialer.DialContext(ctx, network, address)
}
