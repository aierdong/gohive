package gohive

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"fmt"
	"github.com/apache/thrift/lib/go/thrift"
	bgohive "github.com/beltran/gohive"
	"github.com/pkg/errors"
	"os/user"
	hiveserver2 "sqlflow.org/gohive/hiveserver2/gen-go/tcliservice"
	"strings"
	"time"
)

type drv struct{}

func (d drv) Open(dsn string) (conn driver.Conn, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = errors.New(fmt.Sprintf("error: %v", r))
		}
	}()

	cfg, err := ParseDSN(dsn)
	if err != nil {
		return nil, err
	}
	// socket, err := thrift.NewTSocket(cfg.Addr)
	socket := thrift.NewTSocketConf(cfg.Addr, &thrift.TConfiguration{
		ConnectTimeout: 5 * time.Second,
	})
	var bgTransport *bgohive.TSaslTransport
	var transport thrift.TTransport
	if cfg.Auth == "NOSASL" { // todo: 当参数为NOSASL时，需要任意一个用户名，不需要密码，不填写或者填写错误用户名会导致报错
		transport = thrift.NewTBufferedTransport(socket, 4096)
		if transport == nil {
			return nil, fmt.Errorf("BufferedTransport is nil")
		}
	} else if cfg.Auth == "KERBEROS" || cfg.Auth == "GSSAPI" {
		// todo: 当参数为KERBEROS时，用户需要拥有hive的keytab文件（类似于ssh-key等密钥），
		//  有了keytab就相当于拥有了永久的凭证，不需要提供密码，因此只要linux的系统用户对于该keytab文件有读写权限，
		//  就能冒充指定用户访问hadoop，因此keytab文件需要确保只对owner有读写权限。
		if cfg.Service == "" {
			return nil, fmt.Errorf("service is required if auth is KERBEROS or GSSAPI")
		}
		saslCfg := map[string]string{
			"service": cfg.Service,
		}
		bgTransport, err = bgohive.NewTSaslTransport(socket, cfg.Addr, "GSSAPI", saslCfg, bgohive.DEFAULT_MAX_LENGTH)
		if err != nil {
			return nil, fmt.Errorf("create SasalTranposrt failed: %v", err)
		}
		bgTransport.SetMaxLength(uint32(cfg.Batch))
		transport = bgTransport
	} else if cfg.Auth == "PLAIN" || cfg.Auth == "LDAP" || cfg.Auth == "NONE" {
		if cfg.Auth == "NONE" && cfg.User == "" {
			cfg.User = getOsUser()
		}
		if cfg.Auth == "NONE" && cfg.Passwd == "" {
			cfg.Passwd = "x"
		}
		if cfg.Auth != "NONE" && (cfg.User == "" || cfg.Passwd == "") {
			return nil, fmt.Errorf("username and password are required if auth is %s", cfg.Auth)
		}
		saslCfg := map[string]string{
			"username": cfg.User,
			"password": cfg.Passwd,
		}
		bgTransport, err = bgohive.NewTSaslTransport(socket, cfg.Addr, "PLAIN", saslCfg, bgohive.DEFAULT_MAX_LENGTH)
		if err != nil {
			return nil, fmt.Errorf("create SasalTranposrt failed: %v", err)
		}
		bgTransport.SetMaxLength(uint32(cfg.Batch))
		transport = bgTransport
	} else {
		return nil, fmt.Errorf("unrecognized auth mechanism: %s", cfg.Auth)
	}
	if !transport.IsOpen() {
		if err = transport.Open(); err != nil {
			return nil, err
		}
	}

	protocol := thrift.NewTBinaryProtocolFactoryDefault()
	client := hiveserver2.NewTCLIServiceClientFactory(transport, protocol)
	s := hiveserver2.NewTOpenSessionReq()
	s.ClientProtocol = hiveserver2.TProtocolVersion_HIVE_CLI_SERVICE_PROTOCOL_V6
	if cfg.User != "" {
		s.Username = &cfg.User
		if cfg.Passwd != "" {
			s.Password = &cfg.Passwd
		}
	}
	config := cfg.SessionCfg
	if cfg.DBName != "" {
		config["use:database"] = cfg.DBName
	}
	s.Configuration = config
	session, err := client.OpenSession(context.Background(), s)
	if err != nil {
		return nil, err
	}

	options := hiveOptions{PollIntervalSeconds: 5, BatchSize: int64(cfg.Batch)}
	conn = &hiveConnection{
		thrift:  client,
		session: session.SessionHandle,
		options: options,
		ctx:     context.Background(),
	}
	return conn, nil
}

func init() {
	sql.Register("hive", &drv{})
}

func getOsUser() string {
	_user, err := user.Current()
	if err != nil {
		return "root"
	}
	if _user.Name == "" {
		return "root"
	}
	return strings.Replace(_user.Name, " ", "", -1)
}
