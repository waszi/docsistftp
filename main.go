package main

import (
    "errors"
    "io"
    "time"
    "os"
    "net/url"
    "path/filepath"
    "github.com/spf13/viper"
    "github.com/pin/tftp"
    "github.com/sirupsen/logrus"

    "github.com/jmoiron/sqlx"
    _ "github.com/go-sql-driver/mysql"
    _ "github.com/mattn/go-sqlite3"
    _ "github.com/lib/pq"
)

var log = logrus.New()

type ServerHandler struct{
    db *sqlx.DB
}

func NewServerHandler(db *sqlx.DB) *ServerHandler {
    return &ServerHandler{db}
}

func (s *ServerHandler) ReadHandler(filename string, rf io.ReaderFrom) error {
    raddr := rf.(tftp.OutgoingTransfer).RemoteAddr()
    requestLog := log.WithFields(logrus.Fields{
	"ip": raddr.String(),
	"request": filename,
    })

    query, err := url.Parse(filename)
    if err != nil {
	requestLog.Errorf("Cannot parse request: %v", err)
	return err
    }

    full_path := filepath.Join(viper.GetString("root_dir"), query.Path)
    _, err = os.Stat(full_path);
    if err != nil {
	if os.IsNotExist(err) {
	    requestLog.Errorf("Cannot find file: %v", full_path)
	} else {
	    requestLog.Errorf("Error: %v", err)
	}
	return err
    }

    var r io.Reader
    qs := query.Query()
    if filepath.Ext(full_path) == ".anko" {
        enc := NewEncoder(s.db, full_path, qs)
        r, err = enc.Encode()
        if err != nil {
	    requestLog.Errorf("Cannot execute script: %v", err)
	    return err
        }
    } else {
	r, err = os.Open(full_path)
        if err != nil {
	    requestLog.Errorf("Cannot open file: %v", err)
	    return err
        }
    }

    _, err = rf.ReadFrom(r)
    if err != nil {
	requestLog.Errorf("Cannot read: %v", err)
	return err
    }

    fields := logrus.Fields{}
    for k, _ := range qs {
	fields[k] = qs.Get(k)
    }
    requestLog.WithFields(fields).Infof("RRQ from %s (%s)", raddr.String(), filename)
    return nil
}

func (s *ServerHandler) WriteHandler(filename string, wt io.WriterTo) error {
    return errors.New("Not supported")
}

func init() {
    viper.SetDefault("root_dir", "/tftpboot")
    viper.SetDefault("shared_secret", "key")
    viper.SetDefault("db_driver", "postgres")
    viper.SetDefault("db_dsn", "")

    viper.SetConfigName("docsistftp")
    viper.SetEnvPrefix("DOCSISTFTP")
    viper.AddConfigPath("/etc")
    viper.AddConfigPath(".")
    viper.ReadInConfig()
    viper.AutomaticEnv()
}

func main() {
    log.Out = os.Stdout
    db, err := sqlx.Open(viper.GetString("db_driver"), viper.GetString("db_dsn"))
    if err != nil {
	log.Fatal(err)
    }
    defer db.Close()

    h := NewServerHandler(db)
    s := tftp.NewServer(h.ReadHandler, h.WriteHandler)
    s.SetTimeout(5 * time.Second)
    log.Println("Starting server")
    err = s.ListenAndServe(":69")
    if err != nil {
	log.Fatal(err)
    }
}
