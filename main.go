package main

import (
    "os"
    "time"
    "github.com/spf13/viper"
    "github.com/pin/tftp"
    "github.com/sirupsen/logrus"

    "github.com/jmoiron/sqlx"
    _ "github.com/go-sql-driver/mysql"
    _ "github.com/mattn/go-sqlite3"
    _ "github.com/lib/pq"
)

var log = logrus.New()

func init() {
    viper.SetDefault("root_dir", "/tftpboot")
    viper.SetDefault("shared_secret", "key")
    viper.SetDefault("db_driver", "postgres")
    viper.SetDefault("db_dsn", "")
    viper.SetDefault("upgrade_server", "0.0.0.0")
    viper.SetDefault("log_format", "text")

    viper.SetConfigName("docsistftp")
    viper.SetEnvPrefix("DOCSISTFTP")
    viper.AddConfigPath("/etc")
    viper.AddConfigPath(".")
    viper.ReadInConfig()
    viper.AutomaticEnv()

    if viper.GetString("log_format") == "json" {
	log.Formatter =&logrus.JSONFormatter{}
    } else {
	log.Formatter = &logrus.TextFormatter{}
    }
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
