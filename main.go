package main

import (
    "os"
    "syscall"
    "github.com/spf13/viper"
    "pack.ag/tftp"
    "github.com/sirupsen/logrus"

    "github.com/jmoiron/sqlx"
    _ "github.com/go-sql-driver/mysql"
    _ "github.com/mattn/go-sqlite3"
    _ "github.com/lib/pq"
)

var log = logrus.New()

func init() {
    viper.SetDefault("listen", ":69")
    viper.SetDefault("root_dir", "/tftpboot")
    viper.SetDefault("shared_secret", "key")
    viper.SetDefault("db_driver", "postgres")
    viper.SetDefault("db_dsn", "")
    viper.SetDefault("upgrade_server", "0.0.0.0")
    viper.SetDefault("log_format", "text")
    viper.SetDefault("rewrites", map[string]string{} )

    viper.SetConfigName("docsistftp")
    viper.SetEnvPrefix("DOCSISTFTP")
    viper.AddConfigPath("/etc")
    viper.AddConfigPath(".")
    viper.ReadInConfig()
    viper.AutomaticEnv()

    if viper.GetString("log_format") == "json" {
	log.Formatter = &logrus.JSONFormatter{}
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

    if err := syscall.Chroot(viper.GetString("root_dir")); err != nil {
	log.Fatal(err)
    }

    os.Chdir("/")

    server, err := tftp.NewServer(viper.GetString("listen"))
    if err != nil {
	log.Fatal(err)
    }

    handler := NewServerHandler(db)
    server.ReadHandler(handler)
    log.Fatal(server.ListenAndServe())

}

