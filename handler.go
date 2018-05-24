package main

import (
	"github.com/sirupsen/logrus"
	"io"
	"net/url"
	"os"
	"pack.ag/tftp"
	"path/filepath"
	"github.com/spf13/viper"

	_ "github.com/go-sql-driver/mysql"
	"github.com/jmoiron/sqlx"
	_ "github.com/lib/pq"
	_ "github.com/mattn/go-sqlite3"
)

type ServerHandler struct {
	db   *sqlx.DB
	rmap *RewriteMap
}

func NewServerHandler(db *sqlx.DB) *ServerHandler {
	rmap := NewRewriteMap(viper.GetStringMapString("rewrites"))
	return &ServerHandler{db, rmap}
}

func (s *ServerHandler) ServeTFTP(w tftp.ReadRequest) {
	requestLog := log.WithFields(logrus.Fields{
		"ip":      w.Addr().IP.String(),
		"request": w.Name(),
	})

	request := s.rmap.Rewrite(w.Name())
	query, err := url.Parse(request)
	if err != nil {
		requestLog.Errorf("Cannot parse request: %v", err)
		return
	}

	var r io.Reader
	fields := logrus.Fields{}
	full_path := filepath.Join("/", query.Path)
	if _, err := os.Stat(full_path); os.IsNotExist(err) {
		requestLog.Errorf("Cannot find: %s", query.Path)
		w.WriteError(tftp.ErrCodeFileNotFound, err.Error())
		return
	} else {
		ext := filepath.Ext(full_path)
		switch ext {
		case ".anko":
			script := NewScript(full_path, s.db, query)
			r, err = script.Execute()
			if err != nil {
				requestLog.Errorf("Script error: %v", err)
				w.WriteError(tftp.ErrCodeFileNotFound, err.Error())
				return
			}
			break
		default:
			// traditional filesystem
			r, err = os.Open(full_path)
			if err != nil {
				requestLog.Errorf("Cannot open file: %s (%v)", query.Path, err)
				w.WriteError(tftp.ErrCodeFileNotFound, err.Error())
				return
			}

		}
	}

	qs := query.Query()
	for k, _ := range qs {
		fields[k] = qs.Get(k)
	}

	if _, err := io.Copy(w, r); err != nil {
		requestLog.Error(err)
	}

	requestLog.WithFields(fields).Infof("RRQ from %s (%s)", w.Addr().IP.String(), w.Name())
}
