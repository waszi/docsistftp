package main

import (
    "os"
    "fmt"
    "path/filepath"
    "io/ioutil"
    "github.com/cdevr/WapSNMP"
    "github.com/fullsailor/pkcs7"
    "github.com/spf13/viper"
)

func TLV(t int64, v ...[]byte) []byte {
    value := make([]byte, 0)
    for _, i := range v {
	value = append( value, i... )
    }
    return append([]byte{uint8(t), uint8(len(value))}, value...)
}

func Snmp(oidString string, v interface{}) []byte {
    oid, err := wapsnmp.ParseOid(oidString)
    if err != nil {
	return nil
    }

    res, err := wapsnmp.EncodeSequence([]interface{}{
	wapsnmp.Sequence,
	oid,
	v,
    })
    if err != nil {
	return nil
    }

    return res
}

func SnmpGauge(v int64) wapsnmp.Gauge {
    return wapsnmp.Gauge(v)
}

func ChunkSplit(buf []byte, lim int) [][]byte {
    var chunk []byte
    chunks := make([][]byte, 0, len(buf)/lim+1)
    for len(buf) >= lim {
	chunk, buf = buf[:lim], buf[lim:]
	chunks = append(chunks, chunk)
    }
    if len(buf) > 0 {
	chunks = append(chunks, buf[:len(buf)])
    }
    return chunks
}

func ExtractCVC(filename string) ([]byte) {
    full_path := filepath.Join(viper.GetString("root_dir"), filename)
    content, err := ioutil.ReadFile(full_path)
    if err != nil {
	log.Error(err)
	return []byte("")
    }

    p, err := pkcs7.Parse(content)
    if err != nil {
	log.Error(err)
	return []byte("")
    }

    cert := p.GetOnlySigner()
    return cert.Raw
}

func GetFirmwarePath(model string, hwver string) string {
    full_path := filepath.Join(viper.GetString("root_dir"), "firmware", fmt.Sprintf("%s-%s", model, hwver), "current")
    log.Printf("Checking firmware path: %v", full_path)
    if _, err := os.Stat(full_path); err == nil {
	log.Printf("Found firmware: %v", full_path)
	if target, err := os.Readlink(full_path); err == nil {
	    return filepath.Join("firmware", fmt.Sprintf("%s-%s", model, hwver), target)
	}
    }

    full_path = filepath.Join(viper.GetString("root_dir"), "firmware", model, "current")
    log.Printf("Checking firmware path: %v", full_path)
    if _, err := os.Stat(full_path); err == nil {
	log.Printf("Found firmware: %v", full_path)
	if target, err := os.Readlink(full_path); err == nil {
	    return filepath.Join("firmware", model, target)
	}
    }

    return ""
}
