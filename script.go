package main

import (
    "net"
    "fmt"
    "bytes"
    "net/url"
    "crypto/md5"
    "encoding/hex"
    "encoding/binary"
    "io/ioutil"
    "github.com/jmoiron/sqlx"
    "github.com/mattn/anko/vm"
    "github.com/mattn/anko/core"
    "github.com/mattn/anko/parser"
    "github.com/mattn/anko/packages"
)

type Script struct {
    filename string
    env *vm.Env
    db *sqlx.DB
    query url.Values
    tlvOutput map[uint8][]byte
}

func NewScript(filename string, db *sqlx.DB, query url.Values) *Script {
    b, err := ioutil.ReadFile(filename)
    if err != nil {
	log.Fatal(err)
    }

    env := vm.NewEnv()
    env.Define("uint8", func(v int64) []byte {
	res := make([]byte, 1)
	res[0] = uint8(v)
	return res
    })
    env.Define("uint16", func(v int64) []byte {
	res := make([]byte, 2)
	binary.BigEndian.PutUint16(res, uint16(v))
	return res
    })
    env.Define("uint32", func(v int64) []byte {
	res := make([]byte, 4)
	binary.BigEndian.PutUint32(res, uint32(v))
	return res
    })
    env.Define("uint64", func(v int64) []byte {
	res := make([]byte, 8)
	binary.BigEndian.PutUint64(res, uint64(v))
	return res
    })
    env.Define("hexstring", func(v string) string {
	bs, _ := hex.DecodeString(v)
	return string(bs)
    })
    env.Define("ip", func(v string) []byte {
        ip := net.ParseIP(v)
        if ip == nil {
	    return nil
	}
	ip = ip.To4()
	if ip == nil {
	    return nil
	}
	return []byte(ip)
    })
    env.Define("tlv", TLV)
    env.Define("snmp", Snmp)
    env.Define("snmp_gauge", SnmpGauge)
    env.Define("extract_cvc", ExtractCVC)
    env.Define("chunk_split", ChunkSplit)
    env.Define("get_firmware_path", GetFirmwarePath)

    core.Import(env)
    packages.DefineImport(env)

    output := make(map[uint8][]byte)
    return &Script{string(b), env, db, query, output}
}

func (e *Script) Execute() (*bytes.Buffer, error) {
    e.env.Define("tlv_add", e.TlvAdd)
    e.env.Define("sql_row", e.SqlQueryRow)
    e.env.Define("query", e.query)

    out, err := e.env.Execute(e.filename)
    if err != nil {
	switch e := err.(type) {
	    case *parser.Error:
		return nil, fmt.Errorf("[%v:%v]: %v", e.Pos.Line, e.Pos.Column, e.Message)
	    case *vm.Error:
		return nil, fmt.Errorf("[%v:%v]: %v", e.Pos.Line, e.Pos.Column, e.Message)
	    default:
		return nil, err
	}
    }

    res := bytes.NewBuffer(nil)
    switch t, _ := e.env.Get("config_type"); t {
	case "cm", "mta":
	    var keys []int
	    for k := range e.tlvOutput {
		if k != 6 && k != 7 {
		    keys = append(keys, int(k))
		}
	    }
	    for _, k := range keys {
	        res.Write(e.tlvOutput[uint8(k)])
	    }
	    if t == "cm" {
		e.CmMic(res.Bytes())
		res.Write(e.tlvOutput[6])
		res.Write(e.tlvOutput[7])
	    }
	default:
	    res.Write(out.([]byte))
    }

    return res, nil
}

func (e *Script) TlvAdd( t int64, v ...[]byte ) {
    e.tlvOutput[uint8(t)] = append(e.tlvOutput[uint8(t)], TLV(t, v...)... )
}

func (e *Script) SqlQueryRow(query string, args ...interface{}) map[string]interface{} {
    object := make(map[string]interface{})
    err := e.db.QueryRowx(query, args...).MapScan(object)
    if err != nil {
	log.Error(err)
	return nil
    }
    return object
}

func (e *Script) CmMic(data []byte) {
    digest := md5.New()
    digest.Write(data)
    e.tlvOutput[6] = TLV(6, digest.Sum(nil) )
}

func (e *Script) CmtsMic(data []byte) {
    /*
    fields := []uint8{ 1, 2, 3, 4, 17, 43, 6, 18, 19, 20, 22, 23, 24, 25, 28, 29, 26, 35, 36, 37, 40 }

    data = self.data + [ cm_mic ]
    for i in fields:
	for j in data:
	    if i == j.t:
	        binstring += str(j)
	mic = hmac.new(self.secret, binstring).digest()

    e.tlvOutput[7] = TLV(7, md5()) 
    */
}

/*
func (e *Script) Pad() {
    pads = 4 - (1 + len(result)) % 4;
    return pack("B", 255) + pads * chr(0) 
}
*/
