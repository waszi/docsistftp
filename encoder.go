package main

import (
    "net"
    "fmt"
    "sort"
    "bytes"
    "net/url"
    "crypto/md5"
    "encoding/hex"
    "encoding/binary"
    "io/ioutil"
    "github.com/jmoiron/sqlx"
    "github.com/cdevr/WapSNMP"
    "github.com/mattn/anko/vm"
    "github.com/mattn/anko/core"
    "github.com/mattn/anko/parser"
    "github.com/mattn/anko/packages"
    "github.com/fullsailor/pkcs7"
)

func TLV(t int64, v ...[]byte) []byte {
    value := make([]byte, 0)
    for _, i := range v {
	value = append( value, i... )
    }
    return append([]byte{uint8(t), uint8(len(value))}, value...)
}

func Snmp(oidString string, t string, v interface{}) []byte {
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
    content, err := ioutil.ReadFile(filename)
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

type Encoder struct {
    script string
    env *vm.Env
    db *sqlx.DB
    query url.Values
    tlvOutput map[uint8][]byte
}

func NewEncoder(db *sqlx.DB, filename string, query url.Values) *Encoder {
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
    env.Define("extract_cvc", ExtractCVC)
    env.Define("chunk_split", ChunkSplit)

    core.Import(env)
    packages.DefineImport(env)

    output := make(map[uint8][]byte)
    return &Encoder{string(b), env, db, query, output}
}

func (e *Encoder) Encode() (*bytes.Buffer, error) {
    e.env.Define("tlv_add", e.TlvAdd)
    e.env.Define("sql_row", e.SqlQueryRow)
    e.env.Define("config_type", "cm") // mta, text
    e.env.Define("query", e.query)

    out, err := e.env.Execute(e.script)
    if err != nil {
	switch e := err.(type) {
	    case *parser.Error:
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
	    sort.Ints(keys)
	    for _, k := range keys {
		res.Write(e.tlvOutput[uint8(k)])
	    }
	    e.CmMic(res.Bytes())
	    res.Write(e.tlvOutput[6])
	    res.Write(e.tlvOutput[7])
	default:
	    res.Write(out.([]byte))
    }

    return res, nil
}

func (e *Encoder) TlvAdd( t int64, v ...[]byte ) {
    e.tlvOutput[uint8(t)] = append(e.tlvOutput[uint8(t)], TLV(t, v...)... )
}

func (e *Encoder) SqlQueryRow(query string, args ...interface{}) map[string]interface{} {
    object := make(map[string]interface{})
    err := e.db.QueryRowx(query, args...).MapScan(object)
    if err != nil {
	log.Error(err)
	return nil
    }
    return object
}

func (e *Encoder) CmMic(data []byte) {
    digest := md5.New()
    digest.Write(data)
    e.tlvOutput[6] = TLV(6, digest.Sum(nil) )
}

/*
    //fields := []uint8{ 1, 2, 3, 4, 17, 43, 6, 18, 19, 20, 22, 23, 24, 25, 28, 29, 26, 35, 36, 37, 40 }
    data = self.data + [ cm_mic ]
    for i in fields:
	for j in data:
	    if i == j.t:
	        binstring += str(j)
	mic = hmac.new(self.secret, binstring).digest()
    */

    //e.tlvOutput[7] = Tlv(7, md5()) 

/*
func (e *Encoder) Pad() {
    pads = 4 - (1 + len(result)) % 4;
    return pack("B", 255) + pads * chr(0) 
}
*/
