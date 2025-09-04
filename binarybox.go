package main

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"fmt"
)

var (
	CERTTYPE_IM = uint32(0x696D696D)
	CERTTYPE_FT = uint32(0x66746674)

	VERSION_ONE = uint32(1)

	BPINDEX_SN      = uint32(0x10)
	BPINDEX_MAIN_ID = uint32(0x11)

	BPINDEX_PUSH_TOKEN = uint32(0x21)
	BPINDEX_PUSH_CERT  = uint32(0x22)
	BPINDEX_PUSH_KEY   = uint32(0x23)

	BPINDEX_ID_CERT     = uint32(0x31)
	BPINDEX_ID_PRIV_KEY = uint32(0x32)

	BPINDEX_EC_PUB_KEY   = uint32(0x41)
	BPINDEX_EC_PRIV_KEY  = uint32(0x42)
	BPINDEX_RSA_PUB_KEY  = uint32(0x43)
	BPINDEX_RSA_PRIV_KEY = uint32(0x44)

	BPINDEX_LEGACY_FULL_IDENTIDY_KEY = uint8(0x45)
)

// Context 上下文
type Context struct {
	// meta
	Identifier  string `json:"Identifier"`
	CertType    uint32 `json:"-"`
	CertVersion uint32 `json:"-"`

	SeqID        int    `json:"-"`
	SerialNumber string `json:"SN"`
	SourceID     string `json:"ACC"`

	// push
	PushToken string `json:"PUSH_TOKEN"`
	PushCert  string `json:"PUSH_CERT"`
	PushKey   string `json:"PUSH_KEY"`

	// mp
	ECPubKey   string `json:"EC_PUB_KEY"`
	ECPrivKey  string `json:"EC_PRI_KEY"`
	RSAPubKey  string `json:"RSA_PUB_KEY"`
	RSAPrivKey string `json:"RSA_PRI_KEY"`

	// id
	IDCert string `json:"ID_CERT"`
	IDKey  string `json:"ID_KEY"`
}

func ParseBBOXWithHeader(based64bbox string) (*Context, error) {
	ctx := &Context{}
	bbox, err := base64.StdEncoding.DecodeString(based64bbox)
	if err != nil {
		return nil, err
	}
	t_b0 := uint32(bbox[0])
	t_b1 := uint32(bbox[1])
	t_b2 := uint32(bbox[2])
	t_b3 := uint32(bbox[3])
	t_val := t_b0<<24 + t_b1<<16 + t_b2<<8 + t_b3
	ctx.CertType = t_val
	v_b0 := uint32(bbox[4])
	v_b1 := uint32(bbox[5])
	v_b2 := uint32(bbox[6])
	v_b3 := uint32(bbox[7])
	v_val := v_b0<<24 + v_b1<<16 + v_b2<<8 + v_b3
	ctx.CertVersion = v_val
	ParseFromBBOX(bbox[8:], ctx)
	return ctx, err
}

func ParseFromBBOX(bbox []byte, ctx *Context) error {
	var fidx uint32
	var flen uint32
	p_offset := uint32(0)
	t_len := uint32(len(bbox))
	for {
		if p_offset >= t_len {
			break
		}
		fidx_b0 := uint32(bbox[p_offset])
		fidx_b1 := uint32(bbox[p_offset+1])
		fidx_b2 := uint32(bbox[p_offset+2])
		fidx_b3 := uint32(bbox[p_offset+3])
		fidx = fidx_b0<<24 + fidx_b1<<16 + fidx_b2<<8 + fidx_b3
		p_offset += 4
		len_b0 := uint32(bbox[p_offset])
		len_b1 := uint32(bbox[p_offset+1])
		len_b2 := uint32(bbox[p_offset+2])
		len_b3 := uint32(bbox[p_offset+3])
		flen = len_b0<<24 + len_b1<<16 + len_b2<<8 + len_b3
		p_offset += 4
		if p_offset+flen > t_len {
			fmt.Println("Not Enough Data")
			break
		}
		fval := bbox[p_offset : p_offset+flen]
		switch fidx {
		case BPINDEX_SN:
			{
				ctx.SerialNumber = string(fval)
			}
		case BPINDEX_MAIN_ID:
			{
				ctx.SourceID = string(fval)
			}
		case BPINDEX_PUSH_TOKEN:
			{
				ctx.PushToken = base64.StdEncoding.EncodeToString(fval)
			}
		case BPINDEX_PUSH_CERT:
			{
				ctx.PushCert = base64.StdEncoding.EncodeToString(fval)
			}
		case BPINDEX_PUSH_KEY:
			{
				ctx.PushKey = base64.StdEncoding.EncodeToString(fval)
			}
		case BPINDEX_ID_CERT:
			{
				ctx.IDCert = base64.StdEncoding.EncodeToString(fval)
			}
		case BPINDEX_ID_PRIV_KEY:
			{
				ctx.IDKey = base64.StdEncoding.EncodeToString(fval)
			}
		case BPINDEX_EC_PUB_KEY:
			{
				ctx.ECPubKey = base64.StdEncoding.EncodeToString(fval)
			}
		case BPINDEX_EC_PRIV_KEY:
			{
				ctx.ECPrivKey = base64.StdEncoding.EncodeToString(fval)
			}
		case BPINDEX_RSA_PUB_KEY:
			{
				ctx.RSAPubKey = base64.StdEncoding.EncodeToString(fval)
			}
		case BPINDEX_RSA_PRIV_KEY:
			{
				ctx.RSAPrivKey = base64.StdEncoding.EncodeToString(fval)
			}
		}
		p_offset += flen
	}
	return nil
}

func PackBBOX(ctx *Context) ([]byte, error) {
	buf := bytes.NewBuffer([]byte{})
	binary.Write(buf, binary.BigEndian, CERTTYPE_IM)
	binary.Write(buf, binary.BigEndian, VERSION_ONE)
	if ctx.SerialNumber != "" {
		binary.Write(buf, binary.BigEndian, BPINDEX_SN)
		sn_bytes := []byte(ctx.SerialNumber)
		sn_len := uint32(len(sn_bytes))
		binary.Write(buf, binary.BigEndian, sn_len)
		buf.Write(sn_bytes)
	}
	if ctx.SourceID != "" {
		binary.Write(buf, binary.BigEndian, BPINDEX_MAIN_ID)
		sid_bytes := []byte(ctx.SourceID)
		sid_len := uint32(len(sid_bytes))
		binary.Write(buf, binary.BigEndian, sid_len)
		buf.Write(sid_bytes)
	}

	if ctx.PushToken != "" {
		binary.Write(buf, binary.BigEndian, BPINDEX_PUSH_TOKEN)
		pt_bytes, _ := base64.StdEncoding.DecodeString(ctx.PushToken)
		pt_len := uint32(len(pt_bytes))
		binary.Write(buf, binary.BigEndian, pt_len)
		buf.Write(pt_bytes)
	}

	if ctx.PushCert != "" {
		binary.Write(buf, binary.BigEndian, BPINDEX_PUSH_CERT)
		pc_bytes, _ := base64.StdEncoding.DecodeString(ctx.PushCert)
		pc_len := uint32(len(pc_bytes))
		binary.Write(buf, binary.BigEndian, pc_len)
		buf.Write(pc_bytes)
	}

	if ctx.PushKey != "" {
		binary.Write(buf, binary.BigEndian, BPINDEX_PUSH_KEY)
		pk_bytes, _ := base64.StdEncoding.DecodeString(ctx.PushKey)
		pk_len := uint32(len(pk_bytes))
		binary.Write(buf, binary.BigEndian, pk_len)
		buf.Write(pk_bytes)
	}

	if ctx.ECPubKey != "" {
		binary.Write(buf, binary.BigEndian, BPINDEX_EC_PUB_KEY)
		ecpub_bytes, _ := base64.StdEncoding.DecodeString(ctx.ECPubKey)
		ecpub_len := uint32(len(ecpub_bytes))
		binary.Write(buf, binary.BigEndian, ecpub_len)
		buf.Write(ecpub_bytes)
	}

	if ctx.ECPrivKey != "" {
		binary.Write(buf, binary.BigEndian, BPINDEX_EC_PRIV_KEY)
		ecpriv_bytes, _ := base64.StdEncoding.DecodeString(ctx.ECPrivKey)
		ecpriv_len := uint32(len(ecpriv_bytes))
		binary.Write(buf, binary.BigEndian, ecpriv_len)
		buf.Write(ecpriv_bytes)
	}

	if ctx.RSAPubKey != "" {
		binary.Write(buf, binary.BigEndian, BPINDEX_RSA_PUB_KEY)
		rsapub_bytes, _ := base64.StdEncoding.DecodeString(ctx.RSAPubKey)
		rsapub_len := uint32(len(rsapub_bytes))
		binary.Write(buf, binary.BigEndian, rsapub_len)
		buf.Write(rsapub_bytes)
	}

	if ctx.RSAPrivKey != "" {
		binary.Write(buf, binary.BigEndian, BPINDEX_RSA_PRIV_KEY)
		rsapriv_bytes, _ := base64.StdEncoding.DecodeString(ctx.RSAPrivKey)
		rsapriv_len := uint32(len(rsapriv_bytes))
		binary.Write(buf, binary.BigEndian, rsapriv_len)
		buf.Write(rsapriv_bytes)
	}

	if ctx.IDCert != "" {
		binary.Write(buf, binary.BigEndian, BPINDEX_ID_CERT)
		idcert_bytes, _ := base64.StdEncoding.DecodeString(ctx.IDCert)
		idcert_len := uint32(len(idcert_bytes))
		binary.Write(buf, binary.BigEndian, idcert_len)
		buf.Write(idcert_bytes)
	}

	if ctx.IDKey != "" {
		binary.Write(buf, binary.BigEndian, BPINDEX_ID_PRIV_KEY)
		idkey_bytes, _ := base64.StdEncoding.DecodeString(ctx.IDKey)
		idkey_len := uint32(len(idkey_bytes))
		binary.Write(buf, binary.BigEndian, idkey_len)
		buf.Write(idkey_bytes)
	}
	return buf.Bytes(), nil
}

func main() {
	dc := "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"
	b, _ := base64.StdEncoding.DecodeString(dc)
	s := hex.EncodeToString(b)
	fmt.Println(s)
	fmt.Println("-----------")
	ctx, _ := ParseBBOXWithHeader(dc)
	fmt.Println(ctx.IDCert)
	buf, _ := PackBBOX(ctx)
	hbuf := hex.EncodeToString(buf)
	fmt.Println(hbuf)
}
