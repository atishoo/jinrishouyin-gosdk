package main

import (
	"bytes"
	"crypto/md5"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"reflect"
	"sort"
	"strconv"
	"strings"
)

const (
	// BaseURL is the base URL for the API
	BaseURL              string = "http://api.pay.atishoo.cn"
	CREATEORDER          string = "/api/order/create"
	REFUNDORDER          string = "/api/order/refund"
	TRANSFERORDER        string = "/api/order/transfer"
	CREATE_GRANT_QR_TEXT string = "/api/auth/qr"
	GET_USER_INFO        string = "/api/auth/profile"
	GET_USER_PHONE       string = "/api/auth/phone"
)

type cashier struct {
	appid      string
	privateKey string
}

func NewShouyinTodayClient(appid string, private string) *cashier {
	return &cashier{
		appid:      appid,
		privateKey: private,
	}
}

type CreateOrder struct {
	TradeNo     string
	User        int64
	Title       string
	Description string
	Time        int64
	Money       int64
	Attach      string
	Noncestr    string
}

type createOrderBody struct {
	TradeNo     string `json:"trade_no"`
	User        int64  `json:"user"`
	Title       string `json:"title"`
	Description string `json:"description"`
	Time        int64  `json:"time"`
	Money       int64  `json:"money"`
	Appid       string `json:"appid"`
	Attach      string `json:"attach"`
	Noncestr    string `json:"noncestr"`
	Sign        string `json:"sign"`
}

type RefundOrderData struct {
	TradeNo  string `json:"trade_no"`
	Attach   string `json:"attach"`
	Noncestr string `json:"noncestr"`
	Appid    string `json:"appid"`
	Time     int64  `json:"time"`
	Sign     string `json:"sign"`
}

type TransferPostData struct {
	User     uint64 `json:"user"`
	Appid    string `json:"appid"`
	Money    int64  `json:"money"`
	Time     int64  `json:"time"`
	Attach   string `json:"attach"`
	Noncestr string `json:"noncestr"`
	Sign     string `json:"sign"`
}

type qrLinkDataBody struct {
	No       string `json:"no"`
	Appid    string `json:"appid"`
	Attach   string `json:"attach"`
	Noncestr string `json:"noncestr"`
	Sign     string `json:"sign"`
}

type CreateQrLinkData struct {
	Id       string // 您的qr id，最长32位长度
	Attach   string // 附加信息
	Noncestr string // 随机字符串
}

type codeBody struct {
	Code  string `json:"code"`
	Appid string `json:"appid"`
	Sign  string `json:"sign"`
}

type CashierResponse struct {
	Code int    `json:"code"`
	Msg  string `json:"msg"`
}

const SUCCESS = "SUCCESS"

var SUCCESS_RESPONSE = CashierResponse{
	Code: 1,
	Msg:  SUCCESS,
}

type OrderSuccessNotifyData struct {
	TradeNo     string `json:"trade_no"`
	User        int64  `json:"user"`
	Title       string `json:"title"`
	Description string `json:"description"`
	Time        int64  `json:"time"`
	Money       int64  `json:"money"`
	Appid       string `json:"appid"`
	Attach      string `json:"attach"`
	Noncestr    string `json:"noncestr"`
	Sign        string `json:"sign"`
	Status      string `json:"status"`
}

type QrGrantStatusNotifyData struct {
	Code      string `json:"code"`
	Attach    string `json:"attach"`
	Status    string `json:"status"`
	UniqueId  string `json:"unique_id"`
	Noncestr  string `json:"noncestr"`
	Timestamp int64  `json:"timestamp"`
	Sign      string `json:"sign"`
}

type UserInfoData struct {
	UniqueId string `json:"unique_id"`
	Nickname string `json:"nickname"`
	Avatar   string `json:"avatar"`
	Gender   int    `json:"gender"`
}

type UserPhoneData struct {
	UserInfoData
	Phone string `json:"phone"`
}

func (this *cashier) Create(data CreateOrder) []byte {
	var body createOrderBody = createOrderBody{
		TradeNo:     data.TradeNo,
		User:        data.User,
		Title:       data.Title,
		Description: data.Description,
		Time:        data.Time,
		Money:       data.Money,
		Appid:       this.appid,
		Attach:      data.Attach,
		Noncestr:    data.Noncestr,
		Sign:        "",
	}
	body.Sign = priKeyEncryptBody(signMD5(buildBodyStr(body)), this.privateKey)
	return httpPost(BaseURL+CREATEORDER, body)
}

func (this *cashier) Refund(data interface{}) interface{} {
	return httpPost(BaseURL+REFUNDORDER, data)
}

func (this *cashier) Transfer(data interface{}) interface{} {
	return httpPost(BaseURL+TRANSFERORDER, data)
}

func (this *cashier) GetGrantQrText(data CreateQrLinkData) (string, error) {
	var body qrLinkDataBody = qrLinkDataBody{
		Appid:    this.appid,
		Attach:   data.Attach,
		Noncestr: data.Noncestr,
	}
	if len(data.Id) > 32 {
		body.No = data.Id[0:32]
	} else {
		body.No = data.Id
	}
	body.Sign = priKeyEncryptBody(signMD5(buildBodyStr(body)), this.privateKey)

	response := httpPost(BaseURL+CREATE_GRANT_QR_TEXT, body)
	var resp struct {
		Status int    `json:"status"`
		Msg    string `json:"msg"`
		Data   string `json:"data"`
	}
	json.Unmarshal(response, &resp)
	if resp.Status > 0 {
		return resp.Data, nil
	} else {
		return "", errors.New(resp.Msg)
	}
}

func (this *cashier) GetUserInfo(authcode string) (*UserInfoData, error) {
	var body codeBody = codeBody{
		Code:  authcode,
		Appid: this.appid,
	}
	body.Sign = priKeyEncryptBody(signMD5(buildBodyStr(body)), this.privateKey)

	response := httpPost(BaseURL+GET_USER_INFO, body)
	var resp struct {
		Status int          `json:"status"`
		Msg    string       `json:"msg"`
		Data   UserInfoData `json:"data"`
	}
	json.Unmarshal(response, &resp)
	if resp.Status > 0 {
		return &resp.Data, nil
	} else {
		return nil, errors.New(resp.Msg)
	}
}

func (this *cashier) GetUserPhone(authcode string) (*UserPhoneData, error) {
	var body codeBody = codeBody{
		Code:  authcode,
		Appid: this.appid,
	}
	body.Sign = priKeyEncryptBody(signMD5(buildBodyStr(body)), this.privateKey)

	response := httpPost(BaseURL+GET_USER_PHONE, body)
	var resp struct {
		Status int           `json:"status"`
		Msg    string        `json:"msg"`
		Data   UserPhoneData `json:"data"`
	}
	json.Unmarshal(response, &resp)
	if resp.Status > 0 {
		return &resp.Data, nil
	} else {
		return nil, errors.New(resp.Msg)
	}
}

func (this *cashier) NotifyPaser(req *http.Request) (response *OrderSuccessNotifyData, err error) {
	body, _ := io.ReadAll(req.Body)
	str, dbe := priKeyDecryptBody(strings.ReplaceAll(string(body), "\"", ""), this.privateKey)
	if dbe != nil {
		return nil, dbe
	}

	strbyte, _ := hex.DecodeString(str)
	str = string(strbyte)

	notifyData := OrderSuccessNotifyData{}
	json.Unmarshal([]byte(str), &notifyData)

	sign := notifyData.Sign
	notifyData.Sign = ""

	if verifySignStr(notifyData, sign) {
		notifyData.Sign = sign
		return &notifyData, nil
	} else {
		return nil, errors.New("sign error")
	}
}

func (this *cashier) GetGrantStatus(req *http.Request) (response *QrGrantStatusNotifyData, err error) {
	body, _ := io.ReadAll(req.Body)
	str, dbe := priKeyDecryptBody(strings.ReplaceAll(string(body), "\"", ""), this.privateKey)
	if dbe != nil {
		return nil, dbe
	}

	strbyte, _ := hex.DecodeString(str)
	str = string(strbyte)

	notifyData := QrGrantStatusNotifyData{}
	json.Unmarshal([]byte(str), &notifyData)

	sign := notifyData.Sign
	notifyData.Sign = ""

	if verifySignStr(notifyData, sign) {
		notifyData.Sign = sign
		return &notifyData, nil
	} else {
		return nil, errors.New("sign error")
	}
}

func (obj *QrGrantStatusNotifyData) IsScan() bool {
	return obj.Status == "scan"
}

func (obj *QrGrantStatusNotifyData) IsInvalid() bool {
	return obj.Status == "invalid"
}

func (obj *QrGrantStatusNotifyData) IsCancel() bool {
	return obj.Status == "cancel"
}

func (obj *QrGrantStatusNotifyData) IsGrant() bool {
	return !obj.IsScan() && !obj.IsInvalid() && !obj.IsCancel()
}

func (obj *QrGrantStatusNotifyData) GetAuthCode() string {
	return obj.Status
}

func httpPost(url string, data interface{}) []byte {
	body, _ := json.Marshal(&data)
	response, err := http.Post(url, "application/json", bytes.NewReader(body))
	defer response.Body.Close()

	if err != nil || response.StatusCode != 200 {
		return nil
	} else {
		resp, _ := io.ReadAll(response.Body)
		return resp
	}
}

func buildBodyStr(data interface{}) string {
	var keys []string
	var keysMap = map[string]string{}
	types := reflect.TypeOf(data)
	for i := 0; i < types.NumField(); i++ {
		keys = append(keys, types.Field(i).Tag.Get("json"))
		keysMap[types.Field(i).Tag.Get("json")] = types.Field(i).Name
	}
	sort.Strings(keys)

	values := reflect.ValueOf(data)
	var unsignStrArr = []string{}
	for _, field := range keys {
		if values.FieldByName(keysMap[field]).Type().Name() == "int64" && values.FieldByName(keysMap[field]).Int() != 0 {
			unsignStrArr = append(unsignStrArr, field+"="+strconv.FormatInt(values.FieldByName(keysMap[field]).Int(), 10))
		} else if values.FieldByName(keysMap[field]).Type().Name() == "uint64" && values.FieldByName(keysMap[field]).Uint() != 0 {
			unsignStrArr = append(unsignStrArr, field+"="+strconv.FormatUint(values.FieldByName(keysMap[field]).Uint(), 10))
		} else {
			if values.FieldByName(keysMap[field]).String() != "" {
				unsignStrArr = append(unsignStrArr, field+"="+values.FieldByName(keysMap[field]).String())
			}
		}
	}

	return strings.Join(unsignStrArr, "&")
}

func signMD5(str string) string {
	return fmt.Sprintf("%x", md5.Sum([]byte(str)))
}

func priKeyEncryptBody(str string, private_key string) string {
	grsa := rsaSecurity{}
	grsa.setPrivateKey(private_key)

	signture, err := grsa.priKeyENCTYPT([]byte(str))
	if err != nil {
		return ""
	}

	return base64.StdEncoding.EncodeToString(signture)
}

func priKeyDecryptBody(data, privateKey string) (string, error) {
	databs, err := base64.StdEncoding.DecodeString(data)
	if err != nil {
		return "", err
	}
	grsa := rsaSecurity{}
	if err := grsa.setPrivateKey(privateKey); err != nil {
		return "", err
	}

	rsadata, err := grsa.priKeyDECRYPT(databs)
	if err != nil {
		return "", err
	}

	return hex.EncodeToString(rsadata), nil
}

func verifySignStr(data interface{}, sign string) bool {
	signStr := signMD5(buildBodyStr(data))
	return signStr == sign
}

type rsaSecurity struct {
	priStr string          //私钥字符串
	prikey *rsa.PrivateKey //私钥
}

// 设置私钥
func (rsas *rsaSecurity) setPrivateKey(priStr string) (err error) {
	rsas.priStr = priStr
	rsas.prikey, err = rsas.getPrivatekey()
	return err
}

func (rsas *rsaSecurity) getPrivatekey() (*rsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(rsas.priStr))
	if block == nil {
		return nil, errors.New("get private key error")
	}
	pri, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err == nil {
		return pri, nil
	}

	pri2, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	return pri2.(*rsa.PrivateKey), nil
}

func (rsas *rsaSecurity) priKeyENCTYPT(input []byte) ([]byte, error) {
	if rsas.prikey == nil {
		return []byte(""), errors.New(`Please set the private key in advance`)
	}
	output := bytes.NewBuffer(nil)
	err := priKeyIO(rsas.prikey, bytes.NewReader(input), output, true)
	if err != nil {
		return []byte(""), err
	}
	return io.ReadAll(output)
}

func (rsas *rsaSecurity) priKeyDECRYPT(input []byte) ([]byte, error) {
	if rsas.prikey == nil {
		return []byte(""), errors.New(`Please set the private key in advance`)
	}
	output := bytes.NewBuffer(nil)
	err := priKeyIO(rsas.prikey, bytes.NewReader(input), output, false)
	if err != nil {
		return []byte(""), err
	}
	return io.ReadAll(output)
}

// 私钥加密或解密Reader
func priKeyIO(pri *rsa.PrivateKey, r io.Reader, w io.Writer, isEncrytp bool) (err error) {
	k := (pri.N.BitLen() + 7) / 8
	if isEncrytp {
		k = k - 11
	}
	buf := make([]byte, k)
	var b []byte
	size := 0
	for {
		size, err = r.Read(buf)
		if err != nil {
			if err == io.EOF {
				return nil
			}
			return err
		}
		if size < k {
			b = buf[:size]
		} else {
			b = buf
		}
		if isEncrytp {
			b, err = priKeyEncrypt(rand.Reader, pri, b)
		} else {
			b, err = rsa.DecryptPKCS1v15(rand.Reader, pri, b)
		}
		if err != nil {
			return err
		}
		if _, err = w.Write(b); err != nil {
			return err
		}
	}
	return nil
}

// 私钥加密
func priKeyEncrypt(rand io.Reader, priv *rsa.PrivateKey, hashed []byte) ([]byte, error) {
	tLen := len(hashed)
	k := (priv.N.BitLen() + 7) / 8
	if k < tLen+11 {
		return nil, errors.New("data length error")
	}
	em := make([]byte, k)
	em[1] = 1
	for i := 2; i < k-tLen-1; i++ {
		em[i] = 0xff
	}
	copy(em[k-tLen:k], hashed)
	m := new(big.Int).SetBytes(em)
	c, err := decrypt(rand, priv, m)
	if err != nil {
		return nil, err
	}
	numPaddingBytes := len(em) - len(c.Bytes())
	for i := 0; i < numPaddingBytes; i++ {
		em[i] = 0
	}
	copy(em[numPaddingBytes:], c.Bytes())
	return em, nil
}

// 从crypto/rsa复制
func decrypt(random io.Reader, priv *rsa.PrivateKey, c *big.Int) (m *big.Int, err error) {
	if c.Cmp(priv.N) > 0 {
		err = errors.New("decryption error")
		return
	}
	var ir *big.Int
	if random != nil {
		var r *big.Int

		for {
			r, err = rand.Int(random, priv.N)
			if err != nil {
				return
			}
			if r.Cmp(big.NewInt(0)) == 0 {
				r = big.NewInt(1)
			}
			var ok bool
			ir, ok = modInverse(r, priv.N)
			if ok {
				break
			}
		}
		bigE := big.NewInt(int64(priv.E))
		rpowe := new(big.Int).Exp(r, bigE, priv.N)
		cCopy := new(big.Int).Set(c)
		cCopy.Mul(cCopy, rpowe)
		cCopy.Mod(cCopy, priv.N)
		c = cCopy
	}
	if priv.Precomputed.Dp == nil {
		m = new(big.Int).Exp(c, priv.D, priv.N)
	} else {
		m = new(big.Int).Exp(c, priv.Precomputed.Dp, priv.Primes[0])
		m2 := new(big.Int).Exp(c, priv.Precomputed.Dq, priv.Primes[1])
		m.Sub(m, m2)
		if m.Sign() < 0 {
			m.Add(m, priv.Primes[0])
		}
		m.Mul(m, priv.Precomputed.Qinv)
		m.Mod(m, priv.Primes[0])
		m.Mul(m, priv.Primes[1])
		m.Add(m, m2)

		for i, values := range priv.Precomputed.CRTValues {
			prime := priv.Primes[2+i]
			m2.Exp(c, values.Exp, prime)
			m2.Sub(m2, m)
			m2.Mul(m2, values.Coeff)
			m2.Mod(m2, prime)
			if m2.Sign() < 0 {
				m2.Add(m2, prime)
			}
			m2.Mul(m2, values.R)
			m.Add(m, m2)
		}
	}
	if ir != nil {
		m.Mul(m, ir)
		m.Mod(m, priv.N)
	}

	return
}

func modInverse(a, n *big.Int) (ia *big.Int, ok bool) {
	g := new(big.Int)
	x := new(big.Int)
	y := new(big.Int)
	g.GCD(x, y, a, n)
	if g.Cmp(big.NewInt(1)) != 0 {
		return
	}
	if x.Cmp(big.NewInt(1)) < 0 {
		x.Add(x, n)
	}
	return x, true
}
