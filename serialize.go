package main

import (
  "encoding/json"
  "github.com/mmx1/opensslgo"
  "os"
  "strconv"
  "time"
)

type ConnectionError int
const (
  connectionRefused ConnectionError = iota // == 0
  sslError // == 1
  timeout
  invalidHostname
  connectionReset
  ipUnreacheable
  blockedDoS
  dhKeyTooSmall
  dhRSAmismatch
  other
)

type KeyExchangeMethod int8
const (
  rsaKeyExch KeyExchangeMethod = 1 << iota
  dhe //2
  ecdhe //4
  fixedECDH //8
)

type AuthMethod int8
const (
  rsaAuth AuthMethod = 1 << iota
  anonymous
  dsa
  ec
)

type HandShakeResult struct {
  Cipher string
  TLSVersion openssl.SSLVersion
  KeyExchangeID int
  KeyExchangeBits int
  KeyExchangeCurve string //don't hard-code curve names and ask directly from OpenSSL
  AuthKeyId int
  AuthKeyBits int
  AuthKeyCurve string
}

type ScanResult struct{
  Id int
  Error []ConnectionError
  KeyExchangeMethods KeyExchangeMethod
  AuthMethods AuthMethod
  Handshakes []HandShakeResult
  Timestamp time.Time
  Comments string //drop exceptions in here to filter later
}

func exists(path string) (bool, error) {
    _, err := os.Stat(path)
    if err == nil { return true, nil }
    if os.IsNotExist(err) { return false, nil }
    return true, err
}

var dataDir = "./data/"
func (o *sslCheckOptions) print(fileName string) {



  //write data dir if not exists
  if _, err:= os.Stat(dataDir); err != nil {
    if os.IsNotExist(err) {
      err = os.Mkdir(dataDir, os.ModeDir | os.ModePerm)
    }
    check(err)
  }

  //check if existing file and move 
  fileName = dataDir + fileName + ".json"
  if _, err:= os.Stat(fileName); err == nil || !os.IsNotExist(err) {
    fileName += "." + strconv.Itoa( int(time.Now().Unix() ))
  }

  
  outputFile, err := os.Create(fileName)
  check(err)
  defer outputFile.Close()

  // fmt.Println(o.result)
  // jsonObj, err := json.Marshal(o.result)
  // fmt.Println(string(jsonObj[:]), err)

  encoder := json.NewEncoder(outputFile)
  err = encoder.Encode(&o.result)
}