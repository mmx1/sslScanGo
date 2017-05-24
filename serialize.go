package main

import (
  "encoding/json"
  // "fmt"
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
  other
)

type KeyExchangeMethod int
const (
  rsaKeyExch KeyExchangeMethod = iota
  dhe
  ecdhe
  fixedECDH
  anonECDHE
)

type AuthMethod int
const (
  rsaAuth AuthMethod = iota
  anonymous
  dsa
  ecdsa
  ecdh
)

type HandShakeResult struct {
  Cipher string
  KeyExchangeID int
  KeyExchangeBits int
  EcdheCurve string //don't hard-code curve names and ask directly from OpenSSL
  AuthKeyBits int
}

type ScanResult struct{
  Id int
  Error []ConnectionError
  //golang doesn't have option sets (bitmasks). So....array of ints
  KeyExchangeMethods []KeyExchangeMethod
  AuthMethods []AuthMethod

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
      err = os.Mkdir(dataDir, os.ModeDir)
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