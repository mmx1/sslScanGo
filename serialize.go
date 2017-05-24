package main

import (
  "encoding/json"
  "os"
  "strconv"
  "time"
)

type connectionError int
const (
  connectionRefused connectionError = iota // == 0
  sslError // == 1
  timeout
  invalidHostname
  connectionReset
  ipUnreacheable
  blockedDoS
  dhKeyTooSmall
  other
)

type keyExchangeMethod int
const (
  rsaKeyExch keyExchangeMethod = iota
  dhe
  ecdhe
  fixedECDH
  anonECDHE
)

type authMethod int
const (
  rsaAuth authMethod = iota
  anonymous
  dsa
  ecdsa
  ecdh
)

type handShakeResult struct {
  cipher string
  keyExchangeID int
  keyExchangeBits int
  ecdheCurve string //don't hard-code curve names and ask directly from OpenSSL
  authKeyBits int
}

type ScanResult struct{
  id int
  error []connectionError
  //golang doesn't have option sets (bitmasks). So....array of ints
  keyExchangeMethods []keyExchangeMethod
  authMethods []authMethod

  handshakes []handShakeResult
  timestamp time.Time
  comments string //drop exceptions in here to filter later
}

func exists(path string) (bool, error) {
    _, err := os.Stat(path)
    if err == nil { return true, nil }
    if os.IsNotExist(err) { return false, nil }
    return true, err
}

var dataDir = "./data/"
func (o sslCheckOptions) print(fileName string) {

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

  encoder := json.NewEncoder(outputFile)
  err = encoder.Encode(&o.result)
}