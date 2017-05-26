package main

import (
  "encoding/json"
  "database/sql"
  // "fmt"
  _ "github.com/mattn/go-sqlite3"
  "io/ioutil"
  "log"
  "os"
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
  //golang doesn't have option sets (bitmasks). So....array of ints
  KeyExchangeMethods KeyExchangeMethod
  AuthMethods AuthMethod

  Handshakes []HandShakeResult
  Timestamp time.Time
  Comments string //drop exceptions in here to filter later
}

func check(e error) {
  if e != nil {
    log.Fatal(e)
  }
}

func main () {
  args := os.Args
  // expect src, destination , default to data/ scanDb.sqlite

  dataDir := "./data/"
  outputName := "./scanDb.sqlite"
  switch len(args) {
    case 3:
      outputName = args[2]
      fallthrough
    case 2:
      dataDir = args[1]
  }

  // //fix: warn or pause if already exists
  os.Remove(outputName)

  db, err := sql.Open("sqlite3", outputName)
  check(err)

  defer db.Close()

  createHosts := `
  create table hosts (id integer not null primary key,
                      name text,
                      errors int,
                      keyExRSA bool,
                      keyExDHE bool,
                      keyExECDHE bool,
                      authRSA bool,
                      authAnon bool,
                      authDSA bool,
                      authEC bool,
                      comments text 
                      )
  `
  createHandshakes := `
  create table handshakes (id integer not null primary key,
                           host integer,
                           cipher text,
                           keyexid int,
                           keyexbits int ,
                           keyexcurve string,
                           authid int,
                           authbits int,
                           authcurve string,
                           FOREIGN KEY(host) REFERENCES hosts(id)
                      )
  `
  _, err = db.Exec(createHosts)
  check(err)

  _, err = db.Exec(createHandshakes)
  check(err)

  log.Println(dataDir, outputName)

  //todo, read 1m file and fill in name

  insertHostStmt, err := db.Prepare("insert into hosts (id, errors, keyExRSA, keyExDHE, keyExECDHE, authRSA, authAnon, authDSA, authEC, comments) VALUES( ?, ?, ?, ?, ?, ?, ?, ?, ?, ? )")
  check(err)
  defer insertHostStmt.Close()
  insertHandshakeStmt, err := db.Prepare("insert into handshakes (host, cipher, keyexid, keyexbits, keyexcurve, authid, authbits, authcurve ) VALUES ( ?, ?, ?, ?, ?, ?, ?, ?) ")
  check(err) 
  defer insertHandshakeStmt.Close()

  files, err := ioutil.ReadDir(dataDir)
  check(err)
  for _, f := range files {
    log.Println(dataDir + f.Name())
    file, err := os.Open(dataDir +  f.Name())
    if err != nil {
      log.Printf("Error reading file %s: %s \n", f, err)
      continue
    }
    defer file.Close()

    decoder := json.NewDecoder(file)
    var result ScanResult
    err = decoder.Decode(&result)
    if err != nil {
      log.Printf("Error reading json in file %s: %s \n", f, err)
      continue
    }

    // log.Printf(result)

    errorMask := 0
    //make into a bitmask
    for _ , element := range result.Error {
      errorMask += 1 << uint(element)
    }

    //todo, export constants from serialze.go?
    _, err = insertHostStmt.Exec( result.Id, 
                        errorMask, 
                        (result.KeyExchangeMethods & 1) != 0,  
                        (result.KeyExchangeMethods & 2) != 0,
                        (result.KeyExchangeMethods & 4) != 0,
                        (result.AuthMethods & 1) != 0,
                        (result.AuthMethods & 2) != 0,
                        (result.AuthMethods & 4) != 0,
                        (result.AuthMethods & 8) != 0,
                        result.Comments )


    //

  }
}