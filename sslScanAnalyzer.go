package main

import (
  // "encoding/json"
  "database/sql"
  // "fmt"
  _ "github.com/mattn/go-sqlite3"
  // "io/ioutil"
  "log"
  "os"
)

type ConnectionError int
const (
  connectionRefused ConnectionError = 1 << iota // == 0
  sslError // == 2
  timeout
  invalidHostname
  connectionReset
  ipUnreacheable
  blockedDoS
  dhKeyTooSmall
  dhRSAmismatch
  other
)

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
                           uathbits int,
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

  // files, err = ioutil.ReadDir(dataDir)
  // check(err)
  // for _, f := range files {
  //   f, err := io.

  // }
}