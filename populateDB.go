package main

import (
  "encoding/json"
  "database/sql"
  _ "github.com/mattn/go-sqlite3"
  "io/ioutil"
  "log"
  "os"
  "strings"
)

func populateDb (dataDir string, outputName string) {

  _, err := os.Stat(outputName)
  dbExists := err == nil

  db, err := sql.Open("sqlite3", outputName)
  check(err)
  defer db.Close()

  if !dbExists {

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
                             tlsVersion integer,
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

  }
  
  //todo, read 1m file and fill in name
  files, err := ioutil.ReadDir(dataDir)
  check(err)

  resultChan := make(chan ScanResult, 100)
  oldResultChan := make(chan ScanResultOld, 100)

  //kick off thread to fill resultChan and close when done
  go func () {
    log.Printf("Populate progress report may start from 1000000 due to skipped hidden metadata files")
    for i , f := range files {

      //resolve bug with macOS metadatafiles ".*"
      if strings.HasPrefix(f.Name(), ".") {
        continue
      }

      if i % 10000 == 0 {
        log.Println("Read ", i , dataDir + f.Name())
      }

      file, err := os.Open(dataDir +  f.Name())
      if err != nil {
        log.Printf("Error reading file %s: %s \n", f, err)
        continue
      }

      decoder := json.NewDecoder(file)
      decoderOld := json.NewDecoder(file)

      var oldResult ScanResultOld
      err = decoderOld.Decode(&oldResult)
      
      if err == nil {
        oldResultChan <- oldResult
      }else {
        var result ScanResult
        err = decoder.Decode(&result)
        if err == nil {
          resultChan <- result
        }else{
          log.Printf("Error reading json in file %s: %s \n", f, err)
        }
      }
      file.Close()
    }
    close(oldResultChan)
    close(resultChan)
  }()
    
  done := false
  for !done {

    tx, err := db.Begin()
    check(err) 
    insertHostStmt, err := tx.Prepare("insert into hosts (id, errors, keyExRSA, keyExDHE, keyExECDHE, authRSA, authAnon, authDSA, authEC, comments) VALUES( ?, ?, ?, ?, ?, ?, ?, ?, ?, ? )")
    check(err)
    defer insertHostStmt.Close()

    // insertHandshakeStmt, err := tx.Prepare("insert into handshakes (host, cipher, keyexid, keyexbits, keyexcurve, authid, authbits, authcurve ) VALUES ( ?, ?, ?, ?, ?, ?, ?, ?) ")
    insertHandshakeStmt, err := tx.Prepare("insert into handshakes (host, cipher, tlsVersion, keyexid, keyexbits, keyexcurve, authid, authbits, authcurve ) VALUES ( ?, ?, ?, ?, ?, ?, ?, ?, ?) ")
    check(err)
    defer insertHandshakeStmt.Close()


    //batch up to 10 results
    for i := 0 ; i < 10 ; i++ {
      select {
      case result, more := <- oldResultChan:
        done = !more
        if done {
          break;
        }

        errorMask := 0
        //make into a bitmask
        foundM := make (map[uint]bool)
        for _ , element := range result.Error {
          if !foundM[uint(element)]{
            errorMask += 1 << uint(element)
          }
          foundM[uint(element)]=true
        }
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
        check(err)

        for _, handshake := range result.Handshakes {
          _, err = insertHandshakeStmt.Exec ( result.Id,
                                              handshake.Cipher,
                                              handshake.Protocol,
                                              handshake.KeyExchangeID,
                                              handshake.KeyExchangeBits,
                                              handshake.KeyExchangeCurve,
                                              handshake.AuthKeyId,
                                              handshake.AuthKeyBits,
                                              handshake.AuthKeyCurve )
          check(err)
        }
      case result, more := <- resultChan:
        done = !more
        if done {
          break;
        }

        errorMask := 0
        //make into a bitmask
        foundM := make (map[uint]bool)
        for _ , element := range result.Error {
          if !foundM[uint(element)]{
            errorMask += 1 << uint(element)
          }
          foundM[uint(element)]=true
        }
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
        check(err)

        for _, handshake := range result.Handshakes {
          _, err = insertHandshakeStmt.Exec ( result.Id,
                                              handshake.Cipher,
                                              handshake.TLSVersion,
                                              handshake.KeyExchangeID,
                                              handshake.KeyExchangeBits,
                                              handshake.KeyExchangeCurve,
                                              handshake.AuthKeyId,
                                              handshake.AuthKeyBits,
                                              handshake.AuthKeyCurve )
          check(err)
        }
      default: //if none ready
        if i == 0 { //keep waiting if no insert yet
          i--
        }else{   //break and commit
          continue
        }
      }
    }
      
    err = tx.Commit()
    check(err)


  }

  log.Println("Finished the insert of all files: ", len(files))
}