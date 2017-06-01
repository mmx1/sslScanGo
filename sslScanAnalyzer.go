package main

import (
  "encoding/json"
  "database/sql"
  //"fmt"
  _ "github.com/mattn/go-sqlite3"
  "io/ioutil"
  "log"
  "os"
  "time"
  //"strconv"
  //"runtime"
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
  
  log.Println(dataDir, outputName)

  //todo, read 1m file and fill in name



  files, err := ioutil.ReadDir(dataDir)
  check(err)
  // done := make(chan int, len(files))
  // var nW int
  // if len(files) < 20 {
  //   nW = len(files)
  // } else {
  //   nW = 20
  // }
  // worker := make (chan int, nW)
  // dbLock := make(chan int, 1)
  // dbLock <- 1
  // for i := 0; i < nW; i ++ {
  //   worker <- 1
  // } 

  resultChan := make(chan ScanResult, 100)

  //kick off thread to fill resultChan and close when done
  go func () {
    for i , f := range files {
      if f.Name() == "." {
        log.Println("**** FOUND CURRENT DIR *****")
      }

      if i % 10000 == 0 {
        log.Println("Read ", i , dataDir + f.Name())
      }

      file, err := os.Open(dataDir +  f.Name())
      if err != nil {
        log.Printf("Error reading file %s: %s \n", f, err)
        continue
      }
      //defer file.Close()

      decoder := json.NewDecoder(file)
      var result ScanResult
      err = decoder.Decode(&result)
      file.Close()
      if err != nil {
        log.Printf("Error reading json in file %s: %s \n", f, err)
        continue
      }

      resultChan <- result
    }
    close(resultChan)
  }()
    
  done := false
  for !done {

    tx, err := db.Begin()
    check(err) 
    insertHostStmt, err := tx.Prepare("insert into hosts (id, errors, keyExRSA, keyExDHE, keyExECDHE, authRSA, authAnon, authDSA, authEC, comments) VALUES( ?, ?, ?, ?, ?, ?, ?, ?, ?, ? )")
    check(err)
    defer insertHostStmt.Close()

    insertHandshakeStmt, err := tx.Prepare("insert into handshakes (host, cipher, keyexid, keyexbits, keyexcurve, authid, authbits, authcurve ) VALUES ( ?, ?, ?, ?, ?, ?, ?, ?) ")
    check(err)
    defer insertHandshakeStmt.Close()


    //batch up to 10 results
    for i := 0 ; i < 10 ; i++ {
      select {
      case result, more := <- resultChan:
        done = !more

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

      
      
            
      

      



      // log.Printf(result)

      

      // For Concurrency Need A transaction for adding to the database
      //<-dbLock
      
      //counter := 0
      // GETTING A 'DATABASE IS LOCKED' ERROR 
      // THIS MEANS THAT "LIKELY" the thread holding the lock on the database was removed by the 
      // scheduler...
      // for err != nil {
      //   if counter >= 1000 {
      //     break
      //   }
      //   runtime.Gosched()
      //   time.Sleep(100 * time.Millisecond)
      //   insertHostStmt, err = tx.Prepare("insert into hosts (id, errors, keyExRSA, keyExDHE, keyExECDHE, authRSA, authAnon, authDSA, authEC, comments) VALUES( ?, ?, ?, ?, ?, ?, ?, ?, ?, ? )")
      //   counter++
      // }

      //check(err)

      
      //todo, export constants from serialze.go?
      
      // COMMITS THE TRANSACTION TO THE DATABASE (RELEASES THE DATABASE LOCK)
      // ALSO anything tied (state: i.e. insertHostStmt) to this transaction is deleted
      // err = tx.Commit()
      // counter = 0
      // for err != nil {
      //   if counter >= 100 {
      //     //log.Println("here commit1")
      //     log.Fatal(err)
      //   }
      //   runtime.Gosched()
      //   err = tx.Commit()
      //   counter++
      // }
      // insertHostStmt.Close()
      // tx, err = db.Begin()
      // if err != nil {
      //   //log.Println("here begin2")
      // }
      // check(err)

  //}
  // for i := 0; i < len(files); i++ {
  //   <-done
  // }
  log.Println("Finished the insert of all files: ", len(files))
}