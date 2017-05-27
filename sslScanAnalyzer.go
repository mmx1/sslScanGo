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
  "strconv"
  "runtime"
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
  createStatistics := `
  create table stats (id integer not null primary key,
                           totRowCount int,
                           totKeyExRSA int,
                           totKeyExDHE int,
                           totKeyExECDHE int,
                           totAuthRSA int,
                           totAuthAnon int,
                           totAuthDSA int,
                           totAuthEC int
                      )
  `
  _, err = db.Exec(createHosts)
  check(err)

  _, err = db.Exec(createHandshakes)
  check(err)
  _, err = db.Exec(createStatistics)
  check(err)

  log.Println(dataDir, outputName)

  //todo, read 1m file and fill in name



  files, err := ioutil.ReadDir(dataDir)
  check(err)
  
  done := make(chan int, len(files))
  var nW int
  if len(files) < 20 {
    nW = len(files)
  } else {
    nW = 20
  }
  worker := make (chan int, nW)
  for i := 0; i < 20; i ++ {
    worker <- 1
  } 
  for _, f := range files {
    if f.Name() == "." {
      log.Println("**** FOUND CURRENT DIR *****")
    }
    
    <-worker
    go func(f os.FileInfo){
      
      defer func(){
        worker <- 1
        done <- 1
      }()

      log.Println(dataDir + f.Name())
            
      file, err := os.Open(dataDir +  f.Name())
      if err != nil {
        log.Printf("Error reading file %s: %s \n", f, err)
        return
      }
      defer file.Close()

      decoder := json.NewDecoder(file)
      var result ScanResult
      err = decoder.Decode(&result)
      if err != nil {
        log.Printf("Error reading json in file %s: %s \n", f, err)
        return
      }

      // log.Printf(result)

      errorMask := 0
      //make into a bitmask
      for _ , element := range result.Error {
        errorMask += 1 << uint(element)
      }

      // For Concurrency Need A transaction for adding to the database
      tx, err := db.Begin()
      if err != nil {
        //log.Println("here begin1")
      }
      check(err) 
      insertHostStmt, err := tx.Prepare("insert into hosts (id, errors, keyExRSA, keyExDHE, keyExECDHE, authRSA, authAnon, authDSA, authEC, comments) VALUES( ?, ?, ?, ?, ?, ?, ?, ?, ?, ? )")
      counter := 0
      // GETTING A 'DATABASE IS LOCKED' ERROR 
      // THIS MEANS THAT "LIKELY" the thread holding the lock on the database was removed by the 
      // scheduler...
      for err != nil {
        if counter >= 1000 {
          break
        }
        runtime.Gosched()
        time.Sleep(100 * time.Millisecond)
        insertHostStmt, err = tx.Prepare("insert into hosts (id, errors, keyExRSA, keyExDHE, keyExECDHE, authRSA, authAnon, authDSA, authEC, comments) VALUES( ?, ?, ?, ?, ?, ?, ?, ?, ?, ? )")
        counter++
      }
      if err != nil {
        log.Println("here prep1")
      }
      check(err)

      
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
      // COMMITS THE TRANSACTION TO THE DATABASE (RELEASES THE DATABASE LOCK)
      // ALSO anything tied (state: i.e. insertHostStmt) to this transaction is deleted
      err = tx.Commit()
      counter = 0
      for err != nil {
        if counter >= 100 {
          //log.Println("here commit1")
          log.Fatal(err)
        }
        runtime.Gosched()
        err = tx.Commit()
        counter++
      }
      insertHostStmt.Close()
      tx, err = db.Begin()
      if err != nil {
        //log.Println("here begin2")
      }
      check(err)
      insertHandshakeStmt, err := tx.Prepare("insert into handshakes (host, cipher, keyexid, keyexbits, keyexcurve, authid, authbits, authcurve ) VALUES ( ?, ?, ?, ?, ?, ?, ?, ?) ")
      if err != nil {
        //log.Println("here prep2")
      }
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

      }
      err = tx.Commit()
      counter = 0
      for err != nil {
        if counter >= 100 {
          //log.Println("here commit2")
          log.Fatal(err)
        }
        runtime.Gosched()
        err = tx.Commit()
        counter++
      }
      //check(err)
      insertHandshakeStmt.Close()

    }(f)

  }
  for i := 0; i < len(files); i++ {
    <-done
  }

  // WE HAVE A CONCURRENCY PROBLEM: len(Files) != number of rows in the hosts directory 
  log.Println("Finished the insert of all files: ", len(files))

  // Run Statistics Table ???
  populateStatistics, err := db.Prepare("insert into stats (totRowCount, totKeyExRSA, totKeyExDHE, totKeyExECDHE , totAuthRSA, totAuthAnon, totAuthDSA, totAuthEC) VALUES ( ?, ?, ?, ?, ?, ?, ?, ?) ")
  check(err) 

  rows, err := db.Query("select count(*) from hosts")
  check(err)
  var totalRowCount int64 
  rows.Next()
  err = rows.Scan(&totalRowCount) //returns []string
  check(err)
  log.Println("Total number of rows: ", totalRowCount)
  rows.Close()
  
  //used to just get the column names 
  rows, err = db.Query("select * from hosts where id=1")

  statement := "select count(*) from hosts where "
  columns, err := rows.Columns()
  check(err)
  log.Println("Columns are: ", columns)
  var count []int64
  for i, v := range columns {
    if i >= 3 && i != len(columns)-1 {
        rows1, err := db.Query(statement + v + "= 1")
        check(err)
        var val int64 
        rows1.Next()
        err = rows1.Scan(&val) //returns []string
        check(err)
        //log.Println("Total number of "+v+" :", val)
        count = append(count, val)
        rows1.Close()
    }
  }
  log.Println(count)
  //HARD CODED ... MESSY
  _, err = populateStatistics.Exec(totalRowCount, count[0], count[1], count[2], count[3], count[4], count[5], count[6])
  check(err)
  tableIIFile, err := os.Create("TableII.txt")
  _, err = tableIIFile.WriteString("METHOD\t\tHOST\n")
  _, err = tableIIFile.WriteString("----------------------------\n")
  percentage := float64(count[0])/float64(totalRowCount) * 100
  _, err = tableIIFile.WriteString("RSA\t\t\t"+strconv.FormatInt(count[0],10)+" ("+strconv.FormatFloat(percentage, 'f', 1, 64)+"%)\n")
  percentage = float64(count[1])/float64(totalRowCount) * 100
  _, err = tableIIFile.WriteString("DHE\t\t\t"+strconv.FormatInt(count[1],10)+" ("+strconv.FormatFloat(percentage, 'f', 1, 64)+"%)\n")
  percentage = float64(count[2])/float64(totalRowCount) * 100
  _, err = tableIIFile.WriteString("ECDHE\t\t"+strconv.FormatInt(count[2],10)+" ("+strconv.FormatFloat(percentage, 'f', 1, 64)+"%)\n")
}