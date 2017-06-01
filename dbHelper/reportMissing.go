package main

import (
  //"encoding/json"
  "database/sql"
  "fmt"
  _ "github.com/mattn/go-sqlite3"
  //"io/ioutil"
  "log"
  "os"

  "sync"
)

func check(e error) {
  if e != nil {
    log.Fatal(e)
  }
}

func checkGaps(db *sql.DB) {
  createTmpIds := `drop table if exists idseq;
                   create table idseq (id integer not null primary key)`
  _, err := db.Exec(createTmpIds)
  check(err)

  defer func () {
      dropTmpIds := `drop table idseq`
      _, err = db.Exec(dropTmpIds)
      check(err)
  }()

  dbLimit := make(chan int, 1)
  dbLimit <- 1

  var wg sync.WaitGroup

  for i := 0; i< 1000; i++ {
    <- dbLimit
    wg.Add(1)
    go func (i_inner int) {
      insertStmt := "insert into idseq values "
      for j := 1; j < 1000; j++ { 
        insertStmt += fmt.Sprintf("(%d), ", i_inner * 1000 + j)
      }
      insertStmt += fmt.Sprintf("(%d) ", i_inner * 1000 + 1000)

      _, err := db.Exec(insertStmt)
      check(err)

      dbLimit <- 1
      wg.Done()

    }(i)
  } 
  wg.Wait()


  selectMissingStmt := `select 
                            s.id 
                        from 
                            idseq s 
                            left join hosts t on 
                                s.id = t.id 
                         where t.id is null
                        `
  missingRows, err := db.Query(selectMissingStmt)
  check(err)

  missingRowsFile, err := os.Create("missingRows.txt")
  check(err)
  defer missingRowsFile.Close()


  for missingRows.Next() {
    var missingId string
    err = missingRows.Scan(&missingId)
    check(err)
    //fmt.Println(missingId)
    missingRowsFile.WriteString(missingId + "\n")
  }

}

func checkGaps(db *sql.DB) {
  
}

func main () {

  dbName := "scanDb.sqlite"
  db, err := sql.Open("sqlite3", dbName)
  check(err)
  defer db.Close()

  checkGaps(db)
  checkSSLErrorOnly(db)


}