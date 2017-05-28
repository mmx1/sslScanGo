package main

import (
  //"encoding/json"
  "database/sql"
  "fmt"
  _ "github.com/mattn/go-sqlite3"
  //"io/ioutil"
  "log"
  "os"
  //"time"
  "strconv"
  "sort"
)

func check(e error) {
  if e != nil {
    log.Fatal(e)
  }
}

func main () {

  dbName := "scanDb.sqlite"

  db, err := sql.Open("sqlite3", dbName)
  check(err)

  defer db.Close()

  // TABLE II CODE
  rows, err := db.Query("select count(*) from hosts")
  check(err)
  var numEntries int64 
  rows.Next()
  err = rows.Scan(&numEntries) //returns []string
  check(err)
  log.Println("Total number of rows: ", numEntries)
  rows.Close()
  
  //used to just get the column names 
  rows, err = db.Query("select * from hosts where id=1")

  //statement := "select count(*) from hosts where "
  columns, err := rows.Columns()
  check(err)
  rows.Close()

  log.Println("Columns are: ", columns)
  var count []int64
  for i, v := range columns {
    if i >= 3 && i != len(columns)-1 {
        statement := fmt.Sprintf("select count(*) from hosts where %s= 1", v)
        rows1, err := db.Query(statement)
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
  tableIIFile, err := os.Create("TableII.txt")
  check(err)
  _, err = tableIIFile.WriteString("METHOD\t\tHOST\n")
  _, err = tableIIFile.WriteString("----------------------------\n")
  percentage := float64(count[0])/float64(numEntries) * 100
  _, err = tableIIFile.WriteString("RSA\t\t\t"+strconv.FormatInt(count[0],10)+" ("+strconv.FormatFloat(percentage, 'f', 1, 64)+"%)\n")
  percentage = float64(count[1])/float64(numEntries) * 100
  _, err = tableIIFile.WriteString("DHE\t\t\t"+strconv.FormatInt(count[1],10)+" ("+strconv.FormatFloat(percentage, 'f', 1, 64)+"%)\n")
  percentage = float64(count[2])/float64(numEntries) * 100
  _, err = tableIIFile.WriteString("ECDHE\t\t"+strconv.FormatInt(count[2],10)+" ("+strconv.FormatFloat(percentage, 'f', 1, 64)+"%)\n")
  _, err = tableIIFile.WriteString("\n\nTotal Entries: "+strconv.FormatInt(numEntries,10))
  err = tableIIFile.Close()
  check(err)

  //Main Result
  rows, err = db.Query("select count(distinct host) from handshakes where keyexid = 28 AND authid = 6 AND keyexbits < authbits")
  check(err)
  var numBadDHEParam int64 
  rows.Next()
  err = rows.Scan(&numBadDHEParam) //returns []string
  check(err)
  log.Println("Total number of rows: ", numBadDHEParam)
  rows.Close()


  rows, err = db.Query("select count(distinct host) from handshakes where keyexid = 28")
  check(err)
  var numDHEEnabled int64 
  rows.Next()
  err = rows.Scan(&numDHEEnabled) //returns []string
  check(err)
  log.Println("Total number of rows: ", numDHEEnabled)
  rows.Close()

  brFile, err := os.Create("BigResult.txt")
  check(err)

  _, err = brFile.WriteString("Number of DHE enabled servers are: " + strconv.FormatInt(numDHEEnabled,10)+"\n")
  _, err = brFile.WriteString("Number of Weak DHE Parameters: "+strconv.FormatInt(numBadDHEParam,10)+ "\n")
  badPercentage := float64(numBadDHEParam)/float64(numDHEEnabled) * 100
  _, err = brFile.WriteString("\nFor the Grand result of: "+strconv.FormatFloat(badPercentage, 'f', 1, 64)+"%")
  brFile.Close()

  //TABLE III CODE
  
  //Get Bit Sizes
  rows, err = db.Query("select distinct keyexbits from handshakes where keyexid = 28")
  check(err)
  var dheBitSizes []int 
  for rows.Next() {
    var dheBitSize int64
    err = rows.Scan(&dheBitSize)
    check(err)
    dheBitSizes = append(dheBitSizes, int(dheBitSize))
  }
  sort.Ints(dheBitSizes)
  log.Println("Bit Sizes are: ", dheBitSizes)
  rows.Close()

  //count number of handshakes that use each bitsize
  m := make(map[int]int64)
  var num int64
  for _, size := range dheBitSizes {
    statement := fmt.Sprintf("select count(distinct host) from handshakes where keyexid = 28 and keyexbits = %d", int(size))
    rows, err = db.Query(statement) //returns single row
    rows.Next() //need to read row
    err = rows.Scan(&num)
    check(err)
    m[size] = num
    rows.Close()
  }
  
  tableIIIFile, err := os.Create("TableIII.txt")
  check(err)
  _, err = tableIIIFile.WriteString("Size(bits)\t\tHosts\n")
  _, err = tableIIIFile.WriteString("----------------------------\n")
  //Print Results
  for _, bitSz := range dheBitSizes{
    percentage = float64(m[bitSz])/ float64(numDHEEnabled) * 100
    _, err = tableIIIFile.WriteString(strconv.Itoa(bitSz)+"\t\t\t\t"+strconv.FormatInt(m[bitSz],10)+" ("+strconv.FormatFloat(percentage, 'f', 2, 64)+"%)\n")
  }
  _, err = tableIIIFile.WriteString("\n\nTotal DHE Enabled Servers: "+strconv.FormatInt(numDHEEnabled,10))
  tableIIIFile.Close()  
}