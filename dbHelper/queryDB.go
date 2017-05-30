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

func printWideTabletoFile(f *os.File, label string, data string) {
  statement := fmt.Sprintf("%-26s\t%s\n", label , data)
  _, err := f.WriteString(statement)
  check(err)
}

func printTableFilePercentage(f *os.File, label string, data int64, per float64) {
  statement := fmt.Sprintf("%-10s\t%d (%s%%)\n", label , data, strconv.FormatFloat(per, 'f', 2, 64))
  _, err := f.WriteString(statement)
  check(err)
}
func printTableFileHeader(f *os.File, label string, data string) {
  statement := fmt.Sprintf("%-10s\t%s\n", label , data)
  _, err := f.WriteString(statement)
  check(err)
  _, err = f.WriteString("-------------------\n")
  check(err)  
}

func queryNumError (db *sql.DB, bit int) int64 {
  statement := fmt.Sprintf("select count(id) from hosts where errors & %d = %d", bit, bit)
  rows, err := db.Query(statement)
  check(err)
  var result int64 
  rows.Next()
  err = rows.Scan(&result)
  check(err)
  rows.Close()
  return result
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
  
  //used to just get the list of Key Exchange messages (columns of a single row) 
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

  //New Version of openssl does not accept connections with key size lower than 1024
  //Captured as error flag 1 << 7 or 128
  //Find all DHE requests that did not progress to a Handshake
  rows, err = db.Query("select count(errors) from hosts where errors & 128 = 128 and errors & 256 = 0")
  check(err)
  var lowDHEUnreported int64 
  rows.Next()
  err = rows.Scan(&lowDHEUnreported)
  check(err)
  rows.Close()

  log.Println(count)
  tableIIFile, err := os.Create("TableII.txt")
  check(err)
  
  printTableFileHeader(tableIIFile, "METHOD", "HOST")
  percentage := float64(count[0])/float64(numEntries) * 100
  printTableFilePercentage(tableIIFile, "RSA", count[0], percentage)
  percentage = float64(count[1])/float64(numEntries) * 100
  printTableFilePercentage(tableIIFile, "DHE", count[1], percentage)
  percentage = float64(count[2])/float64(numEntries) * 100
  printTableFilePercentage(tableIIFile, "ECDHE", count[2], percentage)

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

  numBadDHEParam += lowDHEUnreported

  rows, err = db.Query("select count(distinct host) from handshakes where keyexid = 28")
  check(err)
  var numDHEEnabled int64 
  rows.Next()
  err = rows.Scan(&numDHEEnabled) //returns []string
  check(err)
  log.Println("Total number of rows: ", numDHEEnabled)
  rows.Close()

  //Include non-reported handshakes
  numDHEEnabled += lowDHEUnreported

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

  // Number of domains that allowed <1024 bits for DHE key exchange  
  rows, err = db.Query("select count(errors) from hosts where errors & 128 = 128")
  check(err)
  var lowDHE int64 
  rows.Next()
  err = rows.Scan(&lowDHE)
  check(err)
  rows.Close()
  
  //Create TableIII File and fill with data
  tableIIIFile, err := os.Create("TableIII.txt")
  check(err)
  printTableFileHeader(tableIIIFile, "Size(bits)", "Hosts")
  
  percentage = float64(lowDHE) / float64(numDHEEnabled) * 100
  printTableFilePercentage(tableIIIFile, "<1024", lowDHE, percentage)

  for _, bitSz := range dheBitSizes{
    percentage = float64(m[bitSz])/ float64(numDHEEnabled) * 100
    printTableFilePercentage(tableIIIFile, strconv.Itoa(bitSz), m[bitSz], percentage)
  }
  _, err = tableIIIFile.WriteString("\nTotal DHE Enabled Servers: "+strconv.FormatInt(numDHEEnabled,10))
  tableIIIFile.Close()

  //Table I : Errors
  connRefusedCnt := queryNumError(db, 1)
  sslErrCnt := queryNumError(db, 2)
  timeoutCnt := queryNumError(db, 4)
  invalidHostnameCnt := queryNumError(db, 8)
  connectionResetCnt := queryNumError(db, 16)
  ipUnreacheableCnt := queryNumError(db, 32)
  blockDosCnt := queryNumError(db, 64)
  otherCnt := queryNumError(db, 512)

  tableIFile, err := os.Create("TableI.txt")
  check(err)
  printWideTabletoFile(tableIFile, "Error", "Hosts")
  _, err = tableIFile.WriteString("-----------------------------------------\n")
  check(err)
  printWideTabletoFile(tableIFile, "Connection Refused Error", strconv.FormatInt(connRefusedCnt, 10))
  printWideTabletoFile(tableIFile, "SSL Errors", strconv.FormatInt(sslErrCnt, 10))
  printWideTabletoFile(tableIFile, "Timeout", strconv.FormatInt(timeoutCnt, 10))
  printWideTabletoFile(tableIFile, "Invalid Host Name", strconv.FormatInt(invalidHostnameCnt, 10))
  printWideTabletoFile(tableIFile, "Connection Reset Error", strconv.FormatInt(connectionResetCnt, 10))
  printWideTabletoFile(tableIFile, "IP unreachable", strconv.FormatInt(ipUnreacheableCnt, 10))
  printWideTabletoFile(tableIFile, "Blocked DOS", strconv.FormatInt(blockDosCnt, 10))
  printWideTabletoFile(tableIFile, "Other Errors", strconv.FormatInt(otherCnt, 10))
  tableIFile.Close()
}