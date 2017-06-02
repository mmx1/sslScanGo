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

func analyze(dbName string) {
  db, err := sql.Open("sqlite3", dbName)
  check(err)
  defer db.Close()

  printTableII(db)
  numDHEEnabled := printMainResult(db)
  printTableIII(db, numDHEEnabled)

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
  printWideTabletoFile(tableIFile, "Connection Refused Error", strconv.Itoa(connRefusedCnt))
  printWideTabletoFile(tableIFile, "SSL Errors", strconv.Itoa(sslErrCnt))
  printWideTabletoFile(tableIFile, "Timeout", strconv.Itoa(timeoutCnt))
  printWideTabletoFile(tableIFile, "Invalid Host Name", strconv.Itoa(invalidHostnameCnt))
  printWideTabletoFile(tableIFile, "Connection Reset Error", strconv.Itoa(connectionResetCnt))
  printWideTabletoFile(tableIFile, "IP unreachable", strconv.Itoa(ipUnreacheableCnt))
  printWideTabletoFile(tableIFile, "Blocked DOS", strconv.Itoa(blockDosCnt))
  printWideTabletoFile(tableIFile, "Other Errors", strconv.Itoa(otherCnt))
  tableIFile.Close()
}

func printTableIII(db *sql.DB, numDHEEnabled int) {
  //TABLE III CODE
  //Get Bit Sizes
  rows, err := db.Query("select distinct keyexbits from handshakes where keyexid = 28")
  check(err)
  var dheBitSizes []int 
  for rows.Next() {
    var dheBitSize int
    err = rows.Scan(&dheBitSize)
    check(err)
    dheBitSizes = append(dheBitSizes, dheBitSize)
  }
  rows.Close()
  sort.Ints(dheBitSizes)
  log.Println("Bit Sizes are: ", dheBitSizes)


  //count number of handshakes that use each bitsize
  m := make(map[int]int)
  for _, size := range dheBitSizes {
    statement := fmt.Sprintf("select count(distinct host) from handshakes where keyexid = 28 and keyexbits = %d", int(size))
    m[size] = singleIntQuery(statement, db)
  }

  // Number of domains that allowed <1024 bits for DHE key exchange  
  lowDHE := singleIntQuery("select count(errors) from hosts where errors & 128 = 128", db)
  
  //Create TableIII File and fill with data
  tableIIIFile, err := os.Create("TableIII.txt")
  check(err)
  printTableFileHeader(tableIIIFile, "Size(bits)", "Hosts")
  printTableFilePercentage(tableIIIFile, "<1024", lowDHE, numDHEEnabled)

  for _, bitSz := range dheBitSizes{
    printTableFilePercentage(tableIIIFile, strconv.Itoa(bitSz), m[bitSz], numDHEEnabled)
  }
  _, err = tableIIIFile.WriteString("\nTotal DHE Enabled Servers: "+strconv.Itoa(numDHEEnabled))
  tableIIIFile.Close()
}

func printTableII (db *sql.DB) {
   // TABLE II CODE
  var numEntries int
  err := db.QueryRow("select count(distinct host) from handshakes").Scan(&numEntries)
  check(err)
  
  //used to just get the list of Key Exchange messages (columns of a single row) 
  rows, err := db.Query("select * from hosts where id=1")
  columns, err := rows.Columns()
  check(err)
  rows.Close()

  log.Println("Columns are: ", columns)
  var count []int
  for i, v := range columns {
    if i >= 3 && i != len(columns)-1 {
        statement := fmt.Sprintf("select count(*) from hosts where %s= 1", v)
        val := singleIntQuery(statement, db)
        //log.Println("Total number of "+v+" :", val)
        count = append(count, val)
    }
  }
  log.Println(count)

  tableIIFile, err := os.Create("TableII.txt")
  check(err)
  
  printTableFileHeader(tableIIFile, "METHOD", "HOST")
  printTableFilePercentage(tableIIFile, "RSA", count[0], numEntries)
  printTableFilePercentage(tableIIFile, "DHE", count[1], numEntries)
  printTableFilePercentage(tableIIFile, "ECDHE", count[2], numEntries)

  err = tableIIFile.Close()
  check(err)
}

func printMainResult (db *sql.DB) (int) {

  numDHEQuery := "select count(distinct host) from handshakes where keyexid = 28"
  numDHEEnabled := singleIntQuery(numDHEQuery, db)
  log.Println("Total DHE enabled: ", numDHEEnabled)

  badDHEParamQuery := `select count(distinct host) 
                       from handshakes 
                       where keyexid = 28 AND authid = 6 AND keyexbits < authbits`
  numBadDHEParam := singleIntQuery(badDHEParamQuery, db)
  log.Println("Total number of bad DHE params: ", numBadDHEParam)

  //New Version of openssl does not accept connections with key size lower than 1024
  //Captured as error flag 1 << 7 or 128
  //Find all DHE requests that did not progress to a Handshake
  lowDHEQuery := "select count(errors) from hosts where errors & 128 = 128 and errors & 256 = 0"
  lowDHEUnreported := singleIntQuery(lowDHEQuery, db)
  //Include non-reported handshakes
  numBadDHEParam += lowDHEUnreported
  numDHEEnabled += lowDHEUnreported

  brFile, err := os.Create("BigResult.txt")
  check(err)

  _, err = brFile.WriteString("Number of DHE enabled servers are: " + strconv.Itoa(numDHEEnabled)+"\n")
  _, err = brFile.WriteString("Number of Weak DHE Parameters: "+strconv.Itoa(numBadDHEParam)+ "\n")
  badPercentage := float64(numBadDHEParam)/float64(numDHEEnabled) * 100
  _, err = brFile.WriteString("\nFor the Grand result of: "+strconv.FormatFloat(badPercentage, 'f', 1, 64)+"%")
  brFile.Close()

  return numDHEEnabled
}

func printWideTabletoFile(f *os.File, label string, data string) {
  statement := fmt.Sprintf("%-26s\t%s\n", label , data)
  _, err := f.WriteString(statement)
  check(err)
}

func printTableFilePercentage(f *os.File, label string, data int, total int) {
  per := float64(data)/float64(total)  * 100
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

func singleIntQuery(q string, db *sql.DB) (int) {
  var result int
  err := db.QueryRow(q).Scan(&result)
  check(err)
  return result
}

func queryNumError (db *sql.DB, bit int) int {
  statement := fmt.Sprintf("select count(id) from hosts where errors & %d = %d", bit, bit)
  return singleIntQuery(statement, db)
}



