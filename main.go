package main 

import (
  "bufio"
  "flag"
  "fmt"
  "log"
  "os"
  "strconv"
  "strings"
  "sync"
  "sync/atomic"
  "time"
)

var numProcesses = 300

func check(e error) {
    if e != nil {
        log.Fatal(e)
    }
}

func main() {

  startPtr := flag.Int("start", 1, "start index")
  endPtr := flag.Int("end", 0, "end index")

  flag.Parse()
  tail := flag.Args()
  
  if len(tail) < 1 {
    fmt.Println("Error, requires an filename argument")
    return
  }

  f, err := os.Open(tail[0])
  check(err)
  defer f.Close()

  globalLimiter := time.NewTicker(time.Millisecond * 100)
  //messages := make(chan int)
  var wg sync.WaitGroup


  processes := make(chan int, numProcesses)
  for i := 0; i < numProcesses; i++ {
    processes <- 1
  }

  var done uint32 = 0
  var total = *endPtr - *startPtr + 1

  scanner := bufio.NewScanner(f)
  for scanner.Scan() {
    tokens := strings.Split(scanner.Text(), ",")
    // fmt.Println(tokens)
    if len(tokens) < 2 {
      continue
    }

    lineNumber, err := strconv.Atoi(tokens[0])
    check(err)
    // fmt.Println(lineNumber)
    if lineNumber < *startPtr {
      continue
    }
    if lineNumber > *endPtr && *endPtr != 0 {
      break
    }

    <- processes
    wg.Add(1)
    go func(lineNumber int, host string) {
      
      defer func () {
        processes <- 1
        wg.Done()
        v := atomic.AddUint32(&done, 1)
        fmt.Printf("Done with host %s, %d of %d \n", host, v, total )
      } ()
      options := sslCheckOptions{ host: host + ":443", 
                                  port: 443,
                                  result: ScanResult{Id:lineNumber,
                                                     Timestamp: time.Now() } ,
                                  hostTicker: time.NewTicker(time.Second),
                                  globalTicker: globalLimiter,
                                }
      options.scanHost()
      options.hostTicker.Stop()
      //fmt.Println("main", host, options.result)
      options.print(strconv.Itoa(lineNumber))
    } (lineNumber, tokens[1])

  }

  wg.Wait()
  globalLimiter.Stop()

  if err := scanner.Err(); err != nil {
    log.Fatal(err)
  }
}