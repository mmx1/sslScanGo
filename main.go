package main 

import (
  "bufio"
  "flag"
  "fmt"
  "log"
  "os"
  "math/rand"
  "strconv"
  "strings"
  "sync"
  "sync/atomic"
  "time"
  "github.com/mmx1/opensslgo"
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
  randSelection := flag.Int("r", -1, "num Items to be randomly selected")
  rerun := flag.String("rerun", "", "file of indices to rerun")
  tlsVersionFlag := flag.String("tls", "all", "tls versions to run")

  var fileName = "top-1m.csv"
  flag.Parse()
  tail := flag.Args()
  
  if len(tail) < 1 {
    fmt.Println("No file specified, defaulting to top-1m.csv")
  }else{
    fileName = tail[0]
  }

  var tlsVersions []openssl.SSLVersion
  switch *tlsVersionFlag {
  case "tls11":
    tlsVersions = append(tlsVersions, openssl.TLSv1_1)
  case "tls12":
    tlsVersions = append(tlsVersions, openssl.TLSv1_2)
  default:
    tlsVersions = append(tlsVersions, openssl.TLSv1_2)
    tlsVersions = append(tlsVersions, openssl.TLSv1_1)
  }

  var selectedIndices map[int]bool
  if *randSelection > 0 {
    fmt.Println(*randSelection, "random selected, ignoring other parameters")
    selectedIndices = make(map[int]bool)
    rndGen := rand.New(rand.NewSource(time.Now().Unix()))

    for i := 0; i < *randSelection; i++ {
      index := int(rndGen.Float32() * 1000 + 1)
      fmt.Println("generated index", index)
      if !selectedIndices[index] {
        selectedIndices[index] = true
      }else{
        i-- //try again
      }
    }

  }else if *rerun != "" {
    fmt.Println("Rerunning indexes from", *rerun)
    selectedIndices = make(map[int]bool)

    f, err := os.Open(*rerun)
    check(err)
    defer f.Close()

    scanner := bufio.NewScanner(f)
    for scanner.Scan() {
      index, err := strconv.Atoi(scanner.Text())
      check(err)
      selectedIndices[index] = true
    }
  }
  var selectedTotal = len(selectedIndices)

  f, err := os.Open(fileName)
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
  var total int
  if selectedIndices == nil {
    total = *endPtr - *startPtr + 1
  }else{
    total = selectedTotal
  }

  scanner := bufio.NewScanner(f)
  for scanner.Scan() {
    tokens := strings.Split(scanner.Text(), ",")
    // fmt.Println(tokens)
    if len(tokens) < 2 {
      continue
    }

    lineNumber, err := strconv.Atoi(tokens[0])
    check(err)

    if selectedIndices == nil { //use start and end
      if lineNumber < *startPtr {
        continue
      }
      if lineNumber > *endPtr && *endPtr != 0 {
        break
      }
    }else{
      if !selectedIndices[lineNumber] {
        continue
      }else{
        selectedTotal--
      }
      // fmt.Println("Selected", lineNumber)
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
      options.scanHost(tlsVersions)
      options.hostTicker.Stop()
      //fmt.Println("main", host, options.result)
      options.print(strconv.Itoa(lineNumber))
    } (lineNumber, tokens[1])

    //early end if using map
    if selectedIndices == nil && selectedTotal == 0 {
      break;
    }

  }

  wg.Wait()
  globalLimiter.Stop()

  if err := scanner.Err(); err != nil {
    log.Fatal(err)
  }
}