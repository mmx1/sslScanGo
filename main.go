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
  "time"
)

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

  globalLimiter := time.Tick(time.Millisecond * 100)
  //messages := make(chan int)
  var wg sync.WaitGroup

  scanner := bufio.NewScanner(f)
  for scanner.Scan() {
    tokens := strings.Split(scanner.Text(), ",")
    //fmt.Println(tokens)
    if len(tokens) < 2 {
      continue
    }

    lineNumber, err := strconv.Atoi(tokens[0])
    check(err)
    // fmt.Println(lineNumber)
    if lineNumber < *startPtr {
      continue
    }
    if lineNumber > *endPtr  {
      break
    }

    host := tokens[1] + ":443"
    
    wg.Add(1)
    go func() {
      defer wg.Done()
      scanHost(host, globalLimiter)
    } ()

  }

  wg.Wait()

  if err := scanner.Err(); err != nil {
    log.Fatal(err)
  }
}