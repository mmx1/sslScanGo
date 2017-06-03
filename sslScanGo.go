// +build cgo

package main

/*
#include <openssl/crypto.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/conf.h>
#include <openssl/evp.h>
*/
import "C"

import (
    "bufio"
    "errors"
    "fmt"
    "github.com/mmx1/opensslgo"
    "log"
    "net"
    "os"
    "time"
    "strconv"
    "strings"
    "sync"
    "sync/atomic"
)

var numProcesses = 300

type sslCheckOptions struct {
  host string
  port int
  hostTicker *time.Ticker
  globalTicker *time.Ticker
  result ScanResult
}

func check(e error) {
    if e != nil {
        log.Fatal(e)
    }
}

func scan(sourceFile string, start int, end int, scanIndices map[int]bool, tlsVersions []openssl.SSLVersion) {

  f, err := os.Open(sourceFile)
  check(err)
  defer f.Close()

  globalLimiter := time.NewTicker(time.Millisecond * 100)
  var wg sync.WaitGroup

  processes := make(chan int, numProcesses)
  for i := 0; i < numProcesses; i++ {
    processes <- 1
  }

  var done uint32 = 0
  var total int
  if len(scanIndices) == 0 {
    total = end - start + 1
  }else{
    total = len(scanIndices)
  }
  selectedTotal := len(scanIndices)

  scanner := bufio.NewScanner(f)
  for scanner.Scan() {
    tokens := strings.Split(scanner.Text(), ",")
    // fmt.Println(tokens)
    if len(tokens) < 2 {
      continue
    }

    lineNumber, err := strconv.Atoi(tokens[0])
    check(err)

    if scanIndices == nil { //use start and end
      if lineNumber < start {
        continue
      }
      if lineNumber > end && end != 0 {
        break
      }
    }else{
      if !scanIndices[lineNumber] {
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
    if scanIndices != nil && selectedTotal == 0 {
      break;
    }

  }

  wg.Wait()
  globalLimiter.Stop()

  if err := scanner.Err(); err != nil {
    log.Fatal(err)
  }
}

func (o *sslCheckOptions) scanHost(tlsVersions []openssl.SSLVersion) {
  o.hostTicker = time.NewTicker(time.Second)

  //initial TCP connection to 443 port
  o.rateLimit()
  conn, err := net.DialTimeout("tcp", o.host, time.Duration(30)*time.Second)
  if err != nil {
    //TODO : fine-grain error check
    log.Println("Error in connection start to host ", o.host, err)
    o.appendError(connectionRefused, err)
    if strings.HasPrefix(o.host, "www") {
      return
    }

    log.Println("Trying www prefix for host", o.host)
    o.host = "www." + o.host

    o.rateLimit()
    conn, err = net.DialTimeout("tcp", o.host, time.Duration(30)*time.Second)
    if err != nil {
      log.Println("Could not connect to host", o.host, err)
      o.appendError(connectionRefused, err)
      return
    }
  }
  conn.Close()

  for _, version := range tlsVersions {
    o.testProtocolCiphers(version)
  }
}

func (o sslCheckOptions) rateLimit () {
  <-o.hostTicker.C
  <-o.globalTicker.C
}

func (o *sslCheckOptions) testProtocolCipher (cipherName string, tlsVersion openssl.SSLVersion) (string){
  // fmt.Println("trying", s.host, cipherName)

  var handshake HandShakeResult

  //creates TLS context (SSL disabled by default)
  context, err := openssl.NewCtxWithVersion(tlsVersion)
  //check(err)
  if err != nil { //if tlsVersion is not locally supported, report and continue
    log.Println(err)
    return ""
  }

  err = context.SetCipherList ( cipherName )
  check(err)

  o.rateLimit()
  conn, err := openssl.DialTimeout("tcp", o.host, context, 0, time.Duration(30)*time.Second)

  if err != nil {
    //inspect for weak dh key
    errorString := err.Error()
    //log.Println(errorString)
    if strings.Contains(errorString, "dh key too small") {
      o.appendError(dhKeyTooSmall, err)
    }
    if strings.Contains(errorString, "connection timed out") {
      o.appendError(timeout, err)
    }
    o.appendError(sslError, err)
    return ""
  }
  defer conn.Close()

  handshake.Cipher, err = conn.CurrentCipher()
  check(err)
  // fmt.Printf("%s cipher: %s\n", o.host, handshake.Cipher)

  tmpKeyId, tmpKeyBits, tmpKeyCurveName := conn.GetServerTmpKey()
  handshake.KeyExchangeID = tmpKeyId
  handshake.KeyExchangeBits = tmpKeyBits
  handshake.KeyExchangeCurve = tmpKeyCurveName
  handshake.TLSVersion = tlsVersion
  

  // fmt.Printf("Tmp key: 0x%x, %d, %s\n",  tmpKeyId, tmpKeyBits, tmpKeyCurveName)
    switch tmpKeyId {
    case int(C.EVP_PKEY_DH):
      o.result.KeyExchangeMethods |= dhe
    case int(C.EVP_PKEY_EC):
      o.result.KeyExchangeMethods |= ecdhe
    }
  //todo: check for fixed DH

  cert, err := conn.PeerCertificate()
  check(err)
  pkey, err := cert.PublicKey()

  if pkey == nil { // no key found, must be anonymous
    o.result.AuthMethods ^= anonymous
    if tmpKeyId == 0 {
      noCipherError := errors.New("No Public Key or Server Tmp Key found")
      o.appendError(other, noCipherError)
    }

  }else{
    certKeyId, certKeyBits, certCurveName := openssl.GetPKeyParameters(pkey)
    // fmt.Printf("Cert 0x%x, %d, %s\n",  certKeyId, certKeyBits, certCurveName)
    switch certKeyId {
    case int(C.EVP_PKEY_RSA):
      o.result.AuthMethods |= rsaAuth
    case int(C.EVP_PKEY_DSA):
      o.result.AuthMethods |= dsa
    case int(C.EVP_PKEY_EC):
      o.result.AuthMethods |= ec
    }

    handshake.AuthKeyId = certKeyId
    handshake.AuthKeyBits = certKeyBits
    handshake.AuthKeyCurve = certCurveName

    if tmpKeyId == 0 {
      o.result.KeyExchangeMethods |= rsaKeyExch
      handshake.KeyExchangeID = certKeyId
      handshake.KeyExchangeBits = certKeyBits
      handshake.KeyExchangeCurve = certCurveName
    } else if handshake.KeyExchangeBits < handshake.AuthKeyBits && handshake.KeyExchangeCurve == "" {
      o.appendError(dhRSAmismatch, nil)
    }
  }

  o.result.Handshakes = append(o.result.Handshakes, handshake)
  return handshake.Cipher  
  
}

func (o *sslCheckOptions) testProtocolCiphers (tlsVersion openssl.SSLVersion) {  

  //loop over DHE ciphers, including anonymous
  cipherList := "ALL:COMPLEMENTOFALL"

  for true {
    //fmt.Print(dheCipher)
    cipher := o.testProtocolCipher(cipherList, tlsVersion)
    if cipher != "" {
      if strings.Contains(cipherList, cipher){
        log.Println("Mis-Configured server:", o.host)
        break
      }
      cipherList += ":!" + cipher
    }else{
      break
    }
  }

  return
}

func (o *sslCheckOptions) appendError (cE ConnectionError, e error) {
  //o.result.Error = append(o.result.Error, cE)
  //o.result.Comments += e.Error() + "\n"
  //inspect for weak dh key
  if e == nil {
    o.result.Error = append(o.result.Error, cE)
    return
  }
  errorString := e.Error()
  if strings.Contains(errorString, "no such host") {
    o.result.Error = append (o.result.Error, invalidHostname)
    o.result.Comments += e.Error() + "\n"
  } else if strings.Contains(errorString, "i/o timeout") {
    o.result.Error = append (o.result.Error, timeout)
    o.result.Comments += e.Error() + "\n"
  } else {
    o.result.Error = append(o.result.Error, cE)
    o.result.Comments += e.Error() + "\n"
  }
}