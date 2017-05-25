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
    "log"
    "fmt"
    "strings"
    "sync"
    "time"
    "net" 
    // "crypto/tls"
    "github.com/mmx1/opensslgo"
    // "github.com/davecgh/go-spew/spew"
)

var rsaCiphers = []string{"AES128-SHA256",
                          "AES256-SHA256",
                          "AES128-GCM-SHA256",
                          "AES256-GCM-SHA384"}

var dhCiphers = []string{"DH-RSA-AES128-SHA256", 
                           "DH-RSA-AES256-SHA256",
                           "DH-RSA-AES128-GCM-SHA256",
                           "DH-RSA-AES256-GCM-SHA384"}

var anonDHCiphers = []string{"ADH-AES128-SHA256",
                             "ADH-AES256-SHA256",
                             "ADH-AES128-GCM-SHA256",
                             "ADH-AES256-GCM-SHA384"}

var anonECDHCiphers = []string{"AECDH-NULL-SHA",
                             "AECDH-RC4-SHA",
                             "AECDH-DES-CBC3-SHA",
                             "AECDH-AES128-SHA",
                             "AECDH-AES256-SHA"}
var dheCiphers = []string{

                           "DHE-RSA-AES128-SHA256",
                           "DHE-RSA-AES256-SHA256",
                           "DHE-RSA-AES128-GCM-SHA256",
                           "DHE-RSA-AES256-GCM-SHA384",

                           "DHE-DSS-AES128-SHA256",
                           "DHE-DSS-AES256-SHA256",
                           "DHE-DSS-AES128-GCM-SHA256",
                           "DHE-DSS-AES256-GCM-SHA384"}

var ecdheCiphers = []string{"ECDHE-RSA-AES128-SHA256",
                             "ECDHE-RSA-AES256-SHA384",
                             "ECDHE-RSA-AES128-GCM-SHA256",
                             "ECDHE-RSA-AES256-GCM-SHA384",

                             "ECDHE-ECDSA-AES128-SHA256",
                             "ECDHE-ECDSA-AES256-SHA384",
                             "ECDHE-ECDSA-AES128-GCM-SHA256",
                             "ECDHE-ECDSA-AES256-GCM-SHA384",

                            "ECDHE-RSA-NULL-SHA",
                            "ECDHE-RSA-RC4-SHA",
                            "ECDHE-RSA-DES-CBC3-SHA",
                            "ECDHE-RSA-AES128-SHA",
                            "ECDHE-RSA-AES256-SHA",

                            "ECDHE-ECDSA-NULL-SHA",
                            "ECDHE-ECDSA-RC4-SHA",
                            "ECDHE-ECDSA-DES-CBC3-SHA",
                            "ECDHE-ECDSA-AES128-SHA",
                            "ECDHE-ECDSA-AES256-SHA"}

var fixedECDHCiphers = []string{"ECDH-RSA-NULL-SHA",
                                "ECDH-RSA-RC4-SHA",
                                "ECDH-RSA-DES-CBC3-SHA",
                                "ECDH-RSA-AES128-SHA",
                                "ECDH-RSA-AES256-SHA",

                                "ECDH-ECDSA-NULL-SHA",
                                "ECDH-ECDSA-RC4-SHA",
                                "ECDH-ECDSA-DES-CBC3-SHA",
                                "ECDH-ECDSA-AES128-SHA",
                                "ECDH-ECDSA-AES256-SHA"}

func concatenateCiphers (ciphers []string) (string) {
  var joinedCiphers string
  for index, cipher := range ciphers {
    if index != 0 {
      joinedCiphers += ":"
    }
    joinedCiphers += cipher
  }
  return joinedCiphers
}

  type sslCheckOptions struct {
  host string
  port int
}

func testConnection() {

}


func (s sslCheckOptions) testProtocolCipher (cipherName string) (int){
  // fmt.Println("trying", s.host, cipherName)

  const request = "GET / HTTP/1.0\r\nUser-Agent: SSLScan\r\nHost: %s\r\n\r\n"

  //creates TLS context (SSL disabled by default)
  context, err := openssl.NewCtxWithVersion(openssl.TLSv1_2)
  if err != nil {
          log.Fatal(err)
  }

  err = context.SetCipherList ( cipherName )
  if err != nil {
    log.Fatal(err)
  }

  conn, err:=s.testHost()
  if err != nil {
    log.Print("Lost connection to Host: ", err)
    return -1
  }

  conn_ssl, err := openssl.Client(conn, context)
  check(err)
  err = conn_ssl.Handshake()  
  //var dialer net.Dialer
  //dialer.Timeout = time.Duration(30)*time.Second

  //conn, err := openssl.Dial("tcp", s.host, context, 0)
  if err != nil {
    //inspect for weak dh key
    errorString := err.Error()
    //log.Println(errorString)
    if strings.Contains(errorString, "dh key too small") {
      log.Print("dh key too small")
    }
    if strings.Contains(errorString, "no such host") {
      log.Print("No such Host")
      return -1
    }
    if strings.Contains(errorString, "connection timed out") {
      log.Print("Connection Timed Out")
      return -1
    }
    return 0
    //fmt.Sprintf("%s rejected cipher %s", s.host, cipherName)
  }
  defer conn_ssl  .Close()

  sslCipherName, err := conn_ssl.CurrentCipher()
  if err != nil {
    log.Fatal(err)
  }

  cert, err := conn_ssl.PeerCertificate()
  if err != nil {
    log.Fatal(err)
  }
  pkey, err := cert.PublicKey()
  if err != nil {
    log.Fatal(err)
  }

  key_size := openssl.PKeySize(pkey)
  fmt.Println("Encryption Key Size (bits): ", key_size*8)


  //fmt.Sprintf("%s accepted cipher %s", s.host, sslCipherName)
  keyId, keyBits, curveName := conn_ssl.GetServerTmpKey()
  fmt.Println(s.host, sslCipherName, keyId, keyBits, curveName)
  return 0
}

func (s sslCheckOptions) testProtocolCiphers (globalLimiter  <-chan time.Time) {

  var wg sync.WaitGroup
  hostLimiter := time.Tick(time.Second)
  result_ch := make(chan int)

  wg.Add(1)
  go func () {
      defer wg.Done()
      <-hostLimiter
      <-globalLimiter
      result_ch <- s.testProtocolCipher(concatenateCiphers(rsaCiphers))
  }()
  if(<-result_ch < 0){
    fmt.Println(s.host, "Done")
    return
  }
  wg.Add(1)
  go func () {
    defer wg.Done()
    <-hostLimiter
    <-globalLimiter
    result_ch <- s.testProtocolCipher(concatenateCiphers(ecdheCiphers))
  }()
  if(<-result_ch < 0){
    fmt.Println(s.host, "Done")
    return
  }

  for _, cipher := range dhCiphers {
    wg.Add(1)
    go func () {
      defer wg.Done()
      <-hostLimiter
      <-globalLimiter
      result_ch <- s.testProtocolCipher(cipher)
    }()
    if(<-result_ch < 0){
     fmt.Println(s.host, "Done")
     return
    }
  }

  for _, cipher := range dheCiphers {
     wg.Add(1)
    go func () {
      defer wg.Done()
      <-hostLimiter
      <-globalLimiter
      result_ch <- s.testProtocolCipher(cipher)
    }()
    if(<-result_ch < 0){
      fmt.Println(s.host, "Done")
      return
    }
  }

  wg.Wait()
  fmt.Println(s.host, "Done")
}


func (o sslCheckOptions) testHost() (net.Conn, error) {
  conn, err := net.DialTimeout("tcp", o.host, time.Duration(30)*time.Second)
  if err != nil {
    return nil, err
  }
  return conn, nil
}

func scanHost(hostName string, globalLimiter <-chan time.Time) {
  log.Println("scanHost" , hostName)

  options := sslCheckOptions{ hostName, 443}
  conn, err:=options.testHost();
  if err != nil {
    log.Print("Error in connection Start ", err)
    return
  }
  conn.Close()
  options.testProtocolCiphers(globalLimiter)

}