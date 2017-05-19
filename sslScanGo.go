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
    // "fmt"
    "strings"
    "time"
    // "crypto/tls"
    "github.com/mmx1/openssl"
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


func (s sslCheckOptions) testProtocolCipher (cipherName string) {
  const request = "GET / HTTP/1.0\r\nUser-Agent: SSLScan\r\nHost: %s\r\n\r\n"

  //creates TLS context (SSL disabled by default)
  context, err := openssl.NewCtxWithVersion(0x05)
  if err != nil {
          log.Fatal(err)
  }

  err = context.SetCipherList ( cipherName )
  if err != nil {
    log.Fatal(err)
  }

  conn, err := openssl.Dial("tcp", s.host, context, 0)
  if err != nil {
    //inspect for weak dh key
    errorString := err.Error()
    if strings.Contains(errorString, "dh key too small") {
      log.Print("dh key too small")
    }
    return
    //fmt.Sprintf("%s rejected cipher %s", s.host, cipherName)
  }
  defer conn.Close()

  // C.SSL_connect(context)

  sslCipherName, err := conn.CurrentCipher()
  if err != nil {
    log.Fatal(err)
  }
  //fmt.Sprintf("%s accepted cipher %s", s.host, sslCipherName)
  println(sslCipherName)
  keyId, keyBits, curveName := conn.GetServerTmpKey()
  println(keyId, keyBits, curveName)

}

func (s sslCheckOptions) testProtocolCiphers (limiter  <-chan time.Time) {
  <-limiter
  s.testProtocolCipher(concatenateCiphers(rsaCiphers))
  s.testProtocolCipher(concatenateCiphers(ecdheCiphers))

  for _, cipher := range dhCiphers {
     <-limiter
     //fmt.Println("Tick at", time.Now())
     go s.testProtocolCipher(cipher)
  }

  for _, cipher := range dheCiphers {
     <-limiter
     //fmt.Println("Tick at", time.Now())
     go s.testProtocolCipher(cipher)
  }
}

func testHost() {
  // ctx, err := NewCtx()
  // if err != nil {
  //   log.Fatal(err)
  // }

  // conn, err := openssl.Dial("tcp", "www.google.com", ctx, 0)

}

func oldMain() {

  hostname := "expired.badssl.com:443"
  options := sslCheckOptions{ hostname, 443}

  limiter := time.Tick(time.Millisecond * 500)
  options.testProtocolCiphers(limiter)

}