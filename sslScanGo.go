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
    "errors"
    "fmt"
    "strings"
    "time"
    "net" 
    "github.com/mmx1/opensslgo"
)

type sslCheckOptions struct {
  host string
  port int
  hostTicker *time.Ticker
  globalTicker *time.Ticker
  result ScanResult
}

func (o sslCheckOptions) rateLimit () {
  <-o.hostTicker.C
  <-o.globalTicker.C
}

func (o *sslCheckOptions) testProtocolCipher (cipherName string) (string, error) {
  // fmt.Println("trying", s.host, cipherName)

  var handshake HandShakeResult

  const request = "GET / HTTP/1.0\r\nUser-Agent: SSLScan\r\nHost: %s\r\n\r\n"

  //creates TLS context (SSL disabled by default)
  context, err := openssl.NewCtxWithVersion(openssl.TLSv1_2)
  check(err)

  err = context.SetCipherList ( cipherName )
  check(err)

  o.rateLimit()
  conn, err := net.DialTimeout("tcp", o.host, time.Duration(30)*time.Second)
  if err != nil {
    o.appendError(blockedDoS, err)
    return "", err
  }

  conn_ssl, err := openssl.Client(conn, context)
  check(err)
  err = conn_ssl.Handshake()  

  if err != nil {
    //inspect for weak dh key
    errorString := err.Error()
    //log.Println(errorString)
    if strings.Contains(errorString, "dh key too small") {
      o.appendError(dhKeyTooSmall, err)
    }
    if strings.Contains(errorString, "no such host") {
      o.appendError(invalidHostname, err)
      return "", err
    }
    if strings.Contains(errorString, "connection timed out") {
      o.appendError(timeout, err)
      return "", err
    }
    return "", nil
  }
  defer conn_ssl.Close()

  handshake.Cipher, err = conn_ssl.CurrentCipher()
  check(err)
  fmt.Printf("%s cipher: %s\n", o.host, handshake.Cipher)

  tmpKeyId, tmpKeyBits, tmpKeyCurveName := conn_ssl.GetServerTmpKey()
  handshake.KeyExchangeID = tmpKeyId
  handshake.KeyExchangeBits = tmpKeyBits
  handshake.KeyExchangeCurve = tmpKeyCurveName

  fmt.Printf("Tmp key: 0x%x, %d, %s\n",  tmpKeyId, tmpKeyBits, tmpKeyCurveName)
    switch tmpKeyId {
    case int(C.EVP_PKEY_DH):
      o.result.KeyExchangeMethods ^= dhe
    case int(C.EVP_PKEY_EC):
      o.result.KeyExchangeMethods ^= ecdhe
    }
  //todo: check for fixed DH

  cert, err := conn_ssl.PeerCertificate()
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
    fmt.Printf("Cert 0x%x, %d, %s\n",  certKeyId, certKeyBits, certCurveName)
    switch certKeyId {
    case int(C.EVP_PKEY_RSA):
      o.result.AuthMethods ^= rsaAuth
    case int(C.EVP_PKEY_DSA):
      o.result.AuthMethods ^= dsa
    case int(C.EVP_PKEY_EC):
      o.result.AuthMethods ^= ec
    }

    handshake.AuthKeyId = certKeyId
    handshake.AuthKeyBits = certKeyBits
    handshake.AuthKeyCurve = certCurveName

    if tmpKeyId == 0 {
      o.result.KeyExchangeMethods ^= rsaKeyExch
      handshake.KeyExchangeID = tmpKeyId
      handshake.KeyExchangeBits = tmpKeyBits
      handshake.KeyExchangeCurve = tmpKeyCurveName

    }
  }

  o.result.Handshakes = append(o.result.Handshakes, handshake)
  return handshake.Cipher, nil

  //FIX: PKeySize assumes RSA authentication
  // pkeySize = openssl.PKeySize(pkey) * 8

  // //fmt.Println("Encryption Key Size (bits): ", key_size*8)

  // //fmt.Sprintf("%s accepted cipher %s", s.host, sslCipherName)
  
  // keyId, keyBits, curveName := conn_ssl.GetServerTmpKey()
  // switch  {
  // case keyId & 0x01 != 0 : //EVP_PK_RSA

  // //case 0x02 : //EVP_PK:DSA
  // case keyId & 0x04 != 0: 
  // }

  // handshake.KeyExchangeID = keyId
  // handshake.KeyExchangeBits = keyBits
  // handshake.EcdheCurve = curveName
  
  
}

func (o *sslCheckOptions) testProtocolCiphers () {  

  //"RSA is an alias for kRSA" per 1.1.0 doc 
  //(wrongly described in 1.0.2 doc as RSA for either key exchange
  //or authentication)
  // cipher, err := o.testProtocolCipher("kRSA")
  // if err != nil {
  //   fmt.Println("Early fail on host ", o.host)
  //   return
  // }
  // if cipher != "" {
  //   o.result.KeyExchangeMethods = append(o.result.KeyExchangeMethods, rsaKeyExch)
  // }

  //check for ECDHE key exchange support, deliberately eliminating anonmyous (kECDHE)
  // cipher, err = o.testProtocolCipher("ECDHE")
  // if err != nil {
  //   fmt.Println("Early fail on host ", o.host)
  //   return
  // }
  // if cipher != ""  {
  //   o.result.KeyExchangeMethods = append(o.result.KeyExchangeMethods, ecdhe)
  // }



  //check for anonymous ECDH
  // cipher, err = o.testProtocolCipher("aECDH")
  // if err != nil {
  //   fmt.Println("Early fail on host ", o.host)
  //   return
  // }
  // if cipher != ""  {
  //   o.result.KeyExchangeMethods = append(o.result.KeyExchangeMethods, anonECDHE)
  // }

  //check for fixed ECDH
  // cipher, err = o.testProtocolCipher("kECDH")
  // if err != nil {
  //   fmt.Println("Early fail on host ", o.host)
  //   return
  // }
  // if cipher != "" {
  //   o.result.KeyExchangeMethods = append(o.result.KeyExchangeMethods, fixedECDH)
  // }

  //loop over DHE ciphers, including anonymous
  dheCipher := "ALL:COMPLEMENTOFALL"

  for true {
    //fmt.Print(dheCipher)
    cipher, _ := o.testProtocolCipher(dheCipher)
    if cipher != "" {
      dheCipher += ":!" + cipher
    }else{
      break;
    }
  }

  fmt.Println(o.host, "Done")

  return
}

func (o *sslCheckOptions) appendError (cE ConnectionError, e error) {
  o.result.Error = append(o.result.Error, cE)
  o.result.Comments += e.Error() + "\n"
}

func (o *sslCheckOptions) scanHost() {
  o.hostTicker = time.NewTicker(time.Second)

  //initial TCP connection to 443 port
  o.rateLimit()
  conn, err := net.DialTimeout("tcp", o.host, time.Duration(30)*time.Second)
  if err != nil {
    //TODO : fine-grain error check
    log.Print("Error in connection start to host", o.host, err)
    o.appendError(connectionRefused, err)
    if strings.HasPrefix(o.host, "www") {
      return
    }

    log.Print("Trying www prefix for host", o.host)
    o.host = "www." + o.host

    o.rateLimit()
    conn, err = net.DialTimeout("tcp", o.host, time.Duration(30)*time.Second)
    if err != nil {
      log.Print("Could not connect to host", o.host, err)
      o.appendError(connectionRefused, err)
      return
    }
  }
  conn.Close()

  o.testProtocolCiphers()
}