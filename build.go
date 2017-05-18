package main

// #cgo pkg-config: libssl libcrypto
// #cgo windows CFLAGS: -DWIN32_LEAN_AND_MEAN
// #cgo darwin CFLAGS: -Wno-deprecated-declarations -I/usr/local/opt/openssl/include
// #cgo darwin LDFLAGS: -L/usr/local/opt/openssl/lib
import "C"