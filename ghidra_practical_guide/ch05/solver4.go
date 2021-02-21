package main

import (
  "fmt"
  "math/rand"
  "crypto/sha256"
  "strconv"
)

func main() {
  rand.Seed(0x2e0ce0)
  hash := sha256.Sum256([]byte(strconv.Itoa(rand.Intn(0xe05def0d10))))
  fmt.Println(fmt.Sprintf("%x", hash))
}
