package main

import (
	"fmt"

	"github.com/oarkflow/crypto/password"
)

func main() {
	pwd, err := password.Generate()
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}
	fmt.Printf("Generated Password: %s\n", pwd)
	fmt.Printf("Validated Password: %v\n", password.Validate(pwd))
}
