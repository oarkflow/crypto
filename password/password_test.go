package password_test

import (
	"testing"

	"github.com/oarkflow/crypto/password"
)

func BenchmarkGenerate(b *testing.B) {
	b.Run("Default", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_, err := password.Generate()
			if err != nil {
				b.Fatal(err)
			}
		}
	})
}

func BenchmarkValidate(b *testing.B) {
	validPassword := "Valid123!"
	invalidPassword := "invalidpassword"

	b.Run("ValidPassword", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			err := password.Validate(validPassword)
			if err != nil {
				b.Fatal(err)
			}
		}
	})

	b.Run("InvalidPassword", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			err := password.Validate(invalidPassword)
			if err == nil {
				b.Fatal("expected validation error")
			}
		}
	})
}
