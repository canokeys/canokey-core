package main

import (
	crand "crypto/rand"
	"encoding/hex"
	"fmt"
	"math/rand"
	"os"
	"time"

	"github.com/canopo/ykoath"
	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
)

func main() {

	someDay := int64(rand.Uint32())<<10 | int64(rand.Uint32())

	oath, err := ykoath.New()
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	// fix the clock
	oath.Clock = func() time.Time {
		return time.Unix(someDay, 0)
	}

	defer oath.Close()

	// enable OATH for this session
	_, err = oath.Select()
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	allKeys := make(map[string]*otp.Key)
	for i := 0; i < 10; i++ {
		name := fmt.Sprintf("name%060d", i)
		key := make([]byte, 64)
		_, err := crand.Read(key)
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}

		fmt.Printf("adding key %d %s %v\n", i, name, hex.EncodeToString(key))
		err = oath.Put(name, ykoath.HmacSha1, ykoath.Totp, 6, key, false)
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}

		opts := totp.GenerateOpts{
			Secret:      key,
			Issuer:      "Someone",
			AccountName: name,
		}
		allKeys[name], err = totp.Generate(opts)
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}

	}

	notUnique := make(map[string]bool)
	items, _ := oath.List()
	for _, item := range items {
		name := item.Name
		if _, ok := allKeys[name]; !ok {
			fmt.Printf("Name %s not found\n", name)
			os.Exit(1)
		}
		otp, err := oath.Calculate(name, nil)
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
		fmt.Printf("%s %s\n", otp, name)
		if notUnique[name] {
			fmt.Printf("List value not unique\n")
			os.Exit(1)
		} else {
			notUnique[name] = true
		}
		otpHost, err := totp.GenerateCode(allKeys[name].Secret(), oath.Clock())
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
		if otpHost != otp {
			fmt.Printf("%s != %s\n", otp, otpHost)
			os.Exit(1)
		}
	}

}
