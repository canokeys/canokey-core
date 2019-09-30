package main

import (
	crand "crypto/rand"
	"fmt"
	"math/rand"
	"strings"
	"testing"
	"time"

	"github.com/canopo/ykoath"
	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
	. "github.com/smartystreets/goconvey/convey"
)

func chooseAlgorithm() (alg1 ykoath.Algorithm, alg2 otp.Algorithm) {
	if rand.Int()%2 == 0 {
		alg1 = ykoath.HmacSha1
		alg2 = otp.AlgorithmSHA1
	} else {
		alg1 = ykoath.HmacSha256
		alg2 = otp.AlgorithmSHA256
	}
	return
}

func totpCodeShouldEqual(actual interface{}, expected ...interface{}) string {
	if actual == expected[0] {
		return ""
	}
	ts := expected[2].(time.Time)
	return fmt.Sprintf("TOTP code %s should be %s\n(secret: %x)\n(time: %v)\n(algorithm: %v)",
		expected[0], actual, expected[1], ts.Unix(), expected[3])
}

func TestOath(t *testing.T) {

	Convey("OATH should work", t, func(ctx C) {

		oath, err := ykoath.New()
		So(err, ShouldBeNil)
		defer oath.Close()

		someDay := int64(rand.Uint32())<<10 | int64(rand.Uint32())
		// consistent time point
		oath.Clock = func() time.Time {
			return time.Unix(someDay, 0)
		}

		// enable OATH for this session
		_, err = oath.Select()
		So(err, ShouldBeNil)

		NumKeys := 100

		Convey("When name is too long", func(ctx C) {
			name := strings.Repeat("O", 65)
			err := oath.Delete(name)
			So(err, ShouldNotBeNil)
			So(err.Error(), ShouldEqual, "wrong syntax")

			err = oath.Put(name, ykoath.HmacSha1, ykoath.Totp, 6, make([]byte, 64), false)
			So(err, ShouldNotBeNil)
			So(err.Error(), ShouldEqual, "wrong syntax")

			_, err = oath.Calculate(name, nil)
			So(err, ShouldNotBeNil)
			So(err.Error(), ShouldEqual, "wrong syntax")
		})

		Convey("When it is empty", func(ctx C) {
			lResult, err := oath.List()
			So(err, ShouldBeNil)
			So(lResult, ShouldBeEmpty)

			cResult, err := oath.CalculateAll()
			So(err, ShouldBeNil)
			So(cResult, ShouldBeEmpty)
		})

		Convey("When deleting non-existent key", func(ctx C) {
			err := oath.Delete("foo")
			So(err, ShouldNotBeNil)
			So(err.Error(), ShouldEqual, "no such object")
		})

		Convey("Firstly add several keys", func(ctx C) {

			allKeys := make(map[string]*otp.Key)
			key2Alg := make(map[string]otp.Algorithm)
			for i := 0; i < NumKeys; i++ {
				alg1, alg2 := chooseAlgorithm()

				name := fmt.Sprintf("Index%054dHmac%d", i, alg1)
				key := make([]byte, 64)
				_, err := crand.Read(key)
				So(err, ShouldBeNil)

				// fmt.Printf("adding key %d %s %v\n", i, name, hex.EncodeToString(key))
				err = oath.Put(name, alg1, ykoath.Totp, 6, key, false)
				So(err, ShouldBeNil)

				opts := totp.GenerateOpts{
					Secret:      key,
					Issuer:      "Someone",
					AccountName: name,
					Algorithm:   alg2,
				}
				allKeys[name], err = totp.Generate(opts)
				So(err, ShouldBeNil)
				key2Alg[name] = alg2
			}

			Reset(func() {
				for name := range allKeys {
					err := oath.Delete(name)
					So(err, ShouldBeNil)
				}

				lResult, err := oath.List()
				So(err, ShouldBeNil)
				So(lResult, ShouldBeEmpty)
			})

			Convey("Then list keys", func(ctx C) {

				uniqueNames := make(map[string]bool)
				items, _ := oath.List()
				for _, item := range items {
					name := item.Name
					So(allKeys, ShouldContainKey, name)
					So(uniqueNames, ShouldNotContainKey, name)
					uniqueNames[name] = true
				}
			})

			Convey("Then calculate each of them", func(ctx C) {
				items, err := oath.List()
				So(err, ShouldBeNil)

				for _, item := range items {
					name := item.Name
					So(allKeys, ShouldContainKey, name)
					otp, err := oath.Calculate(name, nil)
					So(err, ShouldBeNil)
					// fmt.Printf("%s %s\n", otp, name)

					otpHost, err := totp.GenerateCodeCustom(allKeys[name].Secret(), oath.Clock(), totp.ValidateOpts{
						Period:    30,
						Skew:      1,
						Digits:    6,
						Algorithm: key2Alg[name],
					})
					So(err, ShouldBeNil)
					So(otpHost, totpCodeShouldEqual, otp, allKeys[name].Secret(), oath.Clock(), key2Alg[name].String())
				}
			})

			Convey("Then calculate all of them at once", func(ctx C) {
				results, err := oath.CalculateAll()
				So(err, ShouldBeNil)
				for name, otp := range results {
					So(allKeys, ShouldContainKey, name)
					// fmt.Printf("%s %s\n", otp, name)

					otpHost, err := totp.GenerateCodeCustom(allKeys[name].Secret(), oath.Clock(), totp.ValidateOpts{
						Period:    30,
						Skew:      1,
						Digits:    6,
						Algorithm: key2Alg[name],
					})
					So(err, ShouldBeNil)
					So(otpHost, totpCodeShouldEqual, otp, allKeys[name].Secret(), oath.Clock(), key2Alg[name].String())
				}
			})

		})

	})

}
