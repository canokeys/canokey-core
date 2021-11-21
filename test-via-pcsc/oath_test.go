// SPDX-License-Identifier: Apache-2.0
package main

import (
	crand "crypto/rand"
	"encoding/base32"
	"encoding/hex"
	"fmt"
	"math/rand"
	"strings"
	"testing"
	"time"

	"github.com/canokeys/ykoath"
	"github.com/pquerna/otp"
	"github.com/pquerna/otp/hotp"
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

func otpCodeShouldEqual(actual interface{}, expected ...interface{}) string {
	if actual == expected[0] {
		return ""
	}
	b, _ := base32.StdEncoding.DecodeString(expected[1].(string))
	return fmt.Sprintf("OTP code %s should be %s\n(secret: %s)\n(challenge: %016x)\n(algorithm: %v)",
		expected[0], actual, hex.EncodeToString(b), expected[2], expected[3])
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

		clearRecords := func(NKeys int) {
			lResult, err := oath.List()
			So(err, ShouldBeNil)
			if NKeys != -1 {
				So(len(lResult), ShouldEqual, NKeys)
			}

			for _, item := range lResult {
				err := oath.Delete(item.Name)
				So(err, ShouldBeNil)
			}

			lResult, err = oath.List()
			So(err, ShouldBeNil)
			So(lResult, ShouldBeEmpty)
		}

		Convey("With invalid parameters", func(ctx C) {
			name := strings.Repeat("O", 64)
			err = oath.Put(name, ykoath.HmacSha1, ykoath.Totp, 6, make([]byte, 65), false, false, 0)
			So(err, ShouldNotBeNil)
			So(err.Error(), ShouldEqual, "wrong syntax")
		})

		Convey("When deleting all keys", func(ctx C) {
			clearRecords(-1)
		})

		Convey("When name is too long or empty", func(ctx C) {
			for _, l := range []int{0, 65} {
				name := strings.Repeat("O", l)
				err := oath.Delete(name)
				So(err, ShouldNotBeNil)
				So(err.Error(), ShouldEqual, "wrong syntax")

				err = oath.Put(name, ykoath.HmacSha1, ykoath.Totp, 6, make([]byte, 64), false, false, 0)
				So(err, ShouldNotBeNil)
				So(err.Error(), ShouldEqual, "wrong syntax")

				_, err = oath.Calculate(name, nil)
				So(err, ShouldNotBeNil)
				So(err.Error(), ShouldEqual, "wrong syntax")
			}
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

			CurKeys := 0
			allKeys := make(map[string]*otp.Key)
			key2Alg := make(map[string]otp.Algorithm)
			hotpCnt := make(map[string]uint64)
			for i := 0; i < NumKeys; i++ {
				var type1 ykoath.Type
				if i%2 == 0 {
					type1 = ykoath.Totp
				} else {
					type1 = ykoath.Hotp
				}
				alg1, alg2 := chooseAlgorithm()

				name := fmt.Sprintf("Index%054dHmac%d", i, alg1)

				keyLen := make([]byte, 1)
				_, err := crand.Read(keyLen)
				So(err, ShouldBeNil)

				key := make([]byte, int(keyLen[0])%64+1)
				_, err = crand.Read(key)
				So(err, ShouldBeNil)

				// fmt.Printf("adding key %d %s %s\n", i, name, hex.EncodeToString(key))
				err = oath.Put(name, alg1, type1, 6, key, false, true, 0)
				So(err, ShouldBeNil)
				CurKeys++

				if i%2 == 0 {
					opts := totp.GenerateOpts{
						Secret:      key,
						Issuer:      "Someone",
						AccountName: name,
						Algorithm:   alg2,
					}
					allKeys[name], err = totp.Generate(opts)
				} else {
					opts := hotp.GenerateOpts{
						Secret:      key,
						Issuer:      "Someone",
						AccountName: name,
						Algorithm:   alg2,
					}
					allKeys[name], err = hotp.Generate(opts)
					hotpCnt[name] = 1
				}
				So(err, ShouldBeNil)
				key2Alg[name] = alg2
			}

			defer clearRecords(CurKeys)

			validateTotp := func(name string, otp string) {
				// fmt.Printf("%s %s\n", otp, name)

				otpHost, err := totp.GenerateCodeCustom(allKeys[name].Secret(), oath.Clock(), totp.ValidateOpts{
					Period:    30,
					Skew:      1,
					Digits:    6,
					Algorithm: key2Alg[name],
				})
				So(err, ShouldBeNil)
				So(otpHost, otpCodeShouldEqual, otp, allKeys[name].Secret(), oath.Clock().Unix(), key2Alg[name].String())
			}
			validateHotp := func(name string, otp string) {

				otpHost, err := hotp.GenerateCodeCustom(allKeys[name].Secret(), hotpCnt[name], hotp.ValidateOpts{
					Digits:    6,
					Algorithm: key2Alg[name],
				})
				So(err, ShouldBeNil)
				So(otpHost, otpCodeShouldEqual, otp, allKeys[name].Secret(), hotpCnt[name], key2Alg[name].String())
				hotpCnt[name]++
			}

			Convey("Then set one key as default", func(ctx C) {
				name := ""
				for itemName, obj := range allKeys {
					if obj.Type() == "hotp" {
						name = itemName
						break
					}
				}
				err := oath.SetAsDefault(name)
				So(err, ShouldBeNil)
			})

			Convey("Then list keys", func(ctx C) {

				uniqueNames := make(map[string]bool)
				items, _ := oath.List()
				So(len(items), ShouldEqual, CurKeys)
				for _, item := range items {
					name := item.Name
					So(allKeys, ShouldContainKey, name)
					So(uniqueNames, ShouldNotContainKey, name)
					uniqueNames[name] = true
				}
			})

			Convey("Then calculate all of them at once", func(ctx C) {
				results, err := oath.CalculateAll()
				So(err, ShouldBeNil)
				So(len(results), ShouldEqual, CurKeys)
				for name, otp := range results {
					So(allKeys, ShouldContainKey, name)
					if allKeys[name].Type() == "hotp" {
						So(otp, ShouldEqual, "hotp-no-response")
					} else {
						validateTotp(name, otp)
					}
				}
			})
			Convey("Then calculate each of them", func(ctx C) {
				items, err := oath.List()
				So(err, ShouldBeNil)
				So(len(items), ShouldEqual, CurKeys)

				for _, item := range items {
					name := item.Name
					otp, err := oath.Calculate(name, nil)
					So(err, ShouldBeNil)
					So(allKeys, ShouldContainKey, name)
					if allKeys[name].Type() == "hotp" {
						validateHotp(name, otp)
					} else {
						validateTotp(name, otp)
					}
				}
			})
			Convey("Then test a sequence of HOTP values", func(ctx C) {
				name := ""
				for itemName, obj := range allKeys {
					if obj.Type() == "hotp" {
						name = itemName
						break
					}
				}
				for i := 0; i < 257; i++ {
					otp, err := oath.Calculate(name, nil)
					So(err, ShouldBeNil)
					validateHotp(name, otp)
				}
			})
		})

		Convey("Fill all slots in the end", func(ctx C) {
			var name string
			type1 := ykoath.Hotp
			alg1, _ := chooseAlgorithm()
			key := make([]byte, 64)
			for i := 0; i < NumKeys; i++ {
				alg1, _ = chooseAlgorithm()

				name = fmt.Sprintf("Index%054dHmac%d", i, alg1) // len=5+54+4+1
				_, err := crand.Read(key)
				So(err, ShouldBeNil)

				err = oath.Put(name, alg1, type1, 6, key, false, true, 0)
				So(err, ShouldBeNil)
			}

			lResult, err := oath.List()
			So(err, ShouldBeNil)
			So(len(lResult), ShouldEqual, NumKeys)

			Convey("Then put one more key should fail", func(ctx C) {
				err = oath.Put("name", alg1, type1, 6, key, false, true, 0)
				So(err, ShouldNotBeNil)
				So(err.Error(), ShouldEqual, "unknown (6a 84)")

				Convey("Then set the last key as default", func(ctx C) {
					err := oath.SetAsDefault(name)
					So(err, ShouldBeNil)
				})
			})
		})
	})

}
