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

		NumKeys := 10

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

		Convey("By adding some keys", func(ctx C) {

			allKeys := make(map[string]*otp.Key)
			for i := 0; i < NumKeys; i++ {
				name := fmt.Sprintf("name%060d", i)
				key := make([]byte, 64)
				_, err := crand.Read(key)
				So(err, ShouldBeNil)

				// fmt.Printf("adding key %d %s %v\n", i, name, hex.EncodeToString(key))
				err = oath.Put(name, ykoath.HmacSha1, ykoath.Totp, 6, key, false)
				So(err, ShouldBeNil)

				opts := totp.GenerateOpts{
					Secret:      key,
					Issuer:      "Someone",
					AccountName: name,
				}
				allKeys[name], err = totp.Generate(opts)
				So(err, ShouldBeNil)
			}

			Reset(func() {
				for name := range allKeys {
					err := oath.Delete(name)
					So(err, ShouldBeNil)
				}
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

					otpHost, err := totp.GenerateCode(allKeys[name].Secret(), oath.Clock())
					So(err, ShouldBeNil)
					So(otp, ShouldEqual, otpHost)
				}
			})

			Convey("Then calculate all of them at once", func(ctx C) {
				results, err := oath.CalculateAll()
				So(err, ShouldBeNil)
				for name, otp := range results {
					So(allKeys, ShouldContainKey, name)
					// fmt.Printf("%s %s\n", otp, name)

					otpHost, err := totp.GenerateCode(allKeys[name].Secret(), oath.Clock())
					So(err, ShouldBeNil)
					So(otp, ShouldEqual, otpHost)
				}
			})

		})

	})

}
