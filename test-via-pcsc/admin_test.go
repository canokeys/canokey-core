// SPDX-License-Identifier: Apache-2.0
package main

import (
	crand "crypto/rand"
	"fmt"
	"strings"
	"testing"

	"github.com/ebfe/scard"
	"github.com/pkg/errors"
	. "github.com/smartystreets/goconvey/convey"
)

const (
	errFailedToConnect            = "failed to connect to reader"
	errFailedToDisconnect         = "failed to disconnect from reader"
	errFailedToEstablishContext   = "failed to establish context"
	errFailedToListReaders        = "failed to list readers"
	errFailedToListSuitableReader = "no suitable reader found (out of %d readers)"
	errFailedToReleaseContext     = "failed to release context"
	errFailedToTransmit           = "failed to transmit APDU"
	errUnknownTag                 = "unknown tag (%x)"
)

type AdminApplet struct {
	context *scard.Context
	card    *scard.Card
}

func New() (*AdminApplet, error) {
	context, err := scard.EstablishContext()
	if err != nil {
		return nil, errors.Wrapf(err, errFailedToEstablishContext)
	}
	readers, err := context.ListReaders()
	if err != nil {
		context.Release()
		return nil, errors.Wrapf(err, errFailedToListReaders)
	}
	reader := ""
	if len(readers) == 1 {
		reader = readers[0]
	} else {
		for _, reader = range readers {
			// fmt.Printf("Reader: %s\n", reader)
			if strings.Contains(strings.ToLower(reader), "canokey") && strings.Contains(reader, "OATH") {
				break
			}
		}
	}
	if reader != "" {
		card, err := context.Connect(reader, scard.ShareShared, scard.ProtocolAny)
		if err != nil {
			context.Release()
			return nil, errors.Wrapf(err, errFailedToConnect)
		}

		return &AdminApplet{
			card:    card,
			context: context,
		}, nil
	}
	context.Release()
	return nil, fmt.Errorf(errFailedToListSuitableReader, len(readers))
}
func (o *AdminApplet) Close() error {
	if err := o.card.Disconnect(scard.LeaveCard); err != nil {
		return errors.Wrapf(err, errFailedToDisconnect)
	}
	o.card = nil
	if err := o.context.Release(); err != nil {
		return errors.Wrapf(err, errFailedToReleaseContext)
	}
	o.context = nil
	return nil
}
func (o *AdminApplet) Send(apdu []byte) ([]byte, uint16, error) {
	res, err := o.card.Transmit(apdu)

	if err != nil {
		return nil, 0, errors.Wrapf(err, errFailedToTransmit)
	}
	return res[0 : len(res)-2], (uint16(res[len(res)-2])<<8 | uint16(res[len(res)-1])), nil
}

func commandTests(verified bool, app *AdminApplet) func(C) {
	setPinTo := func(pin []byte) (code uint16) {
		_, code, err := app.Send(append([]byte{0x00, 0x21, 0x00, 0x00, byte(len(pin))}, pin...))
		So(err, ShouldBeNil)
		return
	}
	verifyPin := func(pin []byte) (code uint16) {
		_, code, err := app.Send(append([]byte{0x00, 0x20, 0x00, 0x00, byte(len(pin))}, pin...))
		So(err, ShouldBeNil)
		return
	}
	return func(ctx C) {
		if verified {
			So(verifyPin([]byte{0x31, 0x32, 0x33, 0x34, 0x35, 0x36}), ShouldEqual, 0x9000)
		}
		Convey("Invalid Instruction", func(ctx C) {
			apdu := []byte{0x00, 0xEE, 0x00, 0x00}
			_, code, err := app.Send(apdu)
			So(err, ShouldBeNil)
			if verified {
				So(code, ShouldEqual, 0x6D00)
			} else {
				So(code, ShouldEqual, 0x6982)
			}
		})
		Convey("Read Version", func(ctx C) {
			ret, code, err := app.Send([]byte{0x00, 0x31, 0x00, 0x00, 0x00})
			So(err, ShouldBeNil)
			So(code, ShouldEqual, 0x9000)
			So(len(ret), ShouldBeGreaterThanOrEqualTo, 8) // Git short commit hash

			ret, code, err = app.Send([]byte{0x00, 0x31, 0x01, 0x00, 0x00})
			So(err, ShouldBeNil)
			So(code, ShouldEqual, 0x9000)
			So(ret[:7], ShouldResemble, []byte("CanoKey"))
		})
		Convey("Config Pass", func(ctx C) {
			if !verified {
				_, code, err := app.Send([]byte{0x00, 0x44, 0x01, 0x00})
				So(err, ShouldBeNil)
				So(code, ShouldEqual, 0x6982)
				return
			}
			buildCfg := func(ptype uint8, randSeed int) (ret []byte) {
				if ptype == 0 {
					ret = []byte {ptype}
				} else {
					data := []byte(fmt.Sprintf("%032d", randSeed))
					withEnter := uint8(randSeed & 1)
					ret = []byte {ptype, uint8(len(data))}
					ret = append(ret, data...)
					ret = append(ret, withEnter)
				}
				return
			}
			for slot := uint8(0); slot < 4; slot++ {
				for ptype := uint8(0); ptype < 4; ptype++ {
					randSeed := int(slot) * 10000 + int(ptype)
					cfg := buildCfg(ptype, randSeed)
					lc := uint8(len(cfg))
					_, code, err := app.Send(append([]byte{0x00, 0x44, slot, 0x00, lc}, cfg...))
					So(err, ShouldBeNil)
					if slot > 2 || slot < 1 {
						So(code, ShouldEqual, 0x6A86)
						break
					} else if ptype == 1 || ptype > 2 {
						So(code, ShouldEqual, 0x6A80)
						continue
					// } else if code!=0x9000{
					// 	fmt.Printf("%d %d\n", slot, ptype)
					} else {
						// fmt.Printf("write %d %d %v\n",slot,ptype,cfg)
						So(code, ShouldEqual, 0x9000)
					}

					resp, code, err := app.Send([]byte{0x00, 0x43, 0x00, 0x00, 0x60})
					So(code, ShouldEqual, 0x9000)
					So(err, ShouldBeNil)
					slot_rb := 1
					for i := 0; i < len(resp); {
						ptype_rb := resp[i]
						i++
						if ptype_rb == 2 {
							enter := resp[i]
							i++
							So(enter, ShouldEqual, (randSeed & 1))
						}
						if int(slot) == slot_rb {
							So(ptype_rb, ShouldEqual, ptype)
						}
						slot_rb++
					}
				}
			}
		})
		Convey("Vendor-specific", func(ctx C) {
			apdu := []byte{0x00, 0xFF, 0x77, 0x88}
			_, code, err := app.Send(apdu)
			So(err, ShouldBeNil)
			if verified {
				So(code, ShouldBeIn, []uint16{0x9000, 0x6A86})
			} else {
				So(code, ShouldEqual, 0x6982)
			}
		})
		Convey("Configuration", func(ctx C) {
			shadowCfg := []byte{0x01, 0x00, 0x00, 0x01, 0x01, 0x00}
			P1toIdx := map[int]int{
				1: 0, // ADMIN_P1_CFG_LED_ON
				2: 2, // ndef_get_read_only
				// 3: 1, // ADMIN_P1_CFG_KBDIFACE (obsolete)
				4: 3, // ADMIN_P1_CFG_NDEF
				5: 4, // ADMIN_P1_CFG_WEBUSB_LANDING
				// 6: 5, // ADMIN_P1_CFG_KBD_WITH_RETURN (obsolete)
			}
			for P1 := range P1toIdx {
				for _, P2 := range []int{0, 1, 0, 1} {
					apdu := []byte{0x00, 0x40, uint8(P1), uint8(P2)}
					_, code, err := app.Send(apdu)
					So(err, ShouldBeNil)
					if verified {
						if P1 == 2 {
							So(code, ShouldEqual, 0x6A86)
						} else {
							So(code, ShouldEqual, 0x9000)
							shadowCfg[P1toIdx[P1]] = byte(P2)
						}
					} else {
						So(code, ShouldEqual, 0x6982)
					}

					if P1 == 2 {
						apdu = []byte{0x00, 0x08, uint8(P2), 0x00} // ADMIN_INS_TOGGLE_NDEF_READ_ONLY
						_, code, err = app.Send(apdu)
						So(err, ShouldBeNil)
						if verified {
							So(code, ShouldEqual, 0x9000)
							shadowCfg[P1toIdx[P1]] = byte(P2)
						} else {
							So(code, ShouldEqual, 0x6982)
						}

					}

					apdu = []byte{0x00, 0x42, 0x00, 0x00, 0x00}
					cfg, code, err := app.Send(apdu)
					So(err, ShouldBeNil)
					if verified {
						So(code, ShouldEqual, 0x9000)
						So(cfg, ShouldResemble, shadowCfg)
					} else {
						So(code, ShouldEqual, 0x6982)
					}
				}
			}
		})
		Convey("Write SN", func(ctx C) {
			sn := []byte{0xA1, 0xB2, 0xC3, 0xD4}
			apdu := append([]byte{0x00, 0x30, 0x00, 0x00, byte(len(sn))}, sn...)
			_, code, err := app.Send(apdu)
			So(err, ShouldBeNil)
			if verified {
				So(code, ShouldBeIn, []uint16{0x6985, 0x9000})
			} else {
				So(code, ShouldEqual, 0x6982)
			}

			apdu = []byte{0x00, 0x32, 0x00, 0x00, byte(len(sn))}
			readSN, code, err := app.Send(apdu)
			So(code, ShouldEqual, 0x9000)
			if verified { // make sure that the SN is written before
				So(readSN, ShouldResemble, sn)
			}

			readSN, code, err = app.Send([]byte{0x00, 0x32, 0x01, 0x00, 0x00}) // admin_vendor_hw_sn
			So(err, ShouldBeNil)
			So(code, ShouldEqual, 0x9000)
			So(len(readSN), ShouldBeGreaterThan, 0)
		})
		Convey("Change PIN", func(ctx C) {
			pinTooLong := make([]byte, 65)
			pinTooShort := []byte{0x31, 0x32, 0x33, 0x34, 0x35}
			sixZeros := []byte{0x30, 0x30, 0x30, 0x30, 0x30, 0x30}
			code := setPinTo(pinTooLong)
			if !verified {
				So(code, ShouldEqual, 0x6982)
				return
			}
			So(code, ShouldEqual, 0x6700)
			code = setPinTo(pinTooShort)
			So(code, ShouldEqual, 0x6700)

			code = setPinTo(sixZeros)
			So(code, ShouldEqual, 0x9000)

			// security status is cleared after pin change
			So(setPinTo(sixZeros), ShouldEqual, 0x6982)

			// Verify the old pin
			So(verifyPin([]byte{0x31, 0x32, 0x33, 0x34, 0x35, 0x36}), ShouldEqual, 0x63C2)

			// Verify the new pin
			So(verifyPin(sixZeros), ShouldEqual, 0x9000)
			So(setPinTo(make([]byte, 129)), ShouldEqual, 0x6700)

			So(verifyPin(sixZeros), ShouldEqual, 0x9000)
			So(setPinTo(make([]byte, 5)), ShouldEqual, 0x6700)

			longestPin := make([]byte, 64)
			crand.Read(longestPin)
			So(verifyPin(sixZeros), ShouldEqual, 0x9000)
			So(setPinTo(longestPin), ShouldEqual, 0x9000)

			So(verifyPin(longestPin), ShouldEqual, 0x9000)
			So(setPinTo([]byte{0x31, 0x32, 0x33, 0x34, 0x35, 0x36}), ShouldEqual, 0x9000)
			So(verifyPin([]byte{0x31, 0x32, 0x33, 0x34, 0x35, 0x36}), ShouldEqual, 0x9000)

		})
		Convey("Reset OpenPGP", func(ctx C) {
			_, code, err := app.Send([]byte{0x00, 0x03, 0x00, 0x00})
			So(err, ShouldBeNil)
			if verified {
				So(code, ShouldEqual, 0x9000)
			} else {
				So(code, ShouldEqual, 0x6982)
			}
		})
		Convey("Reset PIV", func(ctx C) {
			_, code, err := app.Send([]byte{0x00, 0x04, 0x00, 0x00})
			So(err, ShouldBeNil)
			if verified {
				So(code, ShouldEqual, 0x9000)
			} else {
				So(code, ShouldEqual, 0x6982)
			}
		})
		Convey("Reset OATH", func(ctx C) {
			_, code, err := app.Send([]byte{0x00, 0x05, 0x00, 0x00})
			So(err, ShouldBeNil)
			if verified {
				So(code, ShouldEqual, 0x9000)
			} else {
				So(code, ShouldEqual, 0x6982)
			}
		})
		Convey("Reset NDEF", func(ctx C) {
			_, code, err := app.Send([]byte{0x00, 0x07, 0x00, 0x00})
			So(err, ShouldBeNil)
			if verified {
				So(code, ShouldEqual, 0x9000)
			} else {
				So(code, ShouldEqual, 0x6982)
			}
		})
	}
}

func TestFSUsage(t *testing.T) {

	Convey("Connecting to applet", t, func(ctx C) {

		app, err := New()
		So(err, ShouldBeNil)
		defer app.Close()

		_, code, err := app.Send([]byte{0x00, 0xA4, 0x04, 0x00, 0x05, 0xF0, 0x00, 0x00, 0x00, 0x00})
		So(err, ShouldBeNil)
		So(code, ShouldEqual, 0x9000)

		pin := []byte{0x31, 0x32, 0x33, 0x34, 0x35, 0x36}
		_, code, err = app.Send(append([]byte{0x00, 0x20, 0x00, 0x00, byte(len(pin))}, pin...))
		So(err, ShouldBeNil)

		data, code, err := app.Send([]byte{0x00, 0x41, 0x00, 0x00, 0x02})
		So(err, ShouldBeNil)
		So(len(data), ShouldEqual, 2)
		fmt.Printf("\n\nFile system usage: %d KB\n", int(data[0]))
	})
}

func TestAdminApplet(t *testing.T) {

	Convey("Connecting to applet", t, func(ctx C) {

		app, err := New()
		So(err, ShouldBeNil)
		defer app.Close()

		Convey("Admin Applet behaves correctly", func(ctx C) {

			_, code, err := app.Send([]byte{0x00, 0xA4, 0x04, 0x00, 0x05, 0xF0, 0x00, 0x00, 0x00, 0x00})
			So(err, ShouldBeNil)
			So(code, ShouldEqual, 0x9000)

			Convey("If pin is too long or too short", func(ctx C) {
				pin := make([]byte, 129)
				_, code, err := app.Send(append([]byte{0x00, 0x20, 0x00, 0x00, byte(len(pin))}, pin...))
				So(err, ShouldBeNil)
				So(code, ShouldEqual, 0x6700)
				_, code, err = app.Send([]byte{0x00, 0x20, 0x00, 0x00, 0x05, 0x01, 0x01, 0x01, 0x01, 0x01})
				So(err, ShouldBeNil)
				So(code, ShouldEqual, 0x6700)
			})

			Convey("When pin is not verified", commandTests(false, app))
			Convey("When pin is verified", commandTests(true, app))

			Convey("If pin verification fails", func(ctx C) {
				_, code, err = app.Send([]byte{0x00, 0x20, 0x00, 0x00})
				So(err, ShouldBeNil)
				So(code, ShouldEqual, 0x63C3)
				_, code, err = app.Send([]byte{0x00, 0x20, 0x00, 0x00, 0x06, 0x31, 0x32, 0x33, 0x34, 0x35, 0x35})
				So(err, ShouldBeNil)
				So(code, ShouldEqual, 0x63C2)
				_, code, err = app.Send([]byte{0x00, 0x20, 0x00, 0x00, 0x07, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37})
				So(err, ShouldBeNil)
				So(code, ShouldEqual, 0x63C1)

				Convey("Then enter the correct pin", func(ctx C) {
					_, code, err = app.Send([]byte{0x00, 0x20, 0x00, 0x00, 0x06, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36})
					So(err, ShouldBeNil)
					So(code, ShouldEqual, 0x9000)
				})
				Convey("Until the pin is locked", func(ctx C) {
					// Factory reset not allowed
					_, code, err = app.Send([]byte{0x00, 0x50, 0x00, 0x00, 0x05, 'R', 'E', 'S', 'E', 'T'})
					So(err, ShouldBeNil)
					So(code, ShouldEqual, 0x6985)

					_, code, err = app.Send([]byte{0x00, 0x20, 0x00, 0x00, 0x07, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37})
					So(err, ShouldBeNil)
					So(code, ShouldEqual, 0x6983)
					_, code, err = app.Send([]byte{0x00, 0x20, 0x00, 0x00})
					So(err, ShouldBeNil)
					So(code, ShouldEqual, 0x63C0)
					_, code, err = app.Send([]byte{0x00, 0x20, 0x00, 0x00, 0x06, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36})
					So(err, ShouldBeNil)
					So(code, ShouldEqual, 0x6983)

					// Do factory reset
					_, code, err = app.Send([]byte{0x00, 0x50, 0x00, 0x00, 0x05, 'R', 'E', 'S', 'E', 'T'})
					So(err, ShouldBeNil)
					So(code, ShouldEqual, 0x9000)
					// PIN unlocked now
					_, code, err = app.Send([]byte{0x00, 0x20, 0x00, 0x00, 0x06, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36})
					So(err, ShouldBeNil)
					So(code, ShouldEqual, 0x9000)
				})
			})
			Reset(func() {
				// Reset validation status without decreasing the counter
				_, code, err = app.Send([]byte{0x00, 0x20, 0x00, 0x00, 0x01, 0x00})
				So(err, ShouldBeNil)
				So(code, ShouldEqual, 0x6700)

				// Read retry counter
				_, code, err = app.Send([]byte{0x00, 0x20, 0x00, 0x00, 0x00})
				So(err, ShouldBeNil)
				So(code, ShouldEqual, 0x63C3)
			})
		})
	})

}
