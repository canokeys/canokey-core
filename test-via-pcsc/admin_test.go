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
	for _, reader := range readers {
		fmt.Printf("Reader: %s\n", reader)
		if strings.Contains(reader, "Canokey") && strings.Contains(reader, "OATH") {
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
		Convey("Vendor-specific", func(ctx C) {
			apdu := []byte{0x00, 0xFF, 0x00, 0x00}
			_, code, err := app.Send(apdu)
			So(err, ShouldBeNil)
			if verified {
				So(code, ShouldEqual, 0x9000)
			} else {
				So(code, ShouldEqual, 0x6982)
			}
		})
		Convey("Configuration", func(ctx C) {
			shadowCfg := []byte{0x00, 0x00, 0x00, 0x01, 0x01}
			P1toIdx := map[int]int{
				1: 0, // ADMIN_P1_CFG_LED_ON
				2: 2, // ndef_get_read_only
				3: 1, // ADMIN_P1_CFG_KBDIFACE
				4: 3, // ADMIN_P1_CFG_NDEF
				5: 4, // ADMIN_P1_CFG_WEBUSB_LANDING
			}
			for P1 := 1; P1 <= 5; P1++ {
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
				_, code, err = app.Send([]byte{0x00, 0x20, 0x00, 0x00, 0x06, 0x31, 0x32, 0x33, 0x34, 0x35, 0x35})
				So(err, ShouldBeNil)
				So(code, ShouldEqual, 0x63C2)
				_, code, err := app.Send([]byte{0x00, 0x20, 0x00, 0x00, 0x07, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37})
				So(err, ShouldBeNil)
				So(code, ShouldEqual, 0x63C1)

				_, code, err = app.Send([]byte{0x00, 0x20, 0x00, 0x00, 0x06, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36})
				So(err, ShouldBeNil)
				So(code, ShouldEqual, 0x9000)
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
