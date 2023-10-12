// SPDX-License-Identifier: Apache-2.0
package main

import (
	"crypto/des"
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

const ADMIN_P1_CFG_PIV_ALGO_EXT = 7

type PIVApplet struct {
	context *scard.Context
	card    *scard.Card
}

func New() (*PIVApplet, error) {
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
		if strings.Contains(strings.ToLower(reader), "canokey") && strings.Contains(strings.ToLower(reader), "piv") {
			card, err := context.Connect(reader, scard.ShareShared, scard.ProtocolAny)
			if err != nil {
				context.Release()
				return nil, errors.Wrapf(err, errFailedToConnect)
			}

			return &PIVApplet{
				card:    card,
				context: context,
			}, nil
		}
	}
	context.Release()
	return nil, fmt.Errorf(errFailedToListSuitableReader, len(readers))
}
func (o *PIVApplet) Close() error {
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
func (o *PIVApplet) Send(apdu []byte) ([]byte, uint16, error) {
	res, err := o.card.Transmit(apdu)

	if err != nil {
		return nil, 0, errors.Wrapf(err, errFailedToTransmit)
	}
	return res[0 : len(res)-2], uint16(res[len(res)-2])<<8 | uint16(res[len(res)-1]), nil
}
func (app *PIVApplet) ConfigPIVAlgoExt(enable uint8) {
	verifyPin := func(pin []byte) (code uint16) {
		_, code, err := app.Send(append([]byte{0x00, 0x20, 0x00, 0x00, byte(len(pin))}, pin...))
		So(err, ShouldBeNil)
		return
	}

	_, code, err := app.Send([]byte{0x00, 0xA4, 0x04, 0x00, 0x05, 0xF0, 0x00, 0x00, 0x00, 0x00})
	So(err, ShouldBeNil)
	So(code, ShouldEqual, 0x9000)
	So(verifyPin([]byte{0x31, 0x32, 0x33, 0x34, 0x35, 0x36}), ShouldEqual, 0x9000)

	apdu := []byte{0x00, 0x40, uint8(ADMIN_P1_CFG_PIV_ALGO_EXT), enable}
	_, code, err = app.Send(apdu)
	So(err, ShouldBeNil)
	So(code, ShouldEqual, 0x9000)
}
func (app *PIVApplet) Select() {
	_, code, err := app.Send([]byte{0x00, 0xA4, 0x04, 0x00, 0x05, 0xA0, 0x00, 0x00, 0x03, 0x08})
	So(err, ShouldBeNil)
	So(code, ShouldEqual, 0x9000)
}
func (app *PIVApplet) Authenticate() {
	key := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}
	ci, err := des.NewTripleDESCipher(key)
	So(err, ShouldBeNil)

	chal, code, err := app.Send([]byte{0x00, 0x87, 0x03, 0x9B, 0x04, 0x7C, 0x02, 0x81, 0x00, 0x00})
	So(err, ShouldBeNil)
	So(code, ShouldEqual, 0x9000)
	So(chal[0], ShouldEqual, 0x7C)
	l := chal[1]
	chal = chal[2 : 2+l]
	So(chal[0], ShouldEqual, 0x81)
	l = chal[1]
	chal = chal[2 : 2+l]

	rsp := make([]byte, l)
	ci.Encrypt(rsp, chal)

	_, code, err = app.Send(append([]byte{0x00, 0x87, 0x03, 0x9B, byte(l + 4), 0x7C, byte(l + 2), 0x82, byte(l)}, rsp...))
	So(err, ShouldBeNil)
	So(code, ShouldEqual, 0x9000)
}

func TestPIVExtensions(t *testing.T) {

	Convey("Connecting to applet", t, func(ctx C) {

		app, err := New()
		So(err, ShouldBeNil)
		defer app.Close()

		Convey("Enable algorithm extension", func(ctx C) {
			app.ConfigPIVAlgoExt(1)
		})

		Convey("Select the Applet and Authenticate", func(ctx C) {
			app.Select()
			app.Authenticate()
		})

		Convey("Generate the key", func(ctx C) {
			for keyID := 0x50; keyID <= 0x54; keyID++ {
				_, code, err := app.Send([]byte{0x00, 0x47, 0x00, 0x9E, 0x05, 0xAC, 0x03, 0x80, 0x01, byte(keyID)})
				So(err, ShouldBeNil)
				if code&0xFF00 != 0x6100 {
					So(code, ShouldEqual, 0x9000)
				}
			}
		})

		Convey("Disable algorithm extension", func(ctx C) {
			app.ConfigPIVAlgoExt(0)
		})

		Convey("Select the Applet and Authenticate again", func(ctx C) {
			app.Select()
			app.Authenticate()
		})

		Convey("Generate the key again", func(ctx C) {
			for keyID := 0x50; keyID <= 0x54; keyID++ {
				_, code, err := app.Send([]byte{0x00, 0x47, 0x00, 0x9E, 0x05, 0xAC, 0x03, 0x80, 0x01, byte(keyID)})
				So(err, ShouldBeNil)
				So(code, ShouldEqual, 0x6A80)
			}
		})
	})
}
