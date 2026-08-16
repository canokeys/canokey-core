// SPDX-License-Identifier: Apache-2.0
package main

import (
	"crypto/des"
	"fmt"
	"os"
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
	reader := ""
	if len(readers) == 1 {
		reader = readers[0]
	} else {
		for _, candidate := range readers {
			lower := strings.ToLower(candidate)
			if strings.Contains(lower, "canokey") && strings.Contains(lower, "piv") {
				reader = candidate
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

		return &PIVApplet{
			card:    card,
			context: context,
		}, nil
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

func (o *PIVApplet) SendWithGetResponse(apdu []byte) ([]byte, uint16, error) {
	data, code, err := o.Send(apdu)
	if err != nil {
		return nil, code, err
	}

	out := append([]byte(nil), data...)
	for i := 0; code&0xFF00 == 0x6100; i++ {
		if i >= 16 {
			return nil, code, fmt.Errorf("too many GET RESPONSE iterations")
		}
		le := byte(code)
		if le == 0x00 || le == 0xFF {
			le = 0x00
		}
		data, code, err = o.Send([]byte{0x00, 0xC0, 0x00, 0x00, le})
		if err != nil {
			return nil, code, err
		}
		out = append(out, data...)
	}
	return out, code, nil
}
func (app *PIVApplet) ConfigPIVAlgoExt(config []byte) {
	_, code, err := app.Send(append([]byte{0x00, 0xEE, 0x02, 0x00, byte(len(config))}, config...))
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
	leaveAlgoExtEnabled := os.Getenv("CANOKEY_TEST_LEAVE_PIV_ALGO_EXT") != ""
	configOnly := os.Getenv("CANOKEY_TEST_PIV_CONFIG_ONLY") != ""
	algorithmIDs := []byte{0x22, 0x50, 0x51, 0x52, 0x53, 0x15, 0x54}
	if os.Getenv("CANOKEY_TEST_PIV_ALGO_EXT_STANDARD") != "" {
		algorithmIDs = []byte{0xE0, 0x05, 0x16, 0xE1, 0x53, 0x15, 0x54}
	}
	// Complete 7F49 response lengths: Ed25519, RSA3072, RSA4096,
	// X25519, secp256k1, secp521r1, and SM2.
	publicKeyResponseLengths := []int{37, 399, 527, 37, 70, 140, 70}
	enabledConfig := append([]byte{1}, algorithmIDs...)
	if os.Getenv("CANOKEY_TEST_PIV_ALGO_EXT_DISABLE") != "" {
		enabledConfig[0] = 0
	}

	Convey("Connecting to applet", t, func(ctx C) {

		app, err := New()
		So(err, ShouldBeNil)
		defer app.Close()

		Convey("Select the Applet and Authenticate", func(ctx C) {
			app.Select()
			app.Authenticate()
		})

		Convey("Configure algorithm extension", func(ctx C) {
			app.Authenticate()
			app.ConfigPIVAlgoExt(enabledConfig)
		})

		if !configOnly {
			Convey("Generate the key", func(ctx C) {
				for i, keyID := range algorithmIDs {
					app.Authenticate()
					response, code, err := app.SendWithGetResponse([]byte{0x00, 0x47, 0x00, 0x9E, 0x05, 0xAC, 0x03, 0x80, 0x01, keyID})
					So(err, ShouldBeNil)
					So(code, ShouldEqual, 0x9000)
					So(len(response), ShouldEqual, publicKeyResponseLengths[i])
				}
			})
		}

		if !leaveAlgoExtEnabled && !configOnly {
			Convey("Disable algorithm extension", func(ctx C) {
				app.Authenticate()
				disabledConfig := append([]byte(nil), enabledConfig...)
				disabledConfig[0] = 0
				app.ConfigPIVAlgoExt(disabledConfig)
			})

			Convey("Generate the key again", func(ctx C) {
				for _, keyID := range algorithmIDs {
					app.Authenticate()
					_, code, err := app.Send([]byte{0x00, 0x47, 0x00, 0x9E, 0x05, 0xAC, 0x03, 0x80, 0x01, byte(keyID)})
					So(err, ShouldBeNil)
					So(code, ShouldEqual, 0x6A80)
				}
			})
		}
	})
}
