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

type OpenPGPApplet struct {
	context *scard.Context
	card    *scard.Card
}

func New() (*OpenPGPApplet, error) {
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
		if strings.Contains(reader, "Canokey") && strings.Contains(reader, "OpenPGP") {
			card, err := context.Connect(reader, scard.ShareShared, scard.ProtocolAny)
			if err != nil {
				context.Release()
				return nil, errors.Wrapf(err, errFailedToConnect)
			}

			return &OpenPGPApplet{
				card:    card,
				context: context,
			}, nil
		}
	}
	context.Release()
	return nil, fmt.Errorf(errFailedToListSuitableReader, len(readers))
}
func (o *OpenPGPApplet) Close() error {
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
func (o *OpenPGPApplet) Send(apdu []byte) ([]byte, uint16, error) {
	res, err := o.card.Transmit(apdu)

	if err != nil {
		return nil, 0, errors.Wrapf(err, errFailedToTransmit)
	}
	return res[0 : len(res)-2], uint16(res[len(res)-2])<<8 | uint16(res[len(res)-1]), nil
}

func TestOpenPGPApplet(t *testing.T) {
	Convey("Connecting to applet", t, func(ctx C) {

		app, err := New()
		So(err, ShouldBeNil)
		defer app.Close()

		Convey("OpenPGP Applet behaves correctly", func(ctx C) {
			_, code, err := app.Send([]byte{0x00, 0xA4, 0x04, 0x00, 0x06, 0xD2, 0x76, 0x00, 0x01, 0x24, 0x01})
			So(err, ShouldBeNil)
			So(code, ShouldEqual, 0x9000)
		})

		Convey("Get Key Info", func(ctx C) {
			res, code, err := app.Send([]byte{0x00, 0xCA, 0x00, 0xDE, 0x00})
			So(err, ShouldBeNil)
			So(code, ShouldEqual, 0x9000)
			So(res, ShouldResemble, []byte{0x01, 0x00, 0x02, 0x00, 0x03, 0x00})

			res, code, err = app.Send([]byte{0x00, 0xCA, 0x7F, 0x74, 0x00})
			So(err, ShouldBeNil)
			So(code, ShouldEqual, 0x9000)
			So(res, ShouldResemble, []byte{0x81, 0x01, 0x20})
		})

		Convey("Get extended length info", func(ctx C) {
			res, code, err := app.Send([]byte{0x00, 0xCA, 0x7F, 0x66, 0x08})
			So(err, ShouldBeNil)
			So(code, ShouldEqual, 0x9000)
			So(res, ShouldResemble, []byte{2, 2, 0x05, 0x3C, 2, 2, 0x05, 0x3C}) // 1340 bytes
		})

		Convey("Admin PIN retry times", func(ctx C) {
			_, code, err := app.Send([]byte{0x00, 0x20, 0x00, 0x83})
			So(err, ShouldBeNil)
			So(code, ShouldEqual, 0x63C3)
		})

		Convey("Verify Admin PIN to write data", func(ctx C) {
			_, code, err := app.Send([]byte{0x00, 0x20, 0x00, 0x83, 0x08, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38})
			So(err, ShouldBeNil)
			So(code, ShouldEqual, 0x9000)
		})

		Convey("Admin PIN verified", func(ctx C) {
			_, code, err := app.Send([]byte{0x00, 0x20, 0x00, 0x83})
			So(err, ShouldBeNil)
			So(code, ShouldEqual, 0x9000)
			_, code, err = app.Send([]byte{0x00, 0x20, 0xFF, 0x83})
			So(err, ShouldBeNil)
			So(code, ShouldEqual, 0x9000)
			_, code, err = app.Send([]byte{0x00, 0x20, 0x00, 0x83})
			So(err, ShouldBeNil)
			So(code, ShouldEqual, 0x63C3)
			_, code, err = app.Send([]byte{0x00, 0x20, 0x00, 0x83, 0x08, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38})
			So(err, ShouldBeNil)
			So(code, ShouldEqual, 0x9000)
		})

		Convey("Set then get UIF cache time (Private extension)", func(ctx C) {
			res, code, err := app.Send([]byte{0x00, 0xDA, 0x01, 0x02, 0x01, 0x55})
			So(err, ShouldBeNil)
			So(code, ShouldEqual, 0x9000)

			res, code, err = app.Send([]byte{0x00, 0xCA, 0x01, 0x02, 0x01})
			So(err, ShouldBeNil)
			So(code, ShouldEqual, 0x9000)
			So(res, ShouldResemble, []byte{0x55})
		})

		Convey("Verify User PIN", func(ctx C) {
			// not verified every time
			_, code, err := app.Send([]byte{0x00, 0xDA, 0x00, 0xC4, 0x01, 0x01})
			So(err, ShouldBeNil)
			So(code, ShouldEqual, 0x9000)

			_, code, err = app.Send([]byte{0x00, 0x20, 0x00, 0x81, 0x06, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36})
			So(err, ShouldBeNil)
			So(code, ShouldEqual, 0x9000)

			_, code, err = app.Send([]byte{0x00, 0x20, 0x00, 0x82, 0x06, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36})
			So(err, ShouldBeNil)
			So(code, ShouldEqual, 0x9000)
		})

		Convey("Error handling", func(ctx C) {
			_, code, err := app.Send([]byte{0x00, 0xFF, 0x01, 0x01, 0x00})
			So(err, ShouldBeNil)
			So(code, ShouldEqual, 0x6D00)

			_, code, err = app.Send([]byte{0x00, 0xCA, 0x01, 0x01, 0x00})
			So(err, ShouldBeNil)
			So(code, ShouldEqual, 0x6A88)

			_, code, err = app.Send([]byte{0x00, 0xDA, 0x01, 0x01, 0x01, 0x55})
			So(err, ShouldBeNil)
			So(code, ShouldEqual, 0x6A86)

			_, code, err = app.Send([]byte{0x00, 0xDA, 0x00, 0xC1, 0x01, 0x01})
			So(err, ShouldBeNil)
			So(code, ShouldEqual, 0x6A80)

			_, code, err = app.Send([]byte{0x00, 0xDA, 0x00, 0xC1, 0x06, 0x13, 0x2A, 0x86, 0x48, 0xCE, 0x3D})
			So(err, ShouldBeNil)
			So(code, ShouldEqual, 0x6A80)

			_, code, err = app.Send([]byte{0x00, 0x20, 0xFF, 0x84})
			So(err, ShouldBeNil)
			So(code, ShouldEqual, 0x6A86)

			_, code, err = app.Send([]byte{0x00, 0x24, 0x00, 0x84})
			So(err, ShouldBeNil)
			So(code, ShouldEqual, 0x6A86)

			_, code, err = app.Send([]byte{0x00, 0x47, 0x80, 0x00, 0x02, 0xFF, 0x00})
			So(err, ShouldBeNil)
			So(code, ShouldEqual, 0x6A80)

			_, code, err = app.Send([]byte{0x00, 0x47, 0x82, 0x00, 0x02, 0xA4, 0x00})
			So(err, ShouldBeNil)
			So(code, ShouldEqual, 0x6A86)

			_, code, err = app.Send([]byte{0x00, 0x2A, 0x99, 0x99, 0x00})
			So(err, ShouldBeNil)
			So(code, ShouldEqual, 0x6A86)

			// Sign
			_, code, err = app.Send([]byte{0x00, 0x2A, 0x9E, 0x9A, 0x02, 0xA4, 0x00})
			So(err, ShouldBeNil)
			So(code, ShouldEqual, 0x6A88) // KEY_NOT_PRESENT

			// add an ECDSA key
			_, code, err = app.Send([]byte{0x00, 0xDA, 0x00, 0xC1, 0x06, 0x13, 0x2B, 0x81, 0x04, 0x00, 0x0A})
			So(err, ShouldBeNil)
			So(code, ShouldEqual, 0x9000)
			_, code, err = app.Send([]byte{0x00, 0x47, 0x80, 0x00, 0x02, 0xB6, 0x00, 0x00})
			So(err, ShouldBeNil)
			So(code, ShouldEqual, 0x9000)

			_, code, err = app.Send([]byte{0x00, 0x2A, 0x9E, 0x9A, 0x01, 0xF1})
			So(err, ShouldBeNil)
			So(code, ShouldEqual, 0x6700) // data too short for ECDSA

			// add a RSA key
			_, code, err = app.Send([]byte{0x00, 0xDA, 0x00, 0xC1, 0x06, 0x01, 0x08, 0x00, 0x00, 0x20, 0x02})
			So(err, ShouldBeNil)
			So(code, ShouldEqual, 0x9000)
			// not generated

			_, code, err = app.Send(append([]byte{0x00, 0x2A, 0x9E, 0x9A, 0x66}, make([]byte, 0x66)...))
			So(err, ShouldBeNil)
			So(code, ShouldEqual, 0x6A88) // key deleted automatically

			_, code, err = app.Send([]byte{0x00, 0x47, 0x80, 0x00, 0x05, 0xB6, 0x03, 0x84, 0x01, 0x01, 0x03})
			So(err, ShouldBeNil)
			So(code, ShouldEqual, 0x61FF) // more data available

			_, code, err = app.Send(append([]byte{0x00, 0x2A, 0x9E, 0x9A, 0x67}, make([]byte, 0x67)...))
			So(err, ShouldBeNil)
			So(code, ShouldEqual, 0x6A80) // data is longer than 40% of 2048-bits

			// Decipher
			_, code, err = app.Send([]byte{0x00, 0x2A, 0x80, 0x86, 0x02, 0xA4, 0x00})
			So(err, ShouldBeNil)
			So(code, ShouldEqual, 0x6A88) // KEY_NOT_PRESENT

			// add an ECDH key
			_, code, err = app.Send([]byte{0x00, 0xDA, 0x00, 0xC2, 0x06, 0x12, 0x2B, 0x81, 0x04, 0x00, 0x22})
			So(err, ShouldBeNil)
			So(code, ShouldEqual, 0x9000)
			_, code, err = app.Send([]byte{0x00, 0x47, 0x80, 0x00, 0x02, 0xB8, 0x00, 0x00})
			So(err, ShouldBeNil)
			So(code, ShouldEqual, 0x9000)

			_, code, err = app.Send([]byte{0x00, 0x2A, 0x80, 0x86, 0x08, 0xA6, 0x33, 0x77, 0xA6, 0x77, 0xA6, 0x33, 0x77})
			So(err, ShouldBeNil)
			So(code, ShouldEqual, 0x6A80) // wrong T for ECDH

			_, code, err = app.Send([]byte{0x00, 0x2A, 0x80, 0x86, 0x08, 0xA6, 0x00, 0x7F, 0x49, 0x00, 0x86, 0x00, 0x04})
			So(err, ShouldBeNil)
			So(code, ShouldEqual, 0x6A80) // wrong L for ECDH

			// add a X25519 key
			_, code, err = app.Send([]byte{0x00, 0xDA, 0x00, 0xC2, 0x0B, 0x12, 0x2B, 0x06, 0x01, 0x04, 0x01, 0x97, 0x55, 0x01, 0x05, 0x01})
			So(err, ShouldBeNil)
			So(code, ShouldEqual, 0x9000)
			// not generated

			_, code, err = app.Send(append([]byte{0x00, 0x2A, 0x80, 0x86, 0x27, 0xA6, 0x25, 0x7F, 0x49, 0x22, 0x86, 0x20}, make([]byte, 0x20)...))
			So(err, ShouldBeNil)
			So(code, ShouldEqual, 0x6A88) // key deleted automatically

			_, code, err = app.Send([]byte{0x00, 0x47, 0x80, 0x00, 0x05, 0xB8, 0x03, 0x84, 0x01, 0x02, 0x00})
			So(err, ShouldBeNil)
			So(code, ShouldEqual, 0x9000)

			_, code, err = app.Send([]byte{0x00, 0x2A, 0x80, 0x86, 0x08, 0xA6, 0x25, 0x7F, 0x49, 0x22, 0x86, 0x19, 0x04})
			So(err, ShouldBeNil)
			So(code, ShouldEqual, 0x6A80) // wrong L for X25519

			// X25519, unchanged
			_, code, err = app.Send([]byte{0x00, 0xDA, 0x00, 0xC2, 0x0B, 0x12, 0x2B, 0x06, 0x01, 0x04, 0x01, 0x97, 0x55, 0x01, 0x05, 0x01})
			So(err, ShouldBeNil)
			So(code, ShouldEqual, 0x9000)

			_, code, err = app.Send([]byte{0x00, 0x2A, 0x80, 0x86, 0x08, 0xA6, 0x25, 0x7F, 0x49, 0x22, 0x86, 0x19, 0x04})
			So(err, ShouldBeNil)
			So(code, ShouldEqual, 0x6A80) // wrong L for X25519

			// Auth
			_, code, err = app.Send([]byte{0x00, 0x88, 0x00, 0x00, 0x02, 0xA4, 0x00})
			So(err, ShouldBeNil)
			So(code, ShouldEqual, 0x6A88) // KEY_NOT_PRESENT

			// add an ECDSA key
			_, code, err = app.Send([]byte{0x00, 0xDA, 0x00, 0xC3, 0x06, 0x13, 0x2B, 0x81, 0x04, 0x00, 0x22})
			So(err, ShouldBeNil)
			So(code, ShouldEqual, 0x9000)
			_, code, err = app.Send([]byte{0x00, 0x47, 0x80, 0x00, 0x02, 0xA4, 0x00, 0x00})
			So(err, ShouldBeNil)
			So(code, ShouldEqual, 0x9000)

			_, code, err = app.Send(append([]byte{0x00, 0x88, 0x00, 0x00, 0x01}, make([]byte, 0x01)...))
			So(err, ShouldBeNil)
			So(code, ShouldEqual, 0x6700) // data too short for ECDSA

			// add a RSA key
			_, code, err = app.Send([]byte{0x00, 0xDA, 0x00, 0xC3, 0x06, 0x01, 0x08, 0x00, 0x00, 0x20, 0x02})
			So(err, ShouldBeNil)
			So(code, ShouldEqual, 0x9000)
			// not generated

			_, code, err = app.Send(append([]byte{0x00, 0x88, 0x00, 0x00, 0x67}, make([]byte, 0x67)...))
			So(err, ShouldBeNil)
			So(code, ShouldEqual, 0x6A88) // key deleted automatically

			_, code, err = app.Send([]byte{0x00, 0x47, 0x80, 0x00, 0x05, 0xA4, 0x03, 0x84, 0x01, 0x03, 0x02})
			So(err, ShouldBeNil)
			So(code, ShouldEqual, 0x61FF) // more data available

			_, code, err = app.Send(append([]byte{0x00, 0x88, 0x00, 0x00, 0x67}, make([]byte, 0x67)...))
			So(err, ShouldBeNil)
			So(code, ShouldEqual, 0x6A80) // data is longer than 40% of 2048-bits

		})
	})
}

func TestOpenPGPCerts(t *testing.T) {
	certContent := [][]byte{
		{},
		make([]byte, 0x480),
		make([]byte, 0x480),
		make([]byte, 0x480),
	}
	for i := 1; i <= 3; i++ {
		crand.Read(certContent[i])
	}
	cert3Short := []byte{0x10, 0x20, 0x30, 0x83, 0x08}

	Convey("Connecting to applet", t, func(ctx C) {

		app, err := New()
		So(err, ShouldBeNil)
		defer app.Close()

		// _, code, err := app.Send([]byte{0x00, 0xA4, 0x04, 0x00, 0x06, 0xD2, 0x76, 0x00, 0x01, 0x24, 0x01})
		// So(err, ShouldBeNil)
		// So(code, ShouldEqual, 0x9000)

		// // Verify Admin PIN
		// _, code, err := app.Send([]byte{0x00, 0x20, 0x00, 0x83, 0x08, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38})
		// So(err, ShouldBeNil)
		// So(code, ShouldEqual, 0x9000)

		Convey("Select the Applet", func(ctx C) {
			_, code, err := app.Send([]byte{0x00, 0xA4, 0x04, 0x00, 0x06, 0xD2, 0x76, 0x00, 0x01, 0x24, 0x01})
			So(err, ShouldBeNil)
			So(code, ShouldEqual, 0x9000)
		})

		Convey("Verify Admin PIN", func(ctx C) {
			_, code, err := app.Send([]byte{0x00, 0x20, 0x00, 0x83, 0x08, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38})
			So(err, ShouldBeNil)
			So(code, ShouldEqual, 0x9000)
		})

		putCert := func(cert []byte) []byte {
			if len(cert) > 255 {
				return append([]byte{0x00, 0xDA, 0x7F, 0x21, 0x00, byte(len(cert) >> 8), byte(len(cert))}, cert...)
			}
			return append([]byte{0x00, 0xDA, 0x7F, 0x21, byte(len(cert))}, cert...)
		}

		Convey("Select cert 3", func(ctx C) {
			_, code, err := app.Send([]byte{0x00, 0xA5, 0x02, 0x04, 0x06, 0x60, 0x04, 0x5C, 0x02, 0x7F, 0x21})
			So(err, ShouldBeNil)
			So(code, ShouldEqual, 0x9000)
		})

		Convey("Put cert 3", func(ctx C) {
			_, code, err := app.Send(putCert(cert3Short))
			So(err, ShouldBeNil)
			So(code, ShouldEqual, 0x9000)
		})

		Convey("Select cert 4", func(ctx C) {
			_, code, err := app.Send([]byte{0x00, 0xA5, 0x03, 0x04, 0x06, 0x60, 0x04, 0x5C, 0x02, 0x7F, 0x21})
			So(err, ShouldBeNil)
			So(code, ShouldEqual, 0x6A86)
		})

		Convey("Put cert 1", func(ctx C) {
			_, code, err := app.Send(putCert(certContent[1]))
			So(err, ShouldBeNil)
			So(code, ShouldEqual, 0x9000)
		})

		Convey("Select cert 2", func(ctx C) {
			_, code, err := app.Send([]byte{0x00, 0xA5, 0x01, 0x04, 0x06, 0x60, 0x04, 0x5C, 0x02, 0x7F, 0x21})
			So(err, ShouldBeNil)
			So(code, ShouldEqual, 0x9000)
		})

		Convey("Put cert 2", func(ctx C) {
			_, code, err := app.Send(putCert(certContent[2]))
			So(err, ShouldBeNil)
			So(code, ShouldEqual, 0x9000)
		})

		Convey("Read cert 1", func(ctx C) {
			res, code, err := app.Send([]byte{0x00, 0xCA, 0x7F, 0x21, 0x00, 0x00, 0x00})
			So(err, ShouldBeNil)
			So(code, ShouldEqual, 0x9000)
			So(res, ShouldResemble, certContent[1])
		})

		Convey("Read next cert 2", func(ctx C) {
			res, code, err := app.Send([]byte{0x00, 0xCC, 0x7F, 0x21, 0x00, 0x00, 0x00})
			So(err, ShouldBeNil)
			So(code, ShouldEqual, 0x9000)
			So(res, ShouldResemble, certContent[2])
		})

		Convey("Select cert 3 again", func(ctx C) {
			_, code, err := app.Send([]byte{0x00, 0xA5, 0x02, 0x04, 0x06, 0x60, 0x04, 0x5C, 0x02, 0x7F, 0x21})
			So(err, ShouldBeNil)
			So(code, ShouldEqual, 0x9000)
		})

		Convey("Read cert 3", func(ctx C) {
			res, code, err := app.Send([]byte{0x00, 0xCA, 0x7F, 0x21, 0x00, 0x00, 0x00})
			So(err, ShouldBeNil)
			So(code, ShouldEqual, 0x9000)
			So(res, ShouldResemble, cert3Short)
		})

		Convey("Read next cert 4", func(ctx C) {
			_, code, err := app.Send([]byte{0x00, 0xCC, 0x7F, 0x21, 0x00, 0x00, 0x00})
			So(err, ShouldBeNil)
			So(code, ShouldEqual, 0x6A88)
		})

		Convey("Select cert 3 to update", func(ctx C) {
			_, code, err := app.Send([]byte{0x00, 0xA5, 0x02, 0x04, 0x06, 0x60, 0x04, 0x5C, 0x02, 0x7F, 0x21})
			So(err, ShouldBeNil)
			So(code, ShouldEqual, 0x9000)
		})

		Convey("Put cert 3 again", func(ctx C) {
			_, code, err := app.Send(putCert(certContent[3]))
			So(err, ShouldBeNil)
			So(code, ShouldEqual, 0x9000)
		})

		Convey("Select cert 1", func(ctx C) {
			_, code, err := app.Send([]byte{0x00, 0xA5, 0x00, 0x04, 0x06, 0x60, 0x04, 0x5C, 0x02, 0x7F, 0x21})
			So(err, ShouldBeNil)
			So(code, ShouldEqual, 0x9000)
		})

		Convey("Select cert 2 again", func(ctx C) {
			_, code, err := app.Send([]byte{0x00, 0xA5, 0x01, 0x04, 0x06, 0x60, 0x04, 0x5C, 0x02, 0x7F, 0x21})
			So(err, ShouldBeNil)
			So(code, ShouldEqual, 0x9000)
		})

		Convey("Read cert 2 again", func(ctx C) {
			res, code, err := app.Send([]byte{0x00, 0xCA, 0x7F, 0x21, 0x00, 0x00, 0x00})
			So(err, ShouldBeNil)
			So(code, ShouldEqual, 0x9000)
			So(res, ShouldResemble, certContent[2])
		})

		Convey("Read next cert 3", func(ctx C) {
			res, code, err := app.Send([]byte{0x00, 0xCC, 0x7F, 0x21, 0x00, 0x00, 0x00})
			So(err, ShouldBeNil)
			So(code, ShouldEqual, 0x9000)
			So(res, ShouldResemble, certContent[3])
		})

		Convey("Select non-existent cert", func(ctx C) {
			_, code, err := app.Send([]byte{0x00, 0xA5, 0x02, 0x04, 0x06, 0xFF, 0x04, 0x5C, 0x02, 0x7F, 0x21})
			So(err, ShouldBeNil)
			So(code, ShouldEqual, 0x6A80)
		})
	})
}

func TestAppletReset(t *testing.T) {
	Convey("Connecting to applet", t, func(ctx C) {

		app, err := New()
		So(err, ShouldBeNil)
		defer app.Close()

		Convey("Select the Applet", func(ctx C) {
			_, code, err := app.Send([]byte{0x00, 0xA4, 0x04, 0x00, 0x06, 0xD2, 0x76, 0x00, 0x01, 0x24, 0x01})
			So(err, ShouldBeNil)
			So(code, ShouldEqual, 0x9000)
		})

		Convey("Verify Admin PIN", func(ctx C) {
			_, code, err := app.Send([]byte{0x00, 0x20, 0x00, 0x83, 0x08, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38})
			So(err, ShouldBeNil)
			So(code, ShouldEqual, 0x9000)
		})

		Convey("Reset User PIN", func(ctx C) {
			_, code, err := app.Send([]byte{0x00, 0x2C, 0x02, 0x81, 0x08, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30})
			So(err, ShouldBeNil)
			So(code, ShouldEqual, 0x9000)
		})

		Convey("Set resetting code", func(ctx C) {
			_, code, err := app.Send([]byte{0x00, 0xDA, 0x00, 0xD3, 0x09, 0x31, 0x32, 0x33, 0x31, 0x32, 0x33, 0x31, 0x32, 0x33})
			So(err, ShouldBeNil)
			So(code, ShouldEqual, 0x9000)
		})

		Convey("Clear resetting code", func(ctx C) {
			_, code, err := app.Send([]byte{0x00, 0xDA, 0x00, 0xD3})
			So(err, ShouldBeNil)
			So(code, ShouldEqual, 0x9000)
		})

		Convey("Clear PIN verification state", func(ctx C) {
			_, code, err := app.Send([]byte{0x00, 0x20, 0xFF, 0x83})
			So(err, ShouldBeNil)
			So(code, ShouldEqual, 0x9000)
		})

		Convey("Wrong Admin PIN", func(ctx C) {
			for i := 0; i < 5; i++ {
				_, code, err := app.Send([]byte{0x00, 0x20, 0x00, 0x83, 0x08, 0x30, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38})
				So(err, ShouldBeNil)
				if code == 0x6983 {
					break
				}
				So(code, ShouldEqual, 0x6982)
			}
		})

		Convey("Factory reset", func(ctx C) {
			// terminate
			_, code, err := app.Send([]byte{0x00, 0xE6, 0x00, 0x00})
			So(err, ShouldBeNil)
			So(code, ShouldEqual, 0x9000)

			_, code, err = app.Send([]byte{0x00, 0xCA, 0x00, 0xDE, 0x00})
			So(err, ShouldBeNil)
			So(code, ShouldEqual, 0x6285)

			_, code, err = app.Send([]byte{0x00, 0xA4, 0x04, 0x00, 0x06, 0xD2, 0x76, 0x00, 0x01, 0x24, 0x01})
			So(err, ShouldBeNil)
			So(code, ShouldEqual, 0x9000)

			// activate
			_, code, err = app.Send([]byte{0x00, 0x44, 0x00, 0x00})
			So(err, ShouldBeNil)
			So(code, ShouldEqual, 0x9000)

			_, code, err = app.Send([]byte{0x00, 0xCA, 0x00, 0xDE, 0x00})
			So(err, ShouldBeNil)
			So(code, ShouldEqual, 0x9000)

			// activate again
			_, code, err = app.Send([]byte{0x00, 0x44, 0x00, 0x00})
			So(err, ShouldBeNil)
			So(code, ShouldEqual, 0x6985)
		})

	})

}
