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
		if strings.Contains(reader, "Cano") && strings.Contains(reader, "OpenPGP") {
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
	cert2 := make([]byte, 1000)
	crand.Read(cert2)
	Convey("Connecting to applet", t, func(ctx C) {

		app, err := New()
		So(err, ShouldBeNil)
		defer app.Close()

		Convey("OpenPGP Applet behaves correctly", func(ctx C) {
			_, code, err := app.Send([]byte{0x00, 0xA4, 0x04, 0x00, 0x06, 0xD2, 0x76, 0x00, 0x01, 0x24, 0x01})
			So(err, ShouldBeNil)
			So(code, ShouldEqual, 0x9000)
		})

		Convey("Verify Admin PIN to write data", func(ctx C) {
			_, code, err := app.Send([]byte{0x00, 0x20, 0x00, 0x83, 0x08, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38})
			So(err, ShouldBeNil)
			So(code, ShouldEqual, 0x9000)
		})

		Convey("Select cert 3", func(ctx C) {
			_, code, err := app.Send([]byte{0x00, 0xA5, 0x02, 0x04, 0x06, 0x60, 0x04, 0x5C, 0x02, 0x7F, 0x21})
			So(err, ShouldBeNil)
			So(code, ShouldEqual, 0x9000)
		})

		Convey("Put cert 3", func(ctx C) {
			_, code, err := app.Send([]byte{0x00, 0xDA, 0x7F, 0x21, 0x06, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36})
			So(err, ShouldBeNil)
			So(code, ShouldEqual, 0x9000)
		})

		Convey("Select cert 4", func(ctx C) {
			_, code, err := app.Send([]byte{0x00, 0xA5, 0x03, 0x04, 0x06, 0x60, 0x04, 0x5C, 0x02, 0x7F, 0x21})
			So(err, ShouldBeNil)
			So(code, ShouldEqual, 0x6A86)
		})

		Convey("Put cert 1", func(ctx C) {
			_, code, err := app.Send([]byte{0x00, 0xDA, 0x7F, 0x21, 0x08, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38})
			So(err, ShouldBeNil)
			So(code, ShouldEqual, 0x9000)
		})

		Convey("Select cert 2", func(ctx C) {
			_, code, err := app.Send([]byte{0x00, 0xA5, 0x01, 0x04, 0x06, 0x60, 0x04, 0x5C, 0x02, 0x7F, 0x21})
			So(err, ShouldBeNil)
			So(code, ShouldEqual, 0x9000)
		})

		Convey("Put cert 2", func(ctx C) {
			_, code, err := app.Send(append([]byte{0x00, 0xDA, 0x7F, 0x21, 0x00, 0x03, 0xE8}, cert2...))
			So(err, ShouldBeNil)
			So(code, ShouldEqual, 0x9000)
		})

		Convey("Read cert 1", func(ctx C) {
			res, code, err := app.Send([]byte{0x00, 0xCA, 0x7F, 0x21, 0x00})
			So(err, ShouldBeNil)
			So(code, ShouldEqual, 0x9000)
			So(res, ShouldResemble, []byte{0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38})
		})

		Convey("Read next cert 2", func(ctx C) {
			res, code, err := app.Send([]byte{0x00, 0xCC, 0x7F, 0x21, 0x00})
			So(err, ShouldBeNil)
			So(code, ShouldEqual, 0x9000)
			So(res, ShouldResemble, cert2)
		})

		Convey("Select cert 3 again", func(ctx C) {
			_, code, err := app.Send([]byte{0x00, 0xA5, 0x02, 0x04, 0x06, 0x60, 0x04, 0x5C, 0x02, 0x7F, 0x21})
			So(err, ShouldBeNil)
			So(code, ShouldEqual, 0x9000)
		})

		Convey("Read cert 3", func(ctx C) {
			res, code, err := app.Send([]byte{0x00, 0xCA, 0x7F, 0x21, 0x00})
			So(err, ShouldBeNil)
			So(code, ShouldEqual, 0x9000)
			So(res, ShouldResemble, []byte{0x31, 0x32, 0x33, 0x34, 0x35, 0x36})
		})

		Convey("Read next cert 4", func(ctx C) {
			_, code, err := app.Send([]byte{0x00, 0xCC, 0x7F, 0x21, 0x00})
			So(err, ShouldBeNil)
			So(code, ShouldEqual, 0x6A88)
		})

		Convey("Select cert 1", func(ctx C) {
			_, code, err := app.Send([]byte{0x00, 0xA5, 0x00, 0x04, 0x06, 0x60, 0x04, 0x5C, 0x02, 0x7F, 0x21})
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
	})

}
