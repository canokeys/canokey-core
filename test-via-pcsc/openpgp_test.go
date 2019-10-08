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

		Convey("Get Key Info", func(ctx C) {
			res, code, err := app.Send([]byte{0x00, 0xCA, 0x00, 0xDE, 0x00})
			So(err, ShouldBeNil)
			So(code, ShouldEqual, 0x9000)
			So(res, ShouldResemble, []byte{0x01, 0x00, 0x02, 0x00, 0x03, 0x00})
		})

		Convey("Get extended length info", func(ctx C) {
			res, code, err := app.Send([]byte{0x00, 0xCA, 0x7F, 0x66, 0x08})
			So(err, ShouldBeNil)
			So(code, ShouldEqual, 0x9000)
			So(res, ShouldResemble, []byte{2, 2, 5, 0, 2, 2, 5, 0})
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
		})

		certContent := [][]byte{
			{},
			{0x31, 0x32, 0x33, 0x34, 0x35, 0x36},
			cert2,
			{0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67},
		}
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
			_, code, err := app.Send(putCert(certContent[3]))
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
			res, code, err := app.Send([]byte{0x00, 0xCA, 0x7F, 0x21, 0x00})
			So(err, ShouldBeNil)
			So(code, ShouldEqual, 0x9000)
			So(res, ShouldResemble, certContent[1])
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
			So(res, ShouldResemble, certContent[3])
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

		Convey("Select cert 2 again", func(ctx C) {
			_, code, err := app.Send([]byte{0x00, 0xA5, 0x01, 0x04, 0x06, 0x60, 0x04, 0x5C, 0x02, 0x7F, 0x21})
			So(err, ShouldBeNil)
			So(code, ShouldEqual, 0x9000)
		})

		Convey("Read cert 2 again", func(ctx C) {
			res, code, err := app.Send([]byte{0x00, 0xCA, 0x7F, 0x21, 0x00})
			So(err, ShouldBeNil)
			So(code, ShouldEqual, 0x9000)
			So(res, ShouldResemble, certContent[2])
		})

		Convey("Read next cert 3", func(ctx C) {
			res, code, err := app.Send([]byte{0x00, 0xCC, 0x7F, 0x21, 0x00})
			So(err, ShouldBeNil)
			So(code, ShouldEqual, 0x9000)
			So(res, ShouldResemble, certContent[3])
		})

		Convey("Select non-existent cert", func(ctx C) {
			_, code, err := app.Send([]byte{0x00, 0xA5, 0x02, 0x04, 0x06, 0xFF, 0x04, 0x5C, 0x02, 0x7F, 0x21})
			So(err, ShouldBeNil)
			So(code, ShouldEqual, 0x6A80)
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
	})

}
