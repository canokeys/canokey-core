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

type Applet struct {
	context *scard.Context
	card    *scard.Card
}

var defaultNDEF = append([]byte{0x00, 0x11, 0xD1, 0x01, 0x0D, 0x55, 0x04, 'c', 'a', 'n', 'o', 'k', 'e', 'y', 's', '.', 'o', 'r', 'g'},
	make([]byte, 1005)...)
var currentNDEF = make([]byte, len(defaultNDEF))
var defaultCC = []byte{0, 15, 32, 4, 0, 4, 0, 4, 6, 0, 1, 4, 0, 0, 0}

func New() (*Applet, error) {

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
			if strings.Contains(reader, "Canokey") {
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

		return &Applet{
			card:    card,
			context: context,
		}, nil
	}
	context.Release()
	return nil, fmt.Errorf(errFailedToListSuitableReader, len(readers))
}
func (o *Applet) Close() error {
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
func (o *Applet) Send(apdu []byte) ([]byte, uint16, error) {
	res, err := o.card.Transmit(apdu)

	if err != nil {
		return nil, 0, errors.Wrapf(err, errFailedToTransmit)
	}
	return res[0 : len(res)-2], (uint16(res[len(res)-2])<<8 | uint16(res[len(res)-1])), nil
}

func commandTests(readOnlyMode bool, app *Applet) func(C) {
	maxLen := uint16(1024)
	selectFile := func(name uint16) uint16 {
		_, code, err := app.Send([]byte{0x00, 0xA4, 0x00, 0x0C, 0x02, byte(name >> 8), byte(name & 0xFF)})
		So(err, ShouldBeNil)
		return code
	}
	readFile := func(offset uint16, len uint16) (data []byte, code uint16) {
		So(len, ShouldBeGreaterThan, 0)
		data, code, err := app.Send([]byte{0x00, 0xB0, byte(offset >> 8), byte(offset & 0xFF), 0x00, byte(len >> 8), byte(len & 0xFF)})
		So(err, ShouldBeNil)
		return
	}
	writeFile := func(offset uint16, data []byte) (code uint16) {
		len := len(data)
		So(len, ShouldBeGreaterThan, 0)
		_, code, err := app.Send(append(
			[]byte{0x00, 0xD6, byte(offset >> 8), byte(offset & 0xFF),
				0x00, byte(len >> 8), byte(len & 0xFF)},
			data...))
		So(err, ShouldBeNil)
		return
	}
	return func(ctx C) {

		_, code, err := app.Send([]byte{0x00, 0xA4, 0x04, 0x00, 0x07, 0xD2, 0x76, 0x00, 0x00, 0x85, 0x01, 0x01})
		So(err, ShouldBeNil)
		So(code, ShouldEqual, 0x9000)

		Convey("If nothing is selected", func(ctx C) {
			_, code := readFile(0, 1)
			So(code, ShouldEqual, 0x6985)
			code = writeFile(0, []byte{0x00, 0xA4, 0x04})
			So(code, ShouldEqual, 0x6985)
		})
		Convey("Select an invalid file", func(ctx C) {
			code := selectFile(0xE101)
			So(code, ShouldEqual, 0x6A82)
			code = selectFile(0x0003)
			So(code, ShouldEqual, 0x6A82)
		})
		Convey("Read/Write none", func(ctx C) {
			code := selectFile(0x0001)
			So(code, ShouldEqual, 0x9000)
			data, code, err := app.Send([]byte{0x00, 0xB0, 0x00, 0x00})
			So(err, ShouldBeNil)
			So(code, ShouldEqual, 0x9000)
			So(len(data), ShouldEqual, 0)
			data, code, err = app.Send([]byte{0x00, 0xB0, byte(maxLen >> 8), byte(maxLen & 0xFF)})
			So(err, ShouldBeNil)
			So(code, ShouldEqual, 0x9000)
			So(len(data), ShouldEqual, 0)
			if !readOnlyMode {
				_, code, err = app.Send([]byte{0x00, 0xD6, 0x00, 0x00})
				So(err, ShouldBeNil)
				So(code, ShouldEqual, 0x9000)
				_, code, err = app.Send([]byte{0x00, 0xD6, byte(maxLen >> 8), byte(maxLen & 0xFF)})
				So(err, ShouldBeNil)
				So(code, ShouldEqual, 0x9000)
			}
		})
		Convey("Read/Write CC", func(ctx C) {
			cc := defaultCC
			if readOnlyMode {
				cc[14] = 0xFF
			} else {
				cc[14] = 0
			}
			code := selectFile(0xE103)
			So(code, ShouldEqual, 0x9000)
			data, code := readFile(0, 15)
			// fmt.Println(data)
			So(code, ShouldEqual, 0x9000)
			So(data, ShouldResemble, cc)
			code = writeFile(0, []byte("anything"))
			So(code, ShouldEqual, 0x6985)
			data, code = readFile(0, 15)
			So(code, ShouldEqual, 0x9000)
			So(data, ShouldResemble, cc)
		})
		Convey("Read/Write NDEF", func(ctx C) {
			code := selectFile(0x0001)
			So(code, ShouldEqual, 0x9000)
			data, code := readFile(0, uint16(len(currentNDEF)))
			// fmt.Println(data)
			So(code, ShouldEqual, 0x9000)
			So(data, ShouldResemble, currentNDEF)
			newData := []byte("anything")
			code = writeFile(0, newData)
			if readOnlyMode {
				So(code, ShouldEqual, 0x6982)
			} else {
				So(code, ShouldEqual, 0x9000)
				copy(currentNDEF[0:len(newData)], newData)

				code = writeFile(1, []byte{0xAA})
				So(code, ShouldEqual, 0x9000)
				currentNDEF[1] = 0xAA
				data, code = readFile(0, 2)
				So(code, ShouldEqual, 0x9000)
				So(data, ShouldResemble, currentNDEF[0:2])
				data, code = readFile(3, 1)
				So(code, ShouldEqual, 0x9000)
				So(data, ShouldResemble, currentNDEF[3:4])
			}
		})
		Convey("Limit data size", func(ctx C) {
			if readOnlyMode {
				return
			}
			code := selectFile(0x0001)
			So(code, ShouldEqual, 0x9000)

			largest := make([]byte, maxLen)
			crand.Read(largest)
			code = writeFile(1, largest)
			So(code, ShouldEqual, 0x6700)
			code = writeFile(maxLen, []byte{0x00})
			So(code, ShouldEqual, 0x6700)
			code = writeFile(0, append(largest, 0x00))
			So(code, ShouldEqual, 0x6700)

			data, code := readFile(maxLen, 1)
			So(code, ShouldEqual, 0x6700)
			data, code = readFile(0, maxLen+1)
			So(code, ShouldEqual, 0x6700)
			data, code = readFile(1, maxLen)
			So(code, ShouldEqual, 0x6700)
			data, code = readFile(0x8001, 0x8000)
			So(code, ShouldEqual, 0x6700)

			code = writeFile(0, largest)
			So(code, ShouldEqual, 0x9000)
			currentNDEF = largest
			data, code = readFile(0, maxLen)
			So(code, ShouldEqual, 0x9000)
			So(data, ShouldResemble, currentNDEF)
			data, code = readFile(maxLen-1, 1)
			So(code, ShouldEqual, 0x9000)
			So(data, ShouldResemble, currentNDEF[maxLen-1:maxLen])
		})
	}
}

func updateOptions(app *Applet, option int, state byte) {

	_, code, err := app.Send([]byte{0x00, 0xA4, 0x04, 0x00, 0x05, 0xF0, 0x00, 0x00, 0x00, 0x00})
	So(err, ShouldBeNil)
	So(code, ShouldEqual, 0x9000)

	pin := []byte{0x31, 0x32, 0x33, 0x34, 0x35, 0x36}
	_, code, err = app.Send(append([]byte{0x00, 0x20, 0x00, 0x00, byte(len(pin))}, pin...))
	So(err, ShouldBeNil)
	So(code, ShouldEqual, 0x9000)

	if option == 1 {
		_, code, err = app.Send([]byte{0x00, 0x08, state, 0x00})
	} else if option == 2 {
		_, code, err = app.Send([]byte{0x00, 0x40, 0x04, state})
	}
	So(err, ShouldBeNil)
	if state < 2 {
		So(code, ShouldEqual, 0x9000)
	} else {
		So(code, ShouldEqual, 0x6A86)
	}
}

func resetNDEF(app *Applet) {

	_, code, err := app.Send([]byte{0x00, 0xA4, 0x04, 0x00, 0x05, 0xF0, 0x00, 0x00, 0x00, 0x00})
	So(err, ShouldBeNil)
	So(code, ShouldEqual, 0x9000)

	pin := []byte{0x31, 0x32, 0x33, 0x34, 0x35, 0x36}
	_, code, err = app.Send(append([]byte{0x00, 0x20, 0x00, 0x00, byte(len(pin))}, pin...))
	So(err, ShouldBeNil)
	So(code, ShouldEqual, 0x9000)

	_, code, err = app.Send([]byte{0x00, 0x07, 0x00, 0x00})
	So(err, ShouldBeNil)
	So(code, ShouldEqual, 0x9000)
}

func TestNDEFApplet(t *testing.T) {
	resetOnce := false
	copy(currentNDEF, defaultNDEF)

	Convey("Connecting to applet", t, func(ctx C) {

		app, err := New()
		So(err, ShouldBeNil)
		defer app.Close()

		Convey("NDEF applet behaves correctly", func(ctx C) {

			Convey("When it is not read-only", func(ctx C) {
				updateOptions(app, 1, 0)
				(commandTests(false, app))(ctx)
			})

			Convey("When it is read-only", func(ctx C) {
				updateOptions(app, 1, 1)
				(commandTests(true, app))(ctx)
			})

			Convey("When it is disabled", func(ctx C) {
				updateOptions(app, 2, 0)
				_, code, err := app.Send([]byte{0x00, 0xA4, 0x04, 0x00, 0x07, 0xD2, 0x76, 0x00, 0x00, 0x85, 0x01, 0x01})
				So(err, ShouldBeNil)
				So(code, ShouldEqual, 0x6A82)

				updateOptions(app, 2, 1)
				_, code, err = app.Send([]byte{0x00, 0xA4, 0x04, 0x00, 0x07, 0xD2, 0x76, 0x00, 0x00, 0x85, 0x01, 0x01})
				So(err, ShouldBeNil)
				So(code, ShouldEqual, 0x9000)
				_, code, err = app.Send([]byte{0x00, 0xA4, 0x04, 0x00, 0x06, 0xD2, 0x76, 0x00, 0x00, 0x85, 0x01})
				So(err, ShouldBeNil)
				So(code, ShouldEqual, 0x6A82)
			})

			Convey("After reset", func(ctx C) {
				if !resetOnce {
					resetNDEF(app)
					copy(currentNDEF, defaultNDEF)
					resetOnce = true
				}
				(commandTests(false, app))(ctx)
				updateOptions(app, 1, 9)
			})

			Convey("Reset twice", func(ctx C) {
				resetNDEF(app)
				copy(currentNDEF, defaultNDEF)
			})
		})
	})

}
