# Mixed CCID and WebUSB ownership vectors

See [runner instructions](../c312-ccid/README.md). Use the same command with
`--vectors tests/fixtures/c312-usb-ownership/vectors.json` and its sibling
`report.json` output. Each event polls CCID then WebUSB once; bulk IN is completed
after separate EP0 and bulk observations. Both runners use real applets and
production transport state machines. No response normalization is applied.

The18 cases cover408 events under this explicit serialized schedule: passive
slot/parameter queries during Hold, expired Hold, unfinished RX and unfetched
response; foreign6400 refusal and busy power; aborted reservation retaining
CCID PIN; actual takeover; refusal latched across abort and RX gaps; invalid
slot/RFU/power, oversized and truncated headers preserving foreign context.
No physical timing, HID, arbitrary IRQ races or CIU resource safety is inferred.
