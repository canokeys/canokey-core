# SPDX-License-Identifier: Apache-2.0
"""Shared JSONL/corpus event contract for seed generation and differential replay."""
import json
from pathlib import Path

TAG_APDU = 0x00
TAG_SLOT_POWER = 0x01
TAG_STORAGE_FAULT = 0x02
TAG_RESET = 0x03
TAG_APDU_RAW = 0x04
MAX_APDU_LEN = 4096
Event = tuple[str, bytes]
TAGS = {TAG_APDU: "apdu", TAG_SLOT_POWER: "poweroff",
        TAG_STORAGE_FAULT: "storage_fault", TAG_RESET: "reset", TAG_APDU_RAW: "apdu_raw"}
CONTROLS = {"POWEROFF": "poweroff", "SLOT_POWER": "poweroff", "RESET": "reset"}


def validate(event: Event) -> Event:
    kind, payload = event
    if kind in ("apdu", "apdu_raw"):
        if not payload or len(payload) > MAX_APDU_LEN:
            raise ValueError("APDU must contain 1..4096 bytes")
    elif kind in ("poweroff", "reset"):
        if payload:
            raise ValueError(f"{kind} must have an empty payload")
    elif kind == "storage_fault":
        if len(payload) != 2 or payload[1] not in (0, 1):
            raise ValueError("storage_fault requires record ID and read/write operation")
    else:
        raise ValueError(f"unknown event: {kind}")
    return event


def decode_record(record) -> Event:
    if not isinstance(record, dict):
        raise ValueError("event must be an object")
    if "control" in record:
        if "apdu" in record or "event" in record or record["control"] not in CONTROLS:
            raise ValueError("unknown or ambiguous control event")
        return validate((CONTROLS[record["control"]], b""))
    kind = record.get("event", "apdu" if "apdu" in record else None)
    field = "apdu" if kind in ("apdu", "apdu_raw") else "payload"
    if kind not in ("apdu", "apdu_raw") and "apdu" in record:
        raise ValueError("ambiguous APDU/control event")
    value = record.get(field, "" if kind in ("poweroff", "reset") else None)
    if not isinstance(value, str):
        raise ValueError(f"{field} must be hexadecimal text")
    return validate((kind, bytes.fromhex(value)))


def encode_record(event: Event) -> dict:
    kind, payload = validate(event)
    return {"event": kind, "apdu" if kind in ("apdu", "apdu_raw") else "payload": payload.hex()}


def read_trace(path: Path) -> list[Event]:
    events = []
    for number, line in enumerate(path.read_text().splitlines(), 1):
        if line.strip():
            try:
                events.append(decode_record(json.loads(line)))
            except (ValueError, TypeError) as error:
                raise ValueError(f"{path}:{number}: {error}") from error
    if not events:
        raise ValueError("empty event sequence")
    return events


def write_trace(path: Path, events: list[Event]) -> None:
    path.write_text("".join(json.dumps(encode_record(event)) + "\n" for event in events))


def decode_corpus(data: bytes) -> list[Event]:
    events = []
    offset = 0
    while offset < len(data):
        if len(data) - offset < 3:
            raise ValueError(f"truncated frame header at {offset}")
        tag = data[offset]
        length = int.from_bytes(data[offset + 1:offset + 3], "little")
        offset += 3
        if tag not in TAGS:
            raise ValueError(f"unknown corpus tag 0x{tag:02X}")
        if length > len(data) - offset:
            raise ValueError(f"truncated frame payload at {offset}")
        events.append(validate((TAGS[tag], data[offset:offset + length])))
        offset += length
    if not events:
        raise ValueError("empty event sequence")
    return events


def frame(tag: int, payload: bytes) -> bytes:
    if tag not in TAGS:
        raise ValueError(f"unknown corpus tag 0x{tag:02X}")
    validate((TAGS[tag], payload))
    return bytes([tag]) + len(payload).to_bytes(2, "little") + payload


def replay_command(event: Event) -> str:
    kind, payload = validate(event)
    if kind == "apdu":
        return payload.hex()
    if kind == "apdu_raw":
        return "!RAW " + payload.hex()
    if kind == "storage_fault":
        return f"!FAIL_{'WRITE' if payload[1] == 0 else 'READ'} {payload[0]}"
    return {"poweroff": "!POWEROFF", "reset": "!RESET"}[kind]
