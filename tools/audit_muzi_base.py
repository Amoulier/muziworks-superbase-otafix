#!/usr/bin/env python3
"""Fail closed if Muzi Base OTAFIX release artifacts violate the flash contract."""

from __future__ import annotations

import argparse
import hashlib
import json
import struct
import sys
import zipfile
from pathlib import Path

from intelhex import IntelHex


UF2_MAGIC_START0 = 0x0A324655
UF2_MAGIC_START1 = 0x9E5D5157
UF2_MAGIC_END = 0x0AB16F30
UF2_FLAG_FAMILY_ID = 0x00002000
UF2_BOOTLOADER_FAMILY = 0xD663823C

MBR_START = 0x00000000
MBR_END = 0x00001000
SOFTDEVICE_START = 0x00001000
SOFTDEVICE_END = 0x00026000
APPLICATION_START = 0x00026000
BOOTLOADER_START = 0x000F4000
BOOTLOADER_CONFIG_START = 0x000FD800
MBR_PARAMS_START = 0x000FE000
BOOTLOADER_SETTINGS_START = 0x000FF000
FLASH_END = 0x00100000
UICR_START = 0x10001000
UICR_END = 0x10001400
UICR_BOOTLOADER_ADDR = 0x10001014
UICR_MBR_PARAMS_ADDR = 0x10001018

EXPECTED_BOARD_TOKENS = {
    "board.h": (
        '#define UICR_REGOUT0_VALUE UICR_REGOUT0_VOUT_3V3',
        '#define LED_PRIMARY_PIN _PINNUM(1, 4)',
        '#define LED_SECONDARY_PIN _PINNUM(1, 3)',
        '#define USB_DESC_VID 0x239A',
        '#define USB_DESC_UF2_PID 0x0081',
        '#define UF2_BOARD_ID "muzi-Base-Board"',
    ),
    "board.mk": (
        "MCU_SUB_VARIANT = nrf52840",
        "CFLAGS += -DDEVICE_NAME='\"MUZI_DFU\"'",
    ),
    "pinconfig.c": (
        "204, 0x100000",
        "205, 0x40000",
        "209, 0xada52840",
    ),
}


def fail(message: str) -> None:
    raise RuntimeError(message)


def one(directory: Path, pattern: str) -> Path:
    matches = sorted(directory.glob(pattern))
    if len(matches) != 1:
        fail(f"expected exactly one {pattern}, found {len(matches)}")
    return matches[0]


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def verify_board_definition(repo: Path) -> None:
    board_dir = repo / "src/boards/muzi_base"
    for filename, tokens in EXPECTED_BOARD_TOKENS.items():
        content = (board_dir / filename).read_text(encoding="utf-8")
        for token in tokens:
            if token not in content:
                fail(f"{filename} is missing required token: {token}")


def verify_uf2(path: Path) -> dict[int, int]:
    raw = path.read_bytes()
    if not raw or len(raw) % 512:
        fail("UF2 size is not a non-zero multiple of 512 bytes")

    payload: dict[int, int] = {}
    block_numbers: set[int] = set()
    declared_total: int | None = None

    for offset in range(0, len(raw), 512):
        block = raw[offset : offset + 512]
        magic0, magic1, flags, address, size, number, total, family = struct.unpack_from("<8I", block)
        magic_end = struct.unpack_from("<I", block, 508)[0]
        if (magic0, magic1, magic_end) != (UF2_MAGIC_START0, UF2_MAGIC_START1, UF2_MAGIC_END):
            fail(f"invalid UF2 magic in block {offset // 512}")
        if flags != UF2_FLAG_FAMILY_ID or family != UF2_BOOTLOADER_FAMILY:
            fail(f"unexpected UF2 flags/family in block {number}: {flags:#x}/{family:#x}")
        if size != 256:
            fail(f"unexpected payload size in block {number}: {size}")
        if number in block_numbers:
            fail(f"duplicate UF2 block number {number}")
        block_numbers.add(number)
        declared_total = total if declared_total is None else declared_total
        if total != declared_total:
            fail("inconsistent UF2 total block count")

        end = address + size
        allowed = (MBR_START <= address and end <= MBR_END) or (
            BOOTLOADER_START <= address and end <= MBR_PARAMS_START
        ) or (UICR_START <= address and end <= UICR_END)
        if not allowed:
            fail(f"UF2 writes outside approved regions: {address:#x}-{end:#x}")
        if address < BOOTLOADER_START and end > MBR_END:
            fail("UF2 overlaps SoftDevice or application flash")
        if address < FLASH_END and end > MBR_PARAMS_START:
            fail("UF2 overwrites MBR parameters or bootloader settings")

        for index, value in enumerate(block[32 : 32 + size]):
            absolute = address + index
            if absolute in payload:
                fail(f"overlapping UF2 payload at {absolute:#x}")
            payload[absolute] = value

    if declared_total != len(block_numbers) or block_numbers != set(range(declared_total or 0)):
        fail("UF2 block sequence is incomplete")

    def word(address: int) -> int:
        try:
            return int.from_bytes(bytes(payload[address + offset] for offset in range(4)), "little")
        except KeyError as exc:
            fail(f"UF2 is missing required UICR word at {address:#x}")
            raise AssertionError from exc

    if word(UICR_BOOTLOADER_ADDR) != BOOTLOADER_START:
        fail("UF2 programs the wrong bootloader start address")
    if word(UICR_MBR_PARAMS_ADDR) != MBR_PARAMS_START:
        fail("UF2 programs the wrong MBR parameter address")
    if not any(BOOTLOADER_START <= address < BOOTLOADER_CONFIG_START for address in payload):
        fail("UF2 contains no bootloader payload")
    if not any(BOOTLOADER_CONFIG_START <= address < MBR_PARAMS_START for address in payload):
        fail("UF2 contains no Muzi bootloader configuration")
    return payload


def verify_combined_hex(path: Path) -> None:
    image = IntelHex(str(path))
    segments = image.segments()
    if not any(start <= MBR_START and end > MBR_START for start, end in segments):
        fail("combined HEX is missing the MBR")
    if not any(start <= SOFTDEVICE_START and end > SOFTDEVICE_START for start, end in segments):
        fail("combined HEX is missing S140")
    if not any(start <= BOOTLOADER_START and end > BOOTLOADER_START for start, end in segments):
        fail("combined HEX is missing the bootloader")
    for start, end in segments:
        if start < BOOTLOADER_START and end > APPLICATION_START:
            fail(f"combined HEX unexpectedly writes application flash: {start:#x}-{end:#x}")
    if image.gets(UICR_BOOTLOADER_ADDR, 4) != BOOTLOADER_START.to_bytes(4, "little"):
        fail("combined HEX contains the wrong UICR bootloader address")
    if image.gets(UICR_MBR_PARAMS_ADDR, 4) != MBR_PARAMS_START.to_bytes(4, "little"):
        fail("combined HEX contains the wrong UICR MBR parameter address")


def verify_serial_package(path: Path) -> None:
    with zipfile.ZipFile(path) as archive:
        bad_file = archive.testzip()
        if bad_file:
            fail(f"recovery ZIP CRC failed for {bad_file}")
        if set(archive.namelist()) != {"manifest.json", "sd_bl.bin", "sd_bl.dat"}:
            fail("recovery ZIP contains an unexpected file set")
        manifest = json.loads(archive.read("manifest.json"))["manifest"]["softdevice_bootloader"]
        if manifest["bin_file"] != "sd_bl.bin" or manifest["dat_file"] != "sd_bl.dat":
            fail("recovery ZIP manifest filenames do not match payloads")
        init = manifest["init_packet_data"]
        if init["device_type"] != 82 or init["device_revision"] != 52840:
            fail("recovery ZIP targets the wrong Nordic device")
        if init["softdevice_req"] != [0xFFFE]:
            fail("recovery ZIP has an unexpected SoftDevice requirement")
        binary_size = len(archive.read("sd_bl.bin"))
        if binary_size != manifest["sd_size"] + manifest["bl_size"]:
            fail("recovery ZIP size does not match its manifest")
        if len(archive.read("sd_bl.dat")) != 14:
            fail("recovery ZIP init packet has an unexpected size")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--artifact-dir", type=Path, required=True)
    parser.add_argument("--repo", type=Path, default=Path(__file__).resolve().parents[1])
    args = parser.parse_args()

    verify_board_definition(args.repo)
    uf2 = one(args.artifact_dir, "update-muzi_base_bootloader-*_nosd.uf2")
    combined_hex = one(args.artifact_dir, "muzi_base_bootloader-*_s140_6.1.1.hex")
    serial_zip = one(args.artifact_dir, "muzi_base_bootloader-*_s140_6.1.1.zip")
    verify_uf2(uf2)
    verify_combined_hex(combined_hex)
    verify_serial_package(serial_zip)

    print("Muzi Base OTAFIX artifact audit: PASS")
    for artifact in (uf2, combined_hex, serial_zip):
        print(f"SHA256  {sha256(artifact)}  {artifact.name}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (KeyError, OSError, RuntimeError, ValueError, zipfile.BadZipFile) as error:
        print(f"Muzi Base OTAFIX artifact audit: FAIL: {error}", file=sys.stderr)
        raise SystemExit(1)
