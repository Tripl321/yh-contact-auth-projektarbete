#!/usr/bin/env python3
"""SHALLOT — manuell felinjicering för USB-provisionering (testplan doc 13).

Talar nyckeldistributionsprotokollet direkt med EN mottagare (PAW/PLC)
via dess USB CDC-port, så att felscenarier blir deterministiska:
CRC-fel, partiella ramar, tappade ACK, dubblett-COMMIT, stale epoch,
fel sekvensnummer och nollnyckel.

Ramformat (ska matcha ShallotLoRaProtocol.h, SHALLOT_KD_*_LEN):
  HANDSHAKE  A1 target epoch_be4 seq            (7 B)
  READY      A2 devid[4] epoch_be4              (9 B)
  KEY_DATA   A3 len key[16] crc_be4 epoch seq   (27 B)
  STORED     A4 hash[4] epoch_be4               (9 B)
  COMMIT     A6 target epoch_be4                (6 B)

Säkerhet och förutsättningar:
  - UNO Q ska vara IDLE under körning (ingen samtidig distribution).
  - Öppna ALDRIG med 1200 baud (det återställer RP2040 till bootloader).
  - Om enheten startar om vid portöppning: provisionera om den först med
    normalflödet, utom i negativfallen där omstart är ett giltigt startläge.
  - Testnycklar genereras lokalt med os.urandom ENBART för dessa
    manuella testfall. Provisionera alltid om med UNO Q-TRNG efteråt.
"""

import argparse
import binascii
import hashlib
import os
import sys
import time

import serial

HS, READY, KD, STORED, COMMIT = 0xA1, 0xA2, 0xA3, 0xA4, 0xA6
TARGETS = {'plc': (0x01, b'PLC\x01'), 'paw': (0x02, b'PAW\x01')}
PHASE_TIMEOUT = 12.0  # mottagarens 10 s + marginal


def crc(data):
    return binascii.crc32(bytes(data)) & 0xFFFFFFFF


def fingerprint(key):
    return hashlib.sha256(bytes(key)).digest()[:4]


class Peer:
    def __init__(self, port, target, baud=115200):
        self.target_id, self.dev_id = TARGETS[target]
        self.ser = serial.Serial(port, baud, timeout=0.1)
        time.sleep(2.5)  # USB ska sätta sig; ev. omstart hinner klart
        pending = self.ser.read(4096)
        if b'Firmware' in pending or b'Key Authority' in pending:
            print('[!] Enheten startade om vid portöppning. '
                  'Provisionera om den först vid behov.')
        self.ser.reset_input_buffer()

    def close(self):
        self.ser.close()

    def wr(self, data):
        self.ser.write(bytes(data))
        self.ser.flush()

    def read_frame(self, tag, length, timeout=PHASE_TIMEOUT):
        """Taggankrad läsning likt mottagaren: skippa stray bytes."""
        buf = bytearray()
        end = time.time() + timeout
        while time.time() < end:
            chunk = self.ser.read(max(1, length - len(buf)))
            if chunk:
                buf += chunk
            while len(buf) >= 1 and buf[0] != tag:
                del buf[0]
            if len(buf) >= length:
                frame = bytes(buf[:length])
                del buf[:length]
                return frame
        return None

    def handshake(self, epoch, seq):
        self.wr(bytes([HS, self.target_id]) +
                epoch.to_bytes(4, 'big') + bytes([seq]))

    def expect_ready(self, epoch):
        f = self.read_frame(READY, 9)
        if f is None:
            return False
        return f[1:5] == self.dev_id and int.from_bytes(f[5:9], 'big') == epoch

    def keydata(self, key, epoch, seq, corrupt_at=None, split_at=None):
        data = bytearray(bytes([KD, len(key)]) + bytes(key) +
                         crc(key).to_bytes(4, 'big') +
                         epoch.to_bytes(4, 'big') + bytes([seq]))
        if corrupt_at is not None:
            data[corrupt_at] ^= 0xFF
        if split_at is None:
            self.wr(data)
        else:
            self.wr(data[:split_at])
            time.sleep(1.0)
            self.wr(data[split_at:])

    def expect_stored(self, epoch, key=None):
        f = self.read_frame(STORED, 9)
        if f is None:
            return None
        if int.from_bytes(f[5:9], 'big') != epoch:
            return None
        if key is not None and f[1:5] != fingerprint(key):
            return None
        return f[1:5]

    def commit(self, epoch):
        self.wr(bytes([COMMIT, self.target_id]) + epoch.to_bytes(4, 'big'))


def check(name, cond):
    print(('  [OK] ' if cond else '  [FAIL] ') + name)
    return cond


def case_crc(peer, epoch):
    print('Fall: CRC-fel + retry')
    key = os.urandom(16)
    peer.handshake(epoch, 0)
    ok = check('READY mottagen', peer.expect_ready(epoch))
    peer.keydata(key, epoch, 0, corrupt_at=5)
    ok &= check('ingen STORED för korrupt ram', peer.expect_stored(epoch) is None)
    peer.keydata(key, epoch, 0)
    ok &= check('STORED efter korrekt retry', peer.expect_stored(epoch, key) is not None)
    return ok


def case_zero(peer, epoch):
    print('Fall: nollnyckel avvisas')
    peer.handshake(epoch, 0)
    ok = check('READY mottagen', peer.expect_ready(epoch))
    peer.keydata(bytes(16), epoch, 0)  # giltig CRC för nollor
    ok &= check('ingen STORED för nollnyckel', peer.expect_stored(epoch) is None)
    key = os.urandom(16)
    peer.keydata(key, epoch, 0)
    ok &= check('STORED efter giltig nyckel', peer.expect_stored(epoch, key) is not None)
    return ok


def case_partial(peer, epoch):
    print('Fall: partiell ram')
    key = os.urandom(16)
    peer.handshake(epoch, 0)
    ok = check('READY mottagen', peer.expect_ready(epoch))
    peer.keydata(key, epoch, 0, split_at=10)
    ok &= check('STORED efter komplett ram', peer.expect_stored(epoch, key) is not None)
    return ok


def case_stale(peer):
    print('Fall: stale epoch avvisas')
    peer.handshake(0, 0)
    ok = check('ingen READY för epoch 0', not peer.expect_ready(0))
    return ok


def case_wrongseq(peer, epoch):
    print('Fall: fel sekvensnummer droppas')
    key = os.urandom(16)
    peer.handshake(epoch, 0)
    ok = check('READY mottagen', peer.expect_ready(epoch))
    peer.keydata(key, epoch, 7)
    ok &= check('ingen STORED för fel seq', peer.expect_stored(epoch) is None)
    peer.keydata(key, epoch, 0)
    ok &= check('STORED för rätt seq', peer.expect_stored(epoch, key) is not None)
    return ok


def case_drop_ready(peer, epoch):
    print('Fall: tappad READY (duplikat-handshake)')
    key = os.urandom(16)
    peer.handshake(epoch, 0)
    got1 = peer.expect_ready(epoch)
    ok = check('READY 1 mottagen (ignoreras)', got1)
    peer.handshake(epoch, 1)  # READY "tappad": skicka om med seq+1
    ok &= check('READY 2 (omsändning) mottagen', peer.expect_ready(epoch))
    peer.keydata(key, epoch, 1)
    ok &= check('STORED för seq 1', peer.expect_stored(epoch, key) is not None)
    return ok


def case_drop_stored(peer, epoch):
    print('Fall: tappad STORED (duplikat key-data)')
    key = os.urandom(16)
    peer.handshake(epoch, 0)
    ok = check('READY mottagen', peer.expect_ready(epoch))
    peer.keydata(key, epoch, 0)
    first = peer.expect_stored(epoch, key)
    ok &= check('STORED 1 mottagen (ignoreras)', first is not None)
    peer.keydata(key, epoch, 0)  # STORED "tappad": skicka om samma seq
    second = peer.expect_stored(epoch, key)
    ok &= check('STORED 2 (omsändning) mottagen', second is not None)
    ok &= check('samma fingerprint båda gångerna', first == second)
    return ok


def case_dupcommit(peer, epoch):
    print('Fall: dubblett-COMMIT (kräver provisionerad enhet)')
    peer.commit(epoch)
    first = peer.expect_stored(epoch)
    ok = check('ack 1 mottagen', first is not None)
    peer.commit(epoch)
    second = peer.expect_stored(epoch)
    ok &= check('ack 2 (omsändning) mottagen', second is not None)
    ok &= check('samma hash, tillstånd oförändrat',
                first is not None and first == second)
    return ok


CASES = {
    'crc': case_crc,
    'zero': case_zero,
    'partial': case_partial,
    'stale': case_stale,
    'wrongseq': case_wrongseq,
    'drop-ready': case_drop_ready,
    'drop-stored': case_drop_stored,
    'dupcommit': case_dupcommit,
}


def main():
    ap = argparse.ArgumentParser(description='Manuell felinjicering: USB-provisionering')
    ap.add_argument('--port', required=True, help='mottagarens CDC-port')
    ap.add_argument('--target', required=True, choices=('plc', 'paw'))
    ap.add_argument('--case', required=True, choices=sorted(CASES))
    ap.add_argument('--epoch', type=int, default=1)
    ap.add_argument('--baud', type=int, default=115200)
    args = ap.parse_args()

    peer = Peer(args.port, args.target, args.baud)
    try:
        passed = CASES[args.case](peer, args.epoch)
    finally:
        peer.close()
    print('RESULTAT: ' + ('GODKÄND' if passed else 'UNDERKÄND'))
    return 0 if passed else 1


if __name__ == '__main__':
    sys.exit(main())
