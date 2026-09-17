#!/usr/bin/env python3
# SHALLOT relay bridge: MCU monitor proxy (127.0.0.1:7500) <-> PLC/PAW USB CDC.
#
# Both directions carry printable-ASCII debug on the same line as the protocol.
# Debug bytes are < 0x80; protocol tags are >= 0xA1, so we forward only frames.
#
# MCU -> device frames:
#   0xA1 HANDSHAKE  7   [1]=target
#   0xA3 KEY_DATA   27  no target -> current exchange target
#   0xA5 ERROR      1   no target -> current exchange target
#   0xA6 COMMIT     6   [1]=target
#   0xA7 CANCEL     6   [1]=target
#   0xB4 ID_CHALLENGE 39 [34]=target
# device -> MCU frames:
#   0xA2 READY 9, 0xA4 STORED 9, 0xA5 ERROR 1, 0xB5 ID_RESPONSE 69
import os, socket, termios, select, sys, time

MCU = ("127.0.0.1", 7500)
PORTS = {
    1: "/dev/serial/by-id/usb-Raspberry_Pi_Pico_2_AD501B5D51AD1DFA-if00",        # PLC (Pico 2)
    2: "/dev/serial/by-id/usb-Adafruit_Feather_RP2350_HSTX_48F1F06C7460AE5E-if00",  # PAW (Feather)
}
MCU_FRAME = {0xA1: 7, 0xA3: 27, 0xA5: 1, 0xA6: 6, 0xA7: 6, 0xB4: 39}
DEV_FRAME = {0xA2: 9, 0xA4: 9, 0xA5: 1, 0xB5: 69}


def open_serial(path):
    fd = os.open(path, os.O_RDWR | os.O_NOCTTY | os.O_NONBLOCK)
    a = termios.tcgetattr(fd)
    a[0] = 0
    a[1] = 0
    a[2] = termios.CS8 | termios.CREAD | termios.CLOCAL
    a[3] = 0
    a[4] = a[5] = termios.B115200
    a[6][termios.VMIN] = 0
    a[6][termios.VTIME] = 0
    termios.tcsetattr(fd, termios.TCSANOW, a)
    return fd


def probe():
    for t, p in PORTS.items():
        fd = open_serial(p)
        out = bytearray()
        tt = time.time()
        while time.time() - tt < 2.0:
            r, _, _ = select.select([fd], [], [], 0.2)
            if r:
                try:
                    out += os.read(fd, 4096)
                except OSError:
                    pass
        os.close(fd)
        sys.stdout.write("PROBE dev%d %s len=%d | %s\n" % (t, p, len(out), bytes(out).hex(" ")))


def route_target(tag, frame, current):
    if tag == 0xB4:
        return frame[34]
    if tag in (0xA1, 0xA6, 0xA7):
        return frame[1]
    return current


def main():
    s = socket.create_connection(MCU)
    s.setblocking(False)
    mcu_raw = open("/tmp/mcu_raw.bin", "wb")
    dev_raw = open("/tmp/dev_raw.bin", "wb")
    devs = {}
    for t, p in PORTS.items():
        try:
            devs[t] = open_serial(p)
        except OSError as e:
            print("open %s failed: %s" % (p, e), flush=True)
            devs[t] = None
    mcu_buf = bytearray()
    dev_buf = {t: bytearray() for t in devs}
    current_target = None
    print("relay up: mcu=%s devs=%s" % (MCU, {t: p for t, p in PORTS.items()}), flush=True)

    def reopen(t):
        old = devs.get(t)
        if old is not None:
            try:
                os.close(old)
            except OSError:
                pass
        try:
            devs[t] = open_serial(PORTS[t])
            dev_buf[t] = bytearray()
            print("dev%d reopened %s" % (t, PORTS[t]), flush=True)
        except OSError as e:
            devs[t] = None
            print("dev%d reopen failed: %s" % (t, e), flush=True)

    while True:
        live = [fd for fd in devs.values() if fd is not None]
        try:
            r, _, _ = select.select([s] + live, [], [], 0.2)
        except OSError:
            r = []
        if s in r:
            try:
                data = s.recv(4096)
            except BlockingIOError:
                data = None
            if data is not None and data == b"":
                print("mcu monitor closed", flush=True)
                break
            if data:
                mcu_raw.write(data)
                mcu_raw.flush()
                mcu_buf += data
            while mcu_buf:
                if mcu_buf[0] not in MCU_FRAME:
                    del mcu_buf[0]
                    continue
                ln = MCU_FRAME[mcu_buf[0]]
                if len(mcu_buf) < ln:
                    break
                tag = mcu_buf[0]
                frame = bytes(mcu_buf[:ln])
                del mcu_buf[:ln]
                target = route_target(tag, frame, current_target)
                if target in devs:
                    current_target = target
                fd = devs.get(target)
                if fd is None:
                    print("MCU->dev? unknown target %s frame=%s" % (target, frame.hex()), flush=True)
                else:
                    try:
                        os.write(fd, frame)
                        print("MCU->dev%d tag=%02x %s" % (target, tag, frame.hex()), flush=True)
                    except OSError as e:
                        print("dev%d write EIO (%s), reopening" % (target, e), flush=True)
                        reopen(target)
        for t in list(devs):
            fd = devs[t]
            if fd is None:
                reopen(t)
                continue
            try:
                rr, _, _ = select.select([fd], [], [], 0)
            except OSError:
                reopen(t)
                continue
            if rr:
                try:
                    d = os.read(fd, 4096)
                except OSError as e:
                    print("dev%d read EIO (%s), reopening" % (t, e), flush=True)
                    reopen(t)
                    continue
                if d:
                    dev_raw.write(b"[%d]" % t)
                    dev_raw.write(d)
                    dev_raw.flush()
                    dev_buf[t] += d
                    while dev_buf[t]:
                        if dev_buf[t][0] not in DEV_FRAME:
                            del dev_buf[t][0]
                            continue
                        ln = DEV_FRAME[dev_buf[t][0]]
                        if len(dev_buf[t]) < ln:
                            break
                        frame = bytes(dev_buf[t][:ln])
                        del dev_buf[t][:ln]
                        try:
                            s.sendall(frame)
                        except (BlockingIOError, OSError):
                            pass
                        print("dev%d->MCU %s" % (t, frame.hex()), flush=True)


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "probe":
        probe()
    else:
        main()
