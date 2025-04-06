import argparse
from Crypto.Cipher import DES, DES3
from binascii import hexlify, unhexlify
from datetime import datetime

def debug(msg, enabled):
    if enabled:
        print(msg)

def write_log(mode, nt, offset, lc, data, logfile):
    timestamp = datetime.now().strftime("[%Y-%m-%d %H:%M:%S]")
    log_entry = (
        f"{timestamp} MODE={mode.upper()} NT={nt.upper()} OFFSET={offset.upper()} "
        f"LC={lc.upper()} DATA={data.upper()}\n"
    )
    with open(logfile, "a") as f:
        f.write(log_entry)

def derive_session_key(nt_hex, ak_hex, debug_enabled):
    debug("\n[STEP 1] 🔐 Session Key Derivation", debug_enabled)
    AK = unhexlify(ak_hex)
    AK1, AK2 = AK[:8], AK[8:]
    debug(f"  Administrative Key (AK): {ak_hex}", debug_enabled)
    debug(f"  AK1: {hexlify(AK1).decode()}", debug_enabled)
    debug(f"  AK2: {hexlify(AK2).decode()}", debug_enabled)

    block = bytes.fromhex("000000") + unhexlify(nt_hex) + bytes.fromhex("000000")
    debug(f"  NT: {nt_hex.upper()}", debug_enabled)
    debug(f"  Block for SK derivation: {hexlify(block).decode()}", debug_enabled)

    SK1 = DES3.new(AK1 + AK2, DES3.MODE_ECB).encrypt(block)
    SK2 = DES3.new(AK2 + AK1, DES3.MODE_ECB).encrypt(block)
    session_key = SK1 + SK2
    debug(f"  SK1: {hexlify(SK1).decode()}", debug_enabled)
    debug(f"  SK2: {hexlify(SK2).decode()}", debug_enabled)
    debug(f"  ➤ Session Key: {hexlify(session_key).decode()}", debug_enabled)
    return session_key, SK1, SK2

def compute_mac(message, SK1, session_key, debug_enabled):
    debug("\n[STEP 2] 🧾 MAC (CBC-MAC) Computation", debug_enabled)
    blocks = [message[i:i+8] for i in range(0, len(message), 8)]
    if len(blocks[-1]) < 8:
        blocks[-1] += b"\x00" * (8 - len(blocks[-1]))
        debug("  [i] Last block padded with zeros for CBC-MAC.", debug_enabled)

    for i, b in enumerate(blocks):
        debug(f"  Block {i+1}: {hexlify(b).decode()}", debug_enabled)

    cbc = DES.new(SK1, DES.MODE_ECB)
    cb_prev = cbc.encrypt(blocks[0])
    debug(f"  Encrypted Block 1: {hexlify(cb_prev).decode()}", debug_enabled)

    for i, block in enumerate(blocks[1:-1], start=2):
        xor_block = bytes([x ^ y for x, y in zip(block, cb_prev)])
        cb_prev = cbc.encrypt(xor_block)
        debug(f"  XOR Block {i}: {hexlify(xor_block).decode()}", debug_enabled)
        debug(f"  Encrypted Block {i}: {hexlify(cb_prev).decode()}", debug_enabled)

    xor_last = bytes([x ^ y for x, y in zip(blocks[-1], cb_prev)])
    debug(f"  XOR Final Block: {hexlify(xor_last).decode()}", debug_enabled)
    s2 = DES3.new(session_key, DES3.MODE_ECB).encrypt(xor_last)
    mac = s2[-3:]
    debug(f"  S2: {hexlify(s2).decode()}", debug_enabled)
    debug(f"  ➤ MAC (last 3 bytes): {hexlify(mac).decode()}", debug_enabled)
    return mac

def secure_messaging(nt_hex, ascii_text, offset_hex, ak_hex, debug_enabled, logfile):
    if not ascii_text.isascii():
        print("[ERROR] ASCII input only allowed in secure messaging.")
        return

    try:
        p2 = bytes([int(offset_hex, 16)])
    except ValueError:
        print("[ERROR] Invalid P2 offset.")
        return

    session_key, SK1, SK2 = derive_session_key(nt_hex, ak_hex, debug_enabled)

    data = ascii_text.encode("ascii")
    debug(f"\n[STEP 1.5] 🧱 Message Construction", debug_enabled)
    debug(f"  ASCII Text: {ascii_text}", debug_enabled)
    debug(f"  Encoded Data: {hexlify(data).decode()}", debug_enabled)

    lc = bytes([len(data) + 3])
    debug(f"  Lc (length of Data + 3): {hexlify(lc).decode()}", debug_enabled)

    header = b"\x04\xD6\x00" + p2 + lc
    debug(f"  Header: {hexlify(header).decode()}", debug_enabled)

    message = header + data
    debug(f"  Message (Header + Data): {hexlify(message).decode()}", debug_enabled)

    if len(message) % 8 != 0:
        padding_len = 8 - (len(message) % 8)
        message += b"\x00" * padding_len
        debug(f"  [i] Message padded with {padding_len} null bytes", debug_enabled)
        debug(f"  Padded Message: {hexlify(message).decode()}", debug_enabled)

    mac = compute_mac(header + data, SK1, session_key, debug_enabled)
    final_data = data + mac
    debug(f"\n[STEP 4] 📦 Final APDU Data", debug_enabled)
    debug(f"  Final Data (Data + MAC): {hexlify(final_data).decode()}", debug_enabled)

    print("\n[RESULT] ✉️ APDU Command (Secure Messaging - Signature only)")
    print(f" CLA : 04")
    print(f" INS : D6")
    print(f" P1  : 00")
    print(f" P2  : {hexlify(p2).decode().upper()}")
    print(f" Lc  : {hexlify(lc).decode().upper()}")
    print(f" Data: {hexlify(final_data).decode().upper()}")

    write_log("secure", nt_hex, hexlify(p2).decode(), hexlify(lc).decode(), hexlify(final_data).decode(), logfile)

def ciphered_secure_messaging(nt_hex, data_hex, offset_hex, ak_hex, iv_hex, debug_enabled, logfile):
    try:
        data = unhexlify(data_hex)
    except Exception:
        print("[ERROR] Invalid hex data for ciphered messaging.")
        return
    try:
        p2 = bytes([int(offset_hex, 16)])
    except ValueError:
        print("[ERROR] Invalid P2 offset.")
        return
    try:
        iv = unhexlify(iv_hex)
        if len(iv) != 8:
            raise ValueError()
    except Exception:
        print("[ERROR] IV must be 8 bytes (16 hex digits).")
        return

    session_key, SK1, SK2 = derive_session_key(nt_hex, ak_hex, debug_enabled)

    debug(f"\n[STEP 1.5] 🧱 Message Construction", debug_enabled)
    debug(f"  Plaintext Data: {data_hex.upper()}", debug_enabled)

    lc = bytes([len(data) + 3])
    debug(f"  Lc (length of Data + 3): {hexlify(lc).decode()}", debug_enabled)

    header = b"\x04\xD6\x00" + p2 + lc
    debug(f"  Header: {hexlify(header).decode()}", debug_enabled)

    message_for_mac = header + data
    debug(f"  Message for MAC: {hexlify(message_for_mac).decode()}", debug_enabled)

    mac = compute_mac(message_for_mac, SK1, session_key, debug_enabled)

    debug("\n[STEP 3] 🔒 CBC Encryption", debug_enabled)
    cipher = DES3.new(session_key, DES3.MODE_CBC, iv)
    padded_data = data
    if len(data) % 8 != 0:
        padding_len = 8 - len(data) % 8
        padded_data += b"\x00" * padding_len
        debug(f"  [i] Plaintext padded with {padding_len} null bytes", debug_enabled)

    debug(f"  IV: {iv_hex.upper()}", debug_enabled)
    debug(f"  Plaintext to Encrypt: {hexlify(padded_data).decode()}", debug_enabled)

    encrypted_data = cipher.encrypt(padded_data)
    debug(f"  Encrypted Data: {hexlify(encrypted_data).decode()}", debug_enabled)

    final_data = encrypted_data + mac
    final_lc = bytes([len(final_data)])

    debug(f"  Final Data (Encrypted + MAC): {hexlify(final_data).decode()}", debug_enabled)

    print("\n[RESULT] ✉️ APDU Command (Ciphered Secure Messaging)")
    print(f" CLA : 04")
    print(f" INS : D6")
    print(f" P1  : 00")
    print(f" P2  : {hexlify(p2).decode().upper()}")
    print(f" Lc  : {hexlify(final_lc).decode().upper()}")
    print(f" Data: {hexlify(final_data).decode().upper()}")

    write_log("ciphered", nt_hex, hexlify(p2).decode(), hexlify(final_lc).decode(), hexlify(final_data).decode(), logfile)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Unified Secure Messaging APDU Generator (Signature or Ciphered).")
    parser.add_argument("nt", help="Random NT value in hex (e.g. 0006)")
    parser.add_argument("data", help="ASCII string (for 'secure') or hex string (for 'ciphered')")
    parser.add_argument("--offset", default="00", help="P2 offset in hex (default: 00)")
    parser.add_argument("--mode", choices=["secure", "ciphered"], required=True,
                        help="Mode of secure messaging: 'secure' or 'ciphered'")
    parser.add_argument("--ak", default="5543334D2D4D41535445524B45593035",
                        help="Administrative Key in hex (16 bytes or 32 hex digits)")
    parser.add_argument("--iv", default="0000000000000000",
                        help="IV for CBC encryption (8 bytes = 16 hex digits, only for 'ciphered')")
    parser.add_argument("--debug", action="store_true", help="Enable verbose debug output")
    parser.add_argument("--logfile", default="secure_messaging.log",
                        help="File to append log entries (default: secure_messaging.log)")

    args = parser.parse_args()

    if args.mode == "secure":
        secure_messaging(args.nt, args.data, args.offset, args.ak, args.debug, args.logfile)
    elif args.mode == "ciphered":
        ciphered_secure_messaging(args.nt, args.data, args.offset, args.ak, args.iv, args.debug, args.logfile)
