# 🛡️ Unified Secure Messaging APDU Generator

A Python tool to generate and log APDU commands using **Secure Messaging**, supporting both:
- ✍️ **Signature-only mode** (command integrity via CBC-DES MAC)
- 🔒 **Ciphered mode** (command confidentiality + integrity via CBC-3DES)

This tool is designed to work with smartcards following the **WG10B/ISO 7816** specifications.

---

## 🚀 Features

- Derives **Session Keys (SK)** from Administrative Keys and NTs (Number Tokens)
- Computes **MAC (Message Authentication Code)** using CBC-DES
- Encrypts data using **CBC-3DES** in ciphered mode
- Builds full APDU command with proper headers and length (`Lc`)
- Offers optional debug output and command logging to file
- Modular and easy to integrate into larger card scripting workflows

---

## 📦 Usage

```bash
python3 unified_script.py <NT> <DATA> --mode secure|ciphered [options]
```

### 🔧 Common Options

| Option            | Description                                               |
|-------------------|-----------------------------------------------------------|
| `nt`              | 2-byte NT value in hex (e.g. `000A`)                      |
| `data`            | ASCII (secure mode) or hex (ciphered mode) string         |
| `--mode`          | Either `secure` or `ciphered`                             |
| `--offset`        | P2 offset in hex (default: `00`)                          |
| `--ak`            | 16-byte Administrative Key in hex (default provided)      |
| `--iv`            | 8-byte IV for CBC (used in ciphered mode only)           |
| `--debug`         | Enables verbose output for educational/troubleshooting   |
| `--logfile`       | Output log file (default: `secure_messaging.log`)         |

---

## ⚙️ Defaults

Several parameters are **predefined by default** to simplify usage:

| Parameter     | Default value                              | Description                                 |
|---------------|---------------------------------------------|---------------------------------------------|
| `--ak`        | `5543334D2D4D41535445524B45593035`          | Default Administrative Key (hex, 16 bytes)  |
| `--offset`    | `00`                                        | P2 offset                                   |
| `--iv`        | `0000000000000000`                          | IV for CBC (only used in ciphered mode)     |
| `--logfile`   | `secure_messaging.log`                      | Output log file name                        |

These can be customized at runtime if needed.

---

## 🧪 Examples

### 1. Secure Messaging (Signature Only)
```bash
python3 unified_script.py 000A "whatever" --mode secure --debug
```

### 2. Ciphered Secure Messaging
```bash
python3 unified_script.py 000A 0101010101010101 --mode ciphered --iv 0000000000000000 --debug
```

---

## 📄 Log Output Example

Each command is logged to a file with timestamp and parameters:
```
[2025-03-27 16:45:10] MODE=SECURE NT=000A OFFSET=00 LC=0C DATA=313030353337313437EF5E05
```

---

## 🔐 Technical Background

This tool implements key parts of WG10B Secure Messaging:
- 3DES key derivation using Administrative Keys and NT
- CBC-DES MAC calculation for command authentication
- CBC-3DES encryption for data confidentiality
- Construction of correct APDU structure (CLA, INS, P1, P2, Lc, Data)

---

## 📜 License

This tool is open-source and published under the MIT License.  
Feel free to use, modify, and share it.
