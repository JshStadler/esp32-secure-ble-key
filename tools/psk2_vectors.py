"""Independent PSK2 vectors for the actual firmware decoder (synthetic keys only)."""
import hashlib
import hmac
from pathlib import Path
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

key = b"synthetic-current-key"
nonce = bytes(range(16))
iv = bytes(range(16, 28))
def context(domain):
    return domain + b"\0car-main\0" + nonce
def mac(k, data):
    return hmac.digest(k, data, "sha256")
enc = mac(key, context(b"BLEKEY-PSK2-ENC"))
ack = mac(key, context(b"BLEKEY-PSK2-ACK"))
lines = []
for i, replacement in enumerate([b"replacement-key", b"x"*127, b"x"*128, b"a\0b", b""]):
    packet = b"\xa2" + iv + AESGCM(enc).encrypt(iv, replacement, context(b"BLEKEY-PSK2"))
    lines.append(f'static const unsigned char packet{i}[] = {{' + ','.join(map(str, packet)) + '};')
    if i == 0:
        for success in [True, False]:
            status = "OK" if success else "FAIL"
            receipt = f"PSK2:{status}:" + mac(ack, bytes([success]) + hashlib.sha256(packet).digest()).hex()
            lines.append(f'#define RECEIPT_{status} "{receipt}"')
        print("packet=" + packet.hex())
        print(lines[-2])
Path("psk2_vectors.h").write_text("\n".join(lines) + "\n")
