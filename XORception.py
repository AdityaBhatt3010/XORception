import base64
import argparse


def xor(data: str, key: int) -> str:
    return ''.join(chr(ord(c) ^ key) for c in data)


def bitshift_encode(data: str) -> str:
    return ''.join(chr(((ord(c) << 1) + 1) % 256) for c in data)


def bitshift_decode(data: str) -> str:
    return ''.join(chr(((ord(c) - 1) >> 1) % 256) for c in data)


def layered_obfuscate(data: str, key: int) -> str:
    xored = xor(data, key)
    shifted = bitshift_encode(xored)
    encoded = base64.b64encode(shifted.encode()).decode()
    return encoded


def layered_deobfuscate(encoded_data: str, key: int) -> str:
    decoded = base64.b64decode(encoded_data).decode()
    unshifted = bitshift_decode(decoded)
    original = xor(unshifted, key)
    return original


def main():
    parser = argparse.ArgumentParser(description="XORception - Layered XOR Obfuscator")
    parser.add_argument("-s", "--string", help="String to encode or decode", required=True)
    parser.add_argument("-k", "--key", type=int, help="XOR key (integer)", required=True)
    parser.add_argument("-m", "--mode", choices=["obfuscate", "deobfuscate"], required=True)
    args = parser.parse_args()

    if args.mode == "obfuscate":
        result = layered_obfuscate(args.string, args.key)
        print("[+] Obfuscated:", result)
    elif args.mode == "deobfuscate":
        result = layered_deobfuscate(args.string, args.key)
        print("[+] Deobfuscated:", result)


if __name__ == "__main__":
    main()
