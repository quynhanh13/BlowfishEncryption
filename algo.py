import blowfish_algo as blowfish
import base64

cipher = blowfish.Cipher(b"admin_key")

def encrypt_msg(msg):
    msg = str.encode(msg)
    cipher_text = b"".join(cipher.encrypt_ecb_cts(msg))
    cipher_text = base64.b64encode(cipher_text)
    return cipher_text.decode('utf-8')

def decrypt_msg(msg):
    msg = str.encode(msg)
    cipher_text = base64.b64decode(msg)
    plain_text = b"".join(cipher.decrypt_ecb_cts(cipher_text))
    return plain_text.decode('utf-8')

if __name__ == "__main__":
    plain_text = input("Enter message to send: ")
    cipher_text = encrypt_msg(plain_text)
    print(cipher_text)
    val = decrypt_msg(cipher_text)
    print(val)