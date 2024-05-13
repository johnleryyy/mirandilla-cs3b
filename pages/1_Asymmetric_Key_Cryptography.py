import streamlit as st
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, PKCS1_v1_5
import base64

class SessionState:
    def __init__(self, **kwargs):
        self.__dict__.update(kwargs)

def generate_key_pair(key_size):
    key = RSA.generate(key_size)
    private_key = key.export_key(format='PEM')
    public_key = key.publickey().export_key(format='PEM')
    return private_key, public_key

def rsa_encrypt(message, public_key, cipher_type):
    key = RSA.import_key(public_key)
    if cipher_type == "RSA, ECB, PKCS1Padding":
        cipher = PKCS1_v1_5.new(key)
    elif cipher_type == "RSA, ECB, OAEPWithSHA, 1AndMGF1Padding":
        cipher = PKCS1_OAEP.new(key)
    elif cipher_type == "RSA, ECB, OAEPWithSHA, 256AndMGF1Padding":
        cipher = PKCS1_OAEP.new(key, hashAlgo=SHA256, mgf=MGF1)
    else:
        cipher = PKCS1_v1_5.new(key)
    encrypted_message = cipher.encrypt(message)
    return base64.b64encode(encrypted_message)

def rsa_decrypt(encrypted_message, private_key, cipher_type):
    key = RSA.import_key(private_key)
    cipher = None
    
    if cipher_type == "RSA, ECB, PKCS1Padding":
        cipher = PKCS1_v1_5.new(key)
    elif cipher_type == "RSA, ECB, OAEPWithSHA, 1AndMGF1Padding":
        cipher = PKCS1_OAEP.new(key)
    elif cipher_type == "RSA, ECB, OAEPWithSHA, 256AndMGF1Padding":
        cipher = PKCS1_OAEP.new(key, hashAlgo=SHA256, mgf=MGF1)
    else:
        cipher = PKCS1_v1_5.new(key)

    decrypted_message = cipher.decrypt(base64.b64decode(encrypted_message), sentinel=b"")
    return decrypted_message


def main():
    st.title("RSA Encryption/Decryption App")
    mode = st.sidebar.selectbox("Select Mode:", ["Encrypt", "Decrypt"])

    if mode == "Encrypt":
        key_sizes = [1024, 2048, 3072, 4096]
        key_size = st.selectbox("Select RSA Key Size", key_sizes)

        if not hasattr(st.session_state, "keys_generated"):
            st.session_state.keys_generated = False

        if st.button("Generate RSA Key Pair") or not st.session_state.keys_generated:
            private_key, public_key = generate_key_pair(key_size)
            st.session_state.private_key = private_key
            st.session_state.public_key = public_key
            st.text("Public Key (X.509 Format):")
            st.text(public_key.decode())  # decode bytes to string
            st.text("Private Key (PKCS8 Format):")
            st.text(private_key.decode())  # decode bytes to string
            st.session_state.keys_generated = True

        rsa_mode = st.radio("RSA Key Type:", ["Public Key", "Private Key"])

        cipher_types = ["RSA", "RSA, ECB, PKCS1Padding", "RSA, ECB, OAEPWithSHA, 1AndMGF1Padding", "RSA, ECB, OAEPWithSHA, 256AndMGF1Padding"]
        cipher_type = st.selectbox("Select Cipher Type:", cipher_types)

        if rsa_mode == "Public Key":
            message_encrypt = st.text_input("Enter Plain Text to Encrypt")
            if st.button("Encrypt"):
                encrypted_message = rsa_encrypt(message_encrypt.encode(), st.session_state.public_key, cipher_type)
                st.text("Encrypted Output (Base64):")
                st.text(encrypted_message.decode())  # decode bytes to string
        else:
            st.warning("You're in Encrypt mode. Please select Public Key for encryption.")

    else:
        if hasattr(st.session_state, "private_key"):
            cipher_types = ["RSA, ECB, PKCS1Padding", "RSA, ECB, OAEPWithSHA, 1AndMGF1Padding", "RSA, ECB, OAEPWithSHA, 256AndMGF1Padding"]
            cipher_type = st.selectbox("Select Cipher Type:", cipher_types)
            message_decrypt = st.text_input("Enter Encrypted Text to Decrypt (Base64)")
            if st.button("Decrypt"):
                decrypted_message = rsa_decrypt(message_decrypt.encode(), st.session_state.private_key, cipher_type)
                st.text("Decrypted Output:")
                st.text(decrypted_message.decode())  # decode bytes to string
        else:
            st.error("Please generate RSA key pair first.")

if __name__ == "__main__":
    main()
