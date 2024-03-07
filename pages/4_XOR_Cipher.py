import streamlit as st

def xor_encrypt(plaintext, key):
    """Encrypts plaintext using XOR cipher with the given key, printing bits involved."""
    ciphertext = bytearray()
    for i in range(len(plaintext)):
        plaintext_byte = plaintext[i]
        key_byte = key[i % len(key)]
        cipher_byte = plaintext_byte ^ key_byte
        ciphertext.append(cipher_byte)
        
        st.write(f"Plaintext byte: {bin(plaintext_byte)[2:]:>08} = {chr(plaintext_byte)}")
        st.write(f"Key byte:       {bin(key_byte)[2:]:>08} = {chr(key_byte)}")
        st.write(f"XOR result:     {bin(cipher_byte)[2:]:>08} = {chr(cipher_byte)}")
        st.write("--------------------")
        
    return ciphertext

def xor_decrypt(ciphertext, key):
    """Decrypts ciphertext using XOR cipher with the given key."""
    return xor_encrypt(ciphertext, key)

def main():
    st.title("XOR Cipher Encryption & Decryption")
    st.subheader("Encrypt and Decrypt using XOR Cipher")
    
    plaintext = st.text_area("Plaintext:")
    key = st.text_area("Key:")
    
    if st.button("Encrypt / Decrypt"):
        plaintext_bytes = bytes(plaintext.encode())
        key_bytes = bytes(key.encode())
        
        if len(plaintext_bytes) >= len(key_bytes):
            if plaintext_bytes != key_bytes:
                cipher = xor_encrypt(plaintext_bytes, key_bytes)
                st.write("Ciphertext:", "".join([chr(byte_val) for byte_val in cipher]))

                decrypt = xor_decrypt(cipher, key_bytes)
                st.write("Decrypted:", "".join([chr(byte_val) for byte_val in decrypt]))
            else:
                st.write("Plaintext should not be equal to the key")
        else:
            st.write("Plaintext length should be equal or greater than the length of key")

if __name__ == "__main__":
    main()
