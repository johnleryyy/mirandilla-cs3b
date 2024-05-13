import streamlit as st

st.set_page_config(
    page_title="XOR Cipher",
    page_icon="🔑",
)

col1, col2, col3, col4, col5 = st.columns(5)

with col1:
    st.page_link("Home.py", label="Home", icon="🏠")

with col2:
    st.page_link("parak/0_XOR_Cipher.py", label="XOR Cipher", icon="1️⃣")

with col3:
    st.page_link("parak/1_Caesar_Cipher.py", label="Caesar Cipher", icon="2️⃣")

with col4:
    st.page_link("parak/2_Primitive_Root.py", label="Primitive Root", icon="2️⃣")

with col5:
    st.page_link("parak/3_Block_Cipher.py", label="Block Cipher", icon="2️⃣")

st.header('XOR Cipher', divider='rainbow')

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
    return xor_encrypt(ciphertext, key)   # XOR decryption is the same as encryption

# Example usage:
plaintext = bytes(st.text_input('Plaintext').encode())
key = bytes(st.text_input('Key').encode())

if st.button("Submit", key="clk_btn"):
    col1, col2 = st.columns(2)
    if len(plaintext) >= len(key):
        if plaintext != key:
            try:
                with col1:
                    cipher = xor_encrypt(plaintext, key)
                    st.write(f"Ciphertext:", "".join([f"{chr(byte_val)}" for byte_val in cipher]))
                with col2:
                    decrypt = xor_decrypt(cipher, key)
                    st.write(f"Decrypted:", "".join([f"{chr(byte_va)}" for byte_va in decrypt]))
            except:
                st.error("Invalid Key!")
        else:
            st.write("Plaintext should not be equal to the key")
    else:
        st.write("Plaintext length should be equal or greater than the length of key")