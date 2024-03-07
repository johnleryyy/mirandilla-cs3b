import streamlit as st

def pad(data, block_size):    
    padding_length = block_size - len(data) % block_size  
    padding = bytes([padding_length] * padding_length)  
    return data + padding                          

def unpad(data):
    padding_length = data[-1]
    return data[:-padding_length]                           

def xor_encrypt_block(plaintext_block, key):
    encrypted_block = b''
    for i in range(len(plaintext_block)):
        encrypted_block += bytes([plaintext_block[i] ^ key[i % len(key)]])
    return encrypted_block                   

def xor_decrypt_block(ciphertext_block, key):
    return xor_encrypt_block(ciphertext_block, key)  

def xor_encrypt(plaintext, key, block_size):
    encrypted_data = b''
    padded_plaintext = pad(plaintext, block_size)
    for i in range(0, len(padded_plaintext), block_size):
        plaintext_block = padded_plaintext[i:i+block_size]
        encrypted_block = xor_encrypt_block(plaintext_block, key)
        encrypted_data += encrypted_block
    return encrypted_data                               

def xor_decrypt(ciphertext, key, block_size):
    decrypted_data = b''
    for i in range(0, len(ciphertext), block_size):
        ciphertext_block = ciphertext[i:i+block_size]
        decrypted_block = xor_decrypt_block(ciphertext_block, key)
        decrypted_data += decrypted_block
    unpadded_decrypted_data = unpad(decrypted_data)
    return unpadded_decrypted_data                               

def main():
    st.title("Block Cipher Encryption & Decryption")
    st.subheader("Encrypt and Decrypt using Block Cipher")
    plaintext = st.text_input("Enter the plaintext:")
    key = st.text_input("Enter the key:")
    block_size = st.number_input("Enter the block size:", min_value=8, max_value=128, step=8, value=16)

    if st.button("Encrypt"):
        plaintext_bytes = bytes(plaintext.encode())
        key_bytes = bytes(key.encode())
        key_padded = pad(key_bytes, block_size)
        encrypted_data = xor_encrypt(plaintext_bytes, key_padded, block_size)
        st.write("Encrypted Data:", encrypted_data.hex())

    if st.button("Decrypt"):
        ciphertext_hex = st.text_input("Enter the encrypted data (in hexadecimal format):")
        ciphertext_bytes = bytes.fromhex(ciphertext_hex)
        key_bytes = bytes(key.encode())
        key_padded = pad(key_bytes, block_size)
        decrypted_data = xor_decrypt(ciphertext_bytes, key_padded, block_size)
        st.write("Decrypted Data:", decrypted_data.decode())

if __name__ == "__main__":
    main()
