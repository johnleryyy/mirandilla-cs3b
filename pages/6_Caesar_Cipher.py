import streamlit as st

def encrypt_decrypt(text, shift_keys, ifdecrypt):
    """
    Encrypts a text using Caesar Cipher with a list of shift keys.
    Args:
        text: The text to encrypt.
        shift_keys: A list of integers representing the shift values for each character.
        ifdecrypt: flag if decrypt or encrypt
    Returns:
        A string containing the encrypted text if encrypt and plain text if decrypt
    """
    result = ''
    for i, char in enumerate(text):
        shift = shift_keys[i] if i < len(shift_keys) else shift_keys[i % len(shift_keys)]
        if ifdecrypt:
            shift = -shift
        result += caesar_cipher(char, shift)
    
    return result

def caesar_cipher(char, shift):
    if char.isalpha():
        if char.islower():
            return chr((ord(char) + shift - 32 + 94) % 94 + 32)
        else:
            return chr((ord(char) + shift - 32 + 94) % 94 + 32)
    else:
        return chr((ord(char) + shift - 32 + 94) % 94 + 32)

def main():
    st.title("Caesar Cipher Encryption & Decryption")
    st.subheader("Encrypt and Decrypt using Caesar Cipher")
    text = st.text_input("Enter the text:")
    shift_keys = st.text_input("Enter the shift keys (comma-separated integers within square brackets):")
    shift_keys = list(map(int, shift_keys.replace('[','').replace(']','').replace(',','').split()))

    if st.button("Encrypt"):
        encrypted_text = encrypt_decrypt(text, shift_keys, False)
        st.write("Encrypted Text:", encrypted_text)

    if st.button("Decrypt"):
        decrypted_text = encrypt_decrypt(text, shift_keys, True)
        st.write("Decrypted Text:", decrypted_text)

if __name__ == "__main__":
    main()
