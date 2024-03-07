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

def display_encryption_decryption_details(details, ifdecrypt):
    for i,(char, shift, result_char) in enumerate(details):
        st.write(f"{i} {char} {shift} {result_char}")

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

    if st.checkbox("Show Encryption and Decryption Details"):
        details_encrypt = [(char, shift_keys[i % len(shift_keys)], encrypted_text[i])for i, char in enumerate(text)]
        details_decrypt = [(char, shift_keys[i % len(shift_keys)], decrypted_text[i])for i, char in enumerate(encrypted_text)]

        st.write("Encryption Details:")
        display_encryption_decryption_details(details_encrypt, False)
        st.write('-' * 10)
        st.write("Decryption Details:")
        display_encryption_decryption_details(details_decrypt, True)
        st.write('-' * 10)
        st.write("Text:", text)
        st.write("Shift keys:", " ".join(map(str, shift_keys)))
        st.write("Cipher:", encrypted_text)
        st.write("Decrypted text:", decrypted_text)

if __name__ == "__main__":
    main()
