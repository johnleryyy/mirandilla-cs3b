import streamlit as st
import hashlib

def hash_unique_chars(text):
    hashed_chars = {}
    hashed_text = ""
    for char in text:
        if char not in hashed_chars:
            if char == ' ':
                hashed_chars[char] = hashlib.sha1('<space>'.encode()).hexdigest()
            else:
                hashed_chars[char] = hashlib.sha1(char.encode()).hexdigest()
    return hashed_chars, hashed_text
    
def hash_whole_text(text):
    return hashlib.sha1(text.encode()).hexdigest()

def main():
    st.title("Text Hashing App")
    option = st.radio("Choose input type:", ("Text", "File"))
    
    if option == "Text":
        input_text = st.text_area("Enter text:")
        if st.button("Hash Text"):
            hashed_chars_output, hashed_text_output = hash_unique_chars(input_text)
            hashed_whole_text_output = hash_whole_text(input_text)
            
            st.write("Hashed Characters:")
            for char, hash_value in hashed_chars_output.items():
                if char == ' ':
                    char = char.replace(" ", "<space>")
                    st.write(f"{hash_value.upper()} {char}")
                else:
                    st.write(f"{hash_value.upper()} {char}")
                    
            st.write("Hashed Whole Text:")
            st.write(f"{hashed_whole_text_output.upper()} {input_text}")
            
    elif option == "File":
        uploaded_file = st.file_uploader("Upload a file")
        if uploaded_file is not None:
            file_contents = uploaded_file.getvalue().decode("utf-8")
            if st.button("Hash File"):
                hashed_whole_file_output = hash_whole_text(file_contents)
                
                st.write("Hashed Whole File:")
                st.write(f"{hashed_whole_file_output.upper()} {uploaded_file.name}")

if __name__ == "__main__":
    main()
