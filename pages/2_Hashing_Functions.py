import streamlit as st
import hashlib

def hash_md5(text):
    return hashlib.md5(text.encode()).hexdigest()

def hash_sha1(text):
    return hashlib.sha1(text.encode()).hexdigest()

def hash_sha256(text):
    return hashlib.sha256(text.encode()).hexdigest()

def hash_sha512(text):
    return hashlib.sha512(text.encode()).hexdigest()

def hash_file_md5(file_contents):
    return hashlib.md5(file_contents.encode()).hexdigest()

def hash_file_sha1(file_contents):
    return hashlib.sha1(file_contents.encode()).hexdigest()

def hash_file_sha256(file_contents):
    return hashlib.sha256(file_contents.encode()).hexdigest()

def hash_file_sha512(file_contents):
    return hashlib.sha512(file_contents.encode()).hexdigest()

def main():
    st.title("Hash Function")

    tabs = st.tabs(["MD5", "SHA-1", "SHA-256", "SHA-512"])
    
    for i, option in enumerate(["MD5", "SHA-1", "SHA-256", "SHA-512"]):
        with tabs[i]:
            input_type = st.radio(f"Choose input type for {option}:", ("Text", "File"))
            
            if input_type == "Text":
                input_text = st.text_area(f"Enter text for {option}:")
                
                if st.button(f"Hash Text using {option}"):
                    if option == "MD5":
                        hashed_text = hash_md5(input_text)
                    elif option == "SHA-1":
                        hashed_text = hash_sha1(input_text)
                    elif option == "SHA-256":
                        hashed_text = hash_sha256(input_text)
                    elif option == "SHA-512":
                        hashed_text = hash_sha512(input_text)
                    
                    st.write(f"Hashed Text ({option}):")
                    st.write(hashed_text)
                
            elif input_type == "File":
                uploaded_file = st.file_uploader(f"Upload a file for {option}")
                if uploaded_file is not None:
                    file_contents = uploaded_file.getvalue().decode("utf-8")
                    if st.button(f"Hash File using {option}"):
                        if option == "MD5":
                            hashed_text = hash_file_md5(file_contents)
                        elif option == "SHA-1":
                            hashed_text = hash_file_sha1(file_contents)
                        elif option == "SHA-256":
                            hashed_text = hash_file_sha256(file_contents)
                        elif option == "SHA-512":
                            hashed_text = hash_file_sha512(file_contents)
                        
                        st.write(f"Hashed File ({option}):")
                        st.write(hashed_text)

if __name__ == "__main__":
    main()
