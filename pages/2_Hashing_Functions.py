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
    st.title("Hash Functions")
    
    tabs = ["MD5", "SHA-1", "SHA-256", "SHA-512"]
    selected_tab = st.radio("Choose a hashing function:", tabs)
    
    if selected_tab == "MD5":
        input_type = st.radio("Choose input type:", ("Text", "File"))
        
        if input_type == "Text":
            input_text = st.text_area("Enter text:")
            
            if st.button("Hash Text"):
                hashed_text = hash_md5(input_text)
                st.write("Hashed Text (MD5):")
                st.write(hashed_text)
                
        elif input_type == "File":
            uploaded_file = st.file_uploader("Upload a file")
            if uploaded_file is not None:
                file_contents = uploaded_file.getvalue().decode("utf-8")
                if st.button("Hash File"):
                    hashed_text = hash_file_md5(file_contents)
                    st.write("Hashed File (MD5):")
                    st.write(hashed_text)
    
    elif selected_tab == "SHA-1":
        input_type = st.radio("Choose input type:", ("Text", "File"))
        
        if input_type == "Text":
            input_text = st.text_area("Enter text:")
            
            if st.button("Hash Text"):
                hashed_text = hash_sha1(input_text)
                st.write("Hashed Text (SHA-1):")
                st.write(hashed_text)
                
        elif input_type == "File":
            uploaded_file = st.file_uploader("Upload a file")
            if uploaded_file is not None:
                file_contents = uploaded_file.getvalue().decode("utf-8")
                if st.button("Hash File"):
                    hashed_text = hash_file_sha1(file_contents)
                    st.write("Hashed File (SHA-1):")
                    st.write(hashed_text)
    
    elif selected_tab == "SHA-256":
        input_type = st.radio("Choose input type:", ("Text", "File"))
        
        if input_type == "Text":
            input_text = st.text_area("Enter text:")
            
            if st.button("Hash Text"):
                hashed_text = hash_sha256(input_text)
                st.write("Hashed Text (SHA-256):")
                st.write(hashed_text)
                
        elif input_type == "File":
            uploaded_file = st.file_uploader("Upload a file")
            if uploaded_file is not None:
                file_contents = uploaded_file.getvalue().decode("utf-8")
                if st.button("Hash File"):
                    hashed_text = hash_file_sha256(file_contents)
                    st.write("Hashed File (SHA-256):")
                    st.write(hashed_text)
    
    elif selected_tab == "SHA-512":
        input_type = st.radio("Choose input type:", ("Text", "File"))
        
        if input_type == "Text":
            input_text = st.text_area("Enter text:")
            
            if st.button("Hash Text"):
                hashed_text = hash_sha512(input_text)
                st.write("Hashed Text (SHA-512):")
                st.write(hashed_text)
                
        elif input_type == "File":
            uploaded_file = st.file_uploader("Upload a file")
            if uploaded_file is not None:
                file_contents = uploaded_file.getvalue().decode("utf-8")
                if st.button("Hash File"):
                    hashed_text = hash_file_sha512(file_contents)
                    st.write("Hashed File (SHA-512):")
                    st.write(hashed_text)

if __name__ == "__main__":
    main()
