import streamlit as st

def prime_check(q):
    if q <= 1:
        return False
    for i in range(2, int(q**0.5)+1):
        if (q % i) == 0:
            return False
    return True
    
def power_mod(base, exp, mod):
    res = 1 
    base %= mod
    while exp > 0:
        if exp % 2 == 1:
            res = (res * base) % mod
        exp //= 2
        base = (base * base) % mod
    return res
    
def find_primitive_roots(q):
    primitive_roots = []
    for g in range(1, q):
        is_primitive = True
        powers = set()
        for i in range(1, q):
            power = power_mod(g, i, q)
            powers.add(power)
            if power == 1:
                break 
        if len(powers) == q - 1:
            primitive_roots.append(g)
    return primitive_roots
    
def print_primitive(p, q):
    if not prime_check(p):
        st.write(f"{p} is not a prime number!!")
        return 
    
    print_res = []
    for g in range(1, p):
        output = []
        for j in range(1, p):
            result = power_mod(g, j, p)
            output.append(f"{g}^{j} mod {p} = {result}")
            if result == 1:
                break
        if g in find_primitive_roots(p):
            output[-1] += f" ==> {g} is primitive root of {p}|"
        else:
            output[-1] += "|"
        print_res.append("|".join(output))
    st.write("\n".join(print_res))
    primitive_root = find_primitive_roots(p)
    if primitive_root:
        if q in primitive_root:
            st.write(f"{q} is primitive root: True {primitive_root}")
        else: 
            st.write(f"{q} is NOT primitive root of {p} - List of Primitive roots: {primitive_root}")
    else:
        st.write(f"{q} is NOT primitive root of {p} - List of Primitive roots: {primitive_root}")

def main():
    st.title("Primitive Roots Finder")
    st.subheader("Find primitive roots of a prime number")
    q = st.number_input("Enter a prime number:", min_value=2, step=1)
    g = st.number_input("Enter another number:", min_value=1, step=1)
    print_primitive(int(q), int(g))

if __name__ == "__main__":
    main()
