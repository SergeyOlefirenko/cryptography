from Crypto.Util.number import long_to_bytes
import sys
import re

def read_output(filename="output.txt"):
    with open(filename, "r", encoding="utf-8") as f:
        s = f.read()
    # A simple extracting regex for n, e, ct
    n_match = re.search(r"n\s*=\s*([0-9]+)", s)
    e_match = re.search(r"e\s*=\s*([0-9]+)", s)
    ct_match = re.search(r"ct\s*=\s*([0-9]+)", s)
    if not (n_match and e_match and ct_match):
        raise ValueError("Could not find n, e or ct в output.txt")
    n = int(n_match.group(1))
    e = int(e_match.group(1))
    ct = int(ct_match.group(1))
    return n, e, ct

def integer_nth_root(x, n):
    """Returns (root, exact), where root is the integer n-th root, exact=True if root**n == x"""
    if x < 0:
        raise ValueError("x must be non-negative")
    if x == 0:
        return 0, True
    # Binary search
    lo = 0
    hi = 1 << ((x.bit_length() + n - 1) // n)  # rough upper bound
    while lo + 1 < hi:
        mid = (lo + hi) // 2
        p = mid**n
        if p == x:
            return mid, True
        if p < x:
            lo = mid
        else:
            hi = mid
    # check lo
    return lo, (lo**n == x)

def main():
    n, e, ct = read_output("output.txt")
    print(f"n bits: {n.bit_length()}, e = {e}")
    print("ct:", ct)

    # We expect e == 3 (as per the task), but the algorithm can work for any e:
    if e == 1:
        print("e == 1 -> ct == plaintext (numeric). Try long_to_bytes(ct).")
    if e == 3:
        root, exact = integer_nth_root(ct, 3)
        if exact:
            print("Condition m^3 == ct fulfilled: integer cubic root found")
            m = root
            try:
                plaintext = long_to_bytes(m).decode("utf-8")
                print("Recovered plaintext (utf-8):", plaintext)
            except Exception:
                # In case it isn’t utf-8
                pt_bytes = long_to_bytes(m)
                print("Recovered bytes (not utf-8):", pt_bytes)
                plaintext = None
            # Save the flag
            if plaintext:
                with open("flag.txt", "w", encoding="utf-8") as f:
                    f.write(plaintext + "\n")
                print("Flag saved to flag.txt")
            else:
                with open("flag.bin", "wb") as f:
                    f.write(long_to_bytes(m))
                print("Bytes saved в flag.bin")
        else:
            print("The integer cubic root does not match: possibly m^3 >= n or using padding.")
            print("Try other techniques (CRT, common low-exponent attacks)")
    else:
        # If e small (2 or 3) can try taking the e-th root
        root, exact = integer_nth_root(ct, e)
        if exact:
            print(f"Integer found {e}-th root: Message recovered")
            try:
                print("Plaintext:", long_to_bytes(root).decode("utf-8"))
            except Exception:
                print("Plain bytes:", long_to_bytes(root))
        else:
            print(f"Could not find the exact one {e}-th root")

if __name__ == "__main__":
    main()
