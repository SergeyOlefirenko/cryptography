from Crypto.Util.number import long_to_bytes

# data from output.txt
n = 89130176363968657187562046515332781879906710777886742664996031757940362853930049819009596594982246571669482031940134479813793328701373238273415076270891142859666516439231904521557755729322490606876589914024096621194962329718893576886641536066926542462448229133783052051407061075447588804617825930836181625077
e = 1
ct = 9525146106593233668246438912833048755472216768584708733

# at e=1 ct == pt (mod n), и так как pt < n — ct == pt
pt_bytes = long_to_bytes(ct)
try:
    pt = pt_bytes.decode('utf-8')
except UnicodeDecodeError:
    # In case another method is required, we simply print the bytes
    print("Decoded bytes (non-UTF8):", pt_bytes)
    raise

print("Recovered plaintext:", pt)

# Save the flag to a file
with open("flag.txt", "w", encoding="utf-8") as f:
    f.write(pt + "\n")
print("Flag saved to flag.txt")
