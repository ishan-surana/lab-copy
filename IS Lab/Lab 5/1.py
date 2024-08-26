def hash_function(s):
    hash_value = 5381
    current_xor = 17 # 5+3+8+1 = 17
    for char in s:
        hash_value = (hash_value * 33) + ord(char)
        hash_value = (hash_value ^ current_xor) << 4
        current_xor = ord(char)
    hash_value = hash_value & 0xFFFFFFFF
    return hash_value

input_string = "hello"
print(f"Hash value: {hash_function(input_string)}")