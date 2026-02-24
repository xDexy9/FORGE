# FORGE
Feistel OTP Romanian Gated Encryption 

1. Full Algorithm Specification (Design of the Cipher Logic)
1.1 Purpose This is a 128-bit block cipher that shows: · Mixed English + Romanian plaintext in the same message · Classic Feistel structure · Modern ARX-style round function with extra diffusion · Clear separation between the cipher (confidentiality) and the OTP gate (access control only)
1.2 Alphabet & Encoding Layer We use one fixed 31-character alphabet (uppercase only) so English and Romanian letters can be mixed freely.
Alphabet mapping table (0–30): 0=A, 1=Ă, 2=Â, 3=B, 4=C, 5=D, 6=E, 7=F, 8=G, 9=H, 10=I, 11=Î, 12=J, 13=K, 14=L, 15=M, 16=N, 17=O, 18=P, 19=Q, 20=R, 21=S, 22=Ș, 23=T, 24=Ț, 25=U, 26=V, 27=W, 28=X, 29=Y, 30=Z
Quick instruction for Developer & Encryption Lead: Copy this exact table (or make a dict/list) into your code. Convert plaintext to UPPERCASE first, replace any unknown character with ‘X’, then map each letter to its number (0–30). This byte array is what gets padded and encrypted.
1.3 Block Cipher Core · Block size: 128 bits (16 bytes) · Key size: 128 bits (master key) · Rounds: 8–12 (configurable, default = 10) · Structure: Balanced Feistel. Each 128-bit block = Left 64 bits || Right 64 bits · Mode: CBC with a fresh random 128-bit IV for every message (IV is prepended to the ciphertext) · Padding: PKCS#7 (applied to the 0–30 byte array)
Encryption round (i = 0 to rounds-1): L_{i+1} = R_i R_{i+1} = L_i ⊕ F(R_i, K_i, i)
*** bitwise XOR ⊕ ***
Decryption: Same structure, but use round keys in reverse order. (Decryption Lead: you can simply reverse the key list and call the same round function – it will invert correctly.)
1.4 Round Function F (ARX + Permutation) 64-bit function: F(R, K, round) = bit_reverse_64( (ROTL( (R + K) mod 2⁶⁴ , rotation_amount[round]) ) XOR K )
Round-dependent rotation amounts (prime numbers): [5, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47]
Dev instruction: Implement bit_reverse_64 using any 64-bit reverse method (loop or the fast bitwise trick below).
1.5 Key Derivation & Schedule
1.	User passphrase + 16-byte random salt → PBKDF2-HMAC-SHA256 (10 000 iterations) → 128-bit master key
2.	Only after OTP validation is this master key released.
Round-key generation (after OTP success): For each round i (0 to rounds-1): · Rotate master key left by (i × 11) bits (mod 128) · Take the low 64 bits · Add round constant C[i] (mod 2⁶⁴) · XOR with the high 64 bits
Round constants C[0..11] (first 64 bits of √p fractional part for first 12 primes): [0x6a09e667f3bcc908, 0xbb67ae8584caa73b, 0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1, 0x510e527fade682d1, 0x9b05688c2b3e6c1f, 0x1f83d9abfb41bd6b, 0x5be0cd19137e2179, 0xcbbb9d5dc1059ed8, 0x629a292a367cd507, 0x9159015a3070dd17, 0x152fecd8f70e5939]
Quick instruction for Developer: Store the 12 constants as a simple array. Generate keys only once per decryption, right after OTP check.
1.6 OTP Gate (Access Control – NOT part of cipher strength) The 6-digit TOTP is required only for decryption. It releases the master key. If OTP is wrong → master key stays locked → decryption aborts. (For this part building real Face ID – I will help build it and help integrate it.)
2. Complete Pseudocode
pseudocode
// ==================== HELPER FUNCTIONS ====================
function map_to_bytes(text):          // Developer: implement this first
    text = UPPERCASE(text)
    bytes = []
    for each char in text:
        if char in alphabet_table:
            bytes.append(alphabet_index[char])
        else:
            bytes.append(28)          // X = 28
    return bytes

function map_from_bytes(bytes_list):  //  reverse mapping
    alphabet = "AĂÂBCDEFGHIÎJKLMNOPQRSTȘTUȚVWXYZ"  // exactly 31 chars, index 0-30
    return ''.join(alphabet[b] for b in bytes_list)

function pkcs7_pad(data, block=16):
    pad_len = block - (len(data) % block)
    return data + [pad_len] * pad_len

function pkcs7_unpad(data):           // secure
    if len(data) == 0:
        return []
    pad_len = data[-1]
    if pad_len < 1 or pad_len > 16 or pad_len > len(data):
        return "INVALID PADDING"      // or raise error
    for i in range(1, pad_len + 1):
        if data[-i] != pad_len:
            return "INVALID PADDING"
    return data[0 : -pad_len]

// Bit reverse helper (fast version)
function bit_reverse_64(x: uint64):
    x = ((x & 0x5555555555555555) << 1) | ((x & 0xAAAAAAAAAAAAAAAA) >> 1)
    x = ((x & 0x3333333333333333) << 2) | ((x & 0xCCCCCCCCCCCCCCCC) >> 2)
    x = ((x & 0x0F0F0F0F0F0F0F0F) << 4) | ((x & 0xF0F0F0F0F0F0F0F0) >> 4)
    x = ((x & 0x00FF00FF00FF00FF) << 8) | ((x & 0xFF00FF00FF00FF00) >> 8)
    x = ((x & 0x0000FFFF0000FFFF) << 16) | ((x & 0xFFFF0000FFFF0000) >> 16)
    x = (x << 32) | (x >> 32)
    return x

// Rotation amounts
const rotation_amounts[12] = [5, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47]

// Round constants (exact values)
const round_constants[12] = [
    0x6a09e667f3bcc908, 0xbb67ae8584caa73b, 0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1,
    0x510e527fade682d1, 0x9b05688c2b3e6c1f, 0x1f83d9abfb41bd6b, 0x5be0cd19137e2179,
    0xcbbb9d5dc1059ed8, 0x629a292a367cd507, 0x9159015a3070dd17, 0x152fecd8f70e5939
]

// ==================== ROUND FUNCTION ====================
function F(R: uint64, K: uint64, round: int):
    temp = (R + K) % (2**64)
    rot = rotation_amounts[round % 12]
    temp = ROTL(temp, rot)
    temp = temp XOR K
    temp = bit_reverse_64(temp)
    return temp

// ==================== KEY SCHEDULE ====================
function generate_round_keys(master_128: uint128, rounds=10):
    keys = []
    for i = 0 to rounds-1:
        shifted = ROTL_128(master_128, (i * 11) % 128)
        low  = shifted & 0xFFFFFFFFFFFFFFFF
        high = shifted >> 64
        temp = (low + round_constants[i % 12]) % (2**64)   // FIXED: %12 safety
        keys.append(temp XOR high)
    return keys

// ==================== MAIN FUNCTIONS ====================
function encrypt(plaintext, passphrase, salt, rounds=10):
    bytes = map_to_bytes(plaintext)
    padded = pkcs7_pad(bytes)
    master = PBKDF2(passphrase, salt, 10000, 16)   // 128-bit, HMAC-SHA256
    keys = generate_round_keys(master, rounds)
    iv = random_128_bit()
    ciphertext = CBC_Feistel_Encrypt(padded, keys, iv)
    return iv || ciphertext

function decrypt(ciphertext, passphrase, salt, otp, totp_secret, rounds=10):
    if NOT validate_TOTP(otp, totp_secret):
        return "ACCESS DENIED - Invalid OTP"
    
    iv = ciphertext[0:16]
    enc_data = ciphertext[16:]
    master = PBKDF2(passphrase, salt, 10000, 16)
    keys = generate_round_keys(master, rounds)
    padded = CBC_Feistel_Decrypt(enc_data, keys, iv)
    bytes = pkcs7_unpad(padded)
    if bytes == "INVALID PADDING":
        return "DECRYPTION FAILED - Invalid padding"
    return map_from_bytes(bytes)
Quick instruction for Developer: You only need to fill in the CBC_Feistel_Encrypt/Decrypt loops (standard Feistel CBC – 15 lines each) and the two map functions. Everything else is copy-paste.

3. Input / Output Definitions
Encrypt (no OTP needed – public) Input:
•	plaintext: string (mixed EN/RO)
•	passphrase: string
•	salt: 16 random bytes (generated once per user)
•	rounds: integer (8–12)
Output:
•	ciphertext: byte string = IV (16 bytes) + encrypted blocks
Decrypt (protected) Input:
•	ciphertext: byte string (IV + data)
•	passphrase: string
•	salt: 16 bytes
•	otp: 6-digit string
•	totp_secret: shared secret (your Face ID part supplies this)
•	rounds: integer
Output:
•	plaintext: string OR "ACCESS DENIED - Invalid OTP"
