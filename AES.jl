using Test

const AES_SBOX = UInt8[
    # AES substitution box
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,
    0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,
    0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,
    0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,
    0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,
    0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,
    0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,
    0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,
    0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,
    0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,
    0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,
    0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,
    0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,
    0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,
    0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,
    0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,
    0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16
]

xtime(x::UInt8) = (x << 1) ⊻ ((x & 0x80) != 0 ? 0x1b : 0x00)

function subword(w)
    ntuple(i -> AES_SBOX[Int(w[i])+1], 4)
end

function rotword(w)
    (w[2], w[3], w[4], w[1])
end

function aes_expand_key(key::Vector{UInt8})
    length(key) == 32 || throw(ArgumentError("AES-256 requires 32-byte key"))

    w = Vector{NTuple{4,UInt8}}(undef, 60)

    for i in 1:8
        w[i] = Tuple(key[4i-3:4i])
    end

    rcon = UInt8(1)

    for i in 9:60
        t = w[i-1]

        if (i-1) % 8 == 0
            t = subword(rotword(t))
            t = (t[1] ⊻ rcon, t[2], t[3], t[4])
            rcon = xtime(rcon)
        elseif (i-1) % 8 == 4
            t = subword(t)
        end

        prev = w[i-8]
        w[i] = ntuple(j -> prev[j] ⊻ t[j], 4)
    end

    return w
end

function aes_encrypt_block(block::Vector{UInt8}, w)
    length(block) == 16 || throw(ArgumentError("Block must be 16 bytes"))

    s = copy(block)

    function addkey!(round)
        for c in 0:3, r in 0:3
            s[4c+r+1] ⊻= w[4round+c+1][r+1]
        end
    end

    function subbytes!()
        for i in eachindex(s)
            s[i] = AES_SBOX[Int(s[i])+1]
        end
    end

    function shiftrows!()
        old = copy(s)
        for r in 0:3, c in 0:3
            s[4c+r+1] = old[4mod(c+r,4)+r+1]
        end
    end

    function mixcolumns!()
        for c in 0:3
            i = 4c+1
            a,b,c1,d = s[i:i+3]
            t = a ⊻ b ⊻ c1 ⊻ d
            s[i]   = a ⊻ t ⊻ xtime(a ⊻ b)
            s[i+1] = b ⊻ t ⊻ xtime(b ⊻ c1)
            s[i+2] = c1 ⊻ t ⊻ xtime(c1 ⊻ d)
            s[i+3] = d ⊻ t ⊻ xtime(d ⊻ a)
        end
    end

    addkey!(0)

    for round in 1:13
        subbytes!()
        shiftrows!()
        mixcolumns!()
        addkey!(round)
    end

    subbytes!()
    shiftrows!()
    addkey!(14)

    return s
end

function encrypt(plaintext::AbstractVector{UInt8},
                 key::AbstractVector{UInt8})

    length(key) == 32 ||
        throw(ArgumentError("AES-256 requires a 32-byte key"))

    w = aes_expand_key(Vector{UInt8}(key))

    # PKCS#7 padding
    pad = 16 - mod(length(plaintext), 16)
    data = vcat(Vector{UInt8}(plaintext),
                fill(UInt8(pad), pad))

    ciphertext = UInt8[]

    for i in 1:16:length(data)
        block = data[i:i+15]
        append!(ciphertext, aes_encrypt_block(block, w))
    end

    return ciphertext
end

function encrypt(plaintext::String, key::BigInt)
	key = bigint_to_bytes(key, 32)
	plaintext = collect(codeunits(plaintext))
	encrypt(plaintext, key)
end


function aes_inv_subbytes!(s)
    for i in eachindex(s)
        idx = findfirst(==(s[i]), AES_SBOX)
        s[i] = UInt8(idx - 1)
    end
end

function aes_inv_shiftrows!(s)
    old = copy(s)
    for r in 0:3, c in 0:3
        s[4c+r+1] = old[4mod(c-r,4)+r+1]
    end
end

function gmul(a::UInt8, b::UInt8)
    result = UInt8(0)

    for _ in 1:8
        if (b & 1) != 0
            result ⊻= a
        end

        hi = a & 0x80
        a <<= 1

        if hi != 0
            a ⊻= 0x1b
        end

        b >>= 1
    end

    return result
end

function aes_inv_mixcolumns!(s)
    for c in 0:3
        i = 4c+1
        a,b,c1,d = s[i:i+3]

        s[i]   = gmul(a,0x0e) ⊻ gmul(b,0x0b) ⊻
                 gmul(c1,0x0d) ⊻ gmul(d,0x09)

        s[i+1] = gmul(a,0x09) ⊻ gmul(b,0x0e) ⊻
                 gmul(c1,0x0b) ⊻ gmul(d,0x0d)

        s[i+2] = gmul(a,0x0d) ⊻ gmul(b,0x09) ⊻
                 gmul(c1,0x0e) ⊻ gmul(d,0x0b)

        s[i+3] = gmul(a,0x0b) ⊻ gmul(b,0x0d) ⊻
                 gmul(c1,0x09) ⊻ gmul(d,0x0e)
    end
end

function aes_decrypt_block(block::Vector{UInt8}, w)
    length(block) == 16 ||
        throw(ArgumentError("Block must be 16 bytes"))

    s = copy(block)

    function addkey!(round)
        for c in 0:3, r in 0:3
            s[4c+r+1] ⊻= w[4round+c+1][r+1]
        end
    end

    addkey!(14)

    for round in 13:-1:1
        aes_inv_shiftrows!(s)
        aes_inv_subbytes!(s)
        addkey!(round)
        aes_inv_mixcolumns!(s)
    end

    aes_inv_shiftrows!(s)
    aes_inv_subbytes!(s)
    addkey!(0)

    return s
end

function decrypt(ciphertext::AbstractVector{UInt8},
                 key::AbstractVector{UInt8})

    length(key) == 32 ||
        throw(ArgumentError("AES-256 requires a 32-byte key"))

    isempty(ciphertext) && throw(ArgumentError("Empty ciphertext"))

    length(ciphertext) % 16 == 0 ||
        throw(ArgumentError("Invalid ciphertext length"))

    w = aes_expand_key(Vector{UInt8}(key))

    plaintext = UInt8[]

    for i in 1:16:length(ciphertext)
        block = Vector{UInt8}(ciphertext[i:i+15])
        append!(plaintext, aes_decrypt_block(block, w))
    end

    # Remove PKCS#7 padding
    pad = Int(plaintext[end])

    1 <= pad <= 16 ||
        throw(ArgumentError("Invalid padding"))

    all(==(UInt8(pad)), plaintext[end-pad+1:end]) ||
        throw(ArgumentError("Invalid padding"))

    resize!(plaintext, length(plaintext)-pad)

    return String(plaintext)
end

function decrypt(ciphertext::AbstractVector{UInt8}, key::BigInt)
	decrypt(ciphertext, bigint_to_bytes(key, 32))
end

function decrypt(ciphertext::String, key::BigInt)
	ciphertext = collect(codeunits(ciphertext))
	decrypt(ciphertext, key)
end


function bigint_to_bytes(x::BigInt, n::Int)
    x >= 0 || throw(ArgumentError("Negative integers not supported"))
    n >= 0 || throw(ArgumentError("Width must be non-negative"))

    x < (BigInt(1) << (8*n)) ||
        throw(ArgumentError("Integer does not fit in $n bytes"))

    bytes = Vector{UInt8}(undef, n)

    for i in n:-1:1
        bytes[i] = UInt8(x & 0xff)
        x >>= 8
    end

    return bytes
end
