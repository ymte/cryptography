# 32-bit rotatie naar links
function rotl(a::UInt32, b::Int)
    return (a << b) | (a >> (32 - b))
end

# ChaCha quarter-round
function quarterround!(x::Vector{UInt32}, a::Int, b::Int, c::Int, d::Int)
    x[a] += x[b]
    x[d] ⊻= x[a]
    x[d] = rotl(x[d], 16)

    x[c] += x[d]
    x[b] ⊻= x[c]
    x[b] = rotl(x[b], 12)

    x[a] += x[b]
    x[d] ⊻= x[a]
    x[d] = rotl(x[d], 8)

    x[c] += x[d]
    x[b] ⊻= x[c]
    x[b] = rotl(x[b], 7)
end

# ChaCha20 blockfunctie
function chacha_block(input::Vector{UInt32})
    @assert length(input) == 16 "Input moet 16 UInt32-woorden bevatten"

    x = copy(input)

    # 20 rondes: 10 column + diagonal rondes
    for i in 1:2:20
        # Column rounds
        quarterround!(x, 1, 5, 9, 13)
        quarterround!(x, 2, 6, 10, 14)
        quarterround!(x, 3, 7, 11, 15)
        quarterround!(x, 4, 8, 12, 16)

        # Diagonal rounds
        quarterround!(x, 1, 6, 11, 16)
        quarterround!(x, 2, 7, 12, 13)
        quarterround!(x, 3, 8, 9, 14)
        quarterround!(x, 4, 5, 10, 15)
    end

    # Optellen bij de oorspronkelijke input (modulo 2^32)
    for i in 1:16
        x[i] += input[i]
    end

    return x
end

function bigint_to_uint32(value::BigInt; nwords::Int=16)
    @assert value >= 0 "BigInt moet niet-negatief zijn"
    @assert nwords > 0 "nwords moet groter zijn dan 0"
    @assert value < (big(1) << (32 * nwords)) "BigInt is te groot"

    result = Vector{UInt32}(undef, nwords)
    mask = big(0xffffffff)

    for i in 1:nwords
        result[i] = UInt32((value >> (32 * (i - 1))) & mask)
    end

    return result
end


function uint32_to_bigint(words::Vector{UInt32})
    result = big(0)

    for i in eachindex(words)
        result |= BigInt(words[i]) << (32 * (i - 1))
    end

    return result
end

function ChaCha20(input :: BigInt)
	words = bigint_to_uint32(input)
	encrypted = chacha_block(words)
	uint32_to_bigint(encrypted)
end
