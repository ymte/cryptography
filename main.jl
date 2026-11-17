using Random
using Sockets
using CRC32c
include("AES.jl")
include("ChaCha20.jl")
include("ffdhe.jl")
include("SHA-512.jl")

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

function unpad(padded)
	padded = copy(padded)
    pad = Int(padded[end])

    1 <= pad <= 64 ||
        throw(ArgumentError("Invalid padding"))

    all(==(UInt8(pad)), padded[end-pad+1:end]) ||
        throw(ArgumentError("Invalid padding"))

    resize!(padded, length(padded)-pad)
	return padded
end

function pad(plaintext)
    pad = 64 - mod(length(plaintext), 64)
    padded = vcat(Vector{UInt8}(plaintext),
                fill(UInt8(pad), pad))
	return padded
end

function decrypt(ciphertext :: Vector{UInt8}, key :: BigInt)
	plaintext = Vector{UInt8}()

    for i in 1:64:length(ciphertext)
        block = ciphertext[i:i+64-1]
		data = block .⊻ sha512(key + i)
        append!(plaintext, data)
    end

    # Remove PKCS#7 padding
	plaintext = unpad(plaintext)
	String(plaintext)
end

function encrypt(plaintext :: String, key :: BigInt)
	plaintext = pad(collect(codeunits(plaintext)))

    ciphertext = UInt8[]

    for i in 1:64:length(plaintext)
        block = plaintext[i:i+64-1]
		data = block .⊻ sha512(key+i)
        append!(ciphertext, data)
    end

	ciphertext
end

@assert decrypt(encrypt("hoi", big(3)), big(3)) == "hoi"


# chat
function chat(sock, key, isclient)
	local clientoffset = isclient ? 1_000_000 : 0
	local serveroffset = isclient ? 0 : 1_000_000

	# receive
	@async begin
		local index = 1
		try
			while true
				data = readline(sock)
				plainmessage = decrypt(hex2bytes(data), key+clientoffset+index)
				hash,plaintext = split(plainmessage, ' ', limit=2)
				hash = parse(BigInt, hash)
				if crc32c(string(plaintext)) != hash
					error("Tamper detected!")
				end
				println(plaintext)
				index += 1
			end
		catch e
			# println(e)
			exit()
		end
	end

	# send
	@async begin
		local index = 1
		while true
			try
				local plaintext = readline()
				local plainmessage = string(crc32c(plaintext)) * ' ' * plaintext
				local data = encrypt(plainmessage, key + serveroffset + index)
				write(sock, bytes2hex(data) * '\n')
				index += 1
			catch e
				# println(e)
				exit()
			end
		end
	end
end

function kex(socket, a)
	g = 2
	p = ffdhe8192

	# g^a % p
	A = powermod(g, a, p)

	# send A
	write(socket, string(A)*'\n')

	# receive B
	B = parse(BigInt, readline(socket))

	# calculate shared secret
	s = powermod(B, a, p)

	return s
end

# server
if length(ARGS) == 0
	errormonitor(@async begin
		println("listening...")
		server = listen(IPv6(0),2000)
		socket = accept(server)
		println("accepted")

		rng = RandomDevice()
		a = rand(rng, big(1):big(2)^400)
		s = kex(socket, a)
		println("secret ", s % 1_000_000)

		# calculate key
		key = mod(s, big(2)^512)

		# chat
		chat(socket, key, false)
	end)
end

# client
if length(ARGS) > 0
	errormonitor(@async begin
		println("connecting...")
		socket = connect(ARGS[1], 2000)
		println("connected")

		rng = RandomDevice()
		b = rand(rng, big(1):big(2)^400)
		s = kex(socket, b)
		println("secret ", s % 1_000_000)

		# calculate key
		key = mod(s, big(2)^512)

		# chat
		chat(socket, key, true)

	end)
end

sleep(1e10)
