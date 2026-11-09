using Random
using Sockets
using CRC32c
include("AES.jl")
include("ChaCha20.jl")
include("ffdhe.jl")
include("SHA-512.jl")

p = ffdhe8192
g = 2
port = 2000

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

function decrypt(ciphertext :: Vector{UInt8}, key :: BigInt)
	plaintext = Vector{UInt8}()
	key = sha512(key)

    for i in 1:64:length(ciphertext)
        block = ciphertext[i:i+64-1]
		cipherchar = parse(BigInt, "0x"*bytes2hex(block))
		plainchar = cipherchar ⊻ key
		data = bigint_to_bytes(plainchar, 64)
        append!(plaintext, data)
		key = sha512(key)
    end

    # Remove PKCS#7 padding
    pad = Int(plaintext[end])

    1 <= pad <= 64 ||
        throw(ArgumentError("Invalid padding"))

    all(==(UInt8(pad)), plaintext[end-pad+1:end]) ||
        throw(ArgumentError("Invalid padding"))

    resize!(plaintext, length(plaintext)-pad)

	String(plaintext)
end

function encrypt(plaintext :: String, key :: BigInt)
	plaintext = collect(codeunits(plaintext))
	key = sha512(key)

    # PKCS#7 padding
    pad = 64 - mod(length(plaintext), 64)
    plaintext = vcat(Vector{UInt8}(plaintext),
                fill(UInt8(pad), pad))

    ciphertext = UInt8[]

    for i in 1:64:length(plaintext)
        block = plaintext[i:i+64-1]
		plainchar = parse(BigInt, "0x"*bytes2hex(block))
		cipherchar = plainchar ⊻ key
		data = bigint_to_bytes(cipherchar, 64)
        append!(ciphertext, data)
		key = sha512(key)
    end

	ciphertext
end


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
				if sha512(string(plaintext)) != hash
					error("Tamper detected!")
				end
				println(plaintext)
				index += 1
			end
		catch e
			println(e)
			exit()
		end
	end

	# send
	@async begin
		local index = 1
		while true
			try
				local plaintext = readline()
				local plainmessage = string(sha512(plaintext)) * ' ' * plaintext
				local data = encrypt(plainmessage, key + serveroffset + index)
				write(sock, bytes2hex(data) * '\n')
				index += 1
			catch e
				println(e)
				exit()
			end
		end
	end
end

# server
if length(ARGS) == 0
	errormonitor(@async begin
		rng = RandomDevice()
		a = rand(rng, big(1):big(2)^400)

		# g^a mod p
		A = powermod(g, a, p)

		println("listening...")
		server = listen(IPv6(0),port)
		sock = accept(server)
		println("accepted")

		# send A
		write(sock, string(A)*'\n')

		# receive B
		B = parse(BigInt, readline(sock))

		# calculate shared secret
		s = powermod(B, a, p)
		println("secret ", s % 1_000_000)

		# calculate key
		key = mod(s, big(2)^512)

		# chat HIER
		chat(sock, key, false)
	end)
end

# client
if length(ARGS) > 0
	errormonitor(@async begin
		rng = RandomDevice()
		b = rand(rng, big(1):big(2)^400)

		# g^b mod p
		B = powermod(g, b, p)

		println("connecting...")
		sock = connect(ARGS[1], port)
		println("connected")

		# send B
		write(sock, string(B)*'\n')

		# receive A
		A = parse(BigInt, readline(sock))

		# calculate shared secret
		s = powermod(A, b, p)
		println("secret ", s % 1_000_000)

		# calculate key
		key = mod(s, big(2)^512)

		# chat
		chat(sock, key, true)

	end)
end

sleep(1e10)
