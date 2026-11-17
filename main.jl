using Random
using Sockets
using CRC32c
using SHA
include("ffdhe.jl")

function sha512_bigint(int::BigInt)
    bytes = Vector{UInt8}()
    for i=1:64
        push!(bytes, UInt8(int % 256))
        int ÷= 256
    end
    sha512(bytes)
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

@assert unpad(pad([1,2,3])) == [1,2,3]
@assert length(pad([1,2,3])) == 64


function decrypt(ciphertext :: Vector{UInt8}, key :: BigInt)
	plaintext = Vector{UInt8}()

    for i in 1:64:length(ciphertext)
        block = ciphertext[i:i+64-1]
		data = block .⊻ sha512_bigint(key + i)
        append!(plaintext, data)
    end

	plaintext = unpad(plaintext)
	String(plaintext)
end

function encrypt(plaintext :: String, key :: BigInt)
	plaintext = pad(collect(codeunits(plaintext)))

    ciphertext = UInt8[]

    for i in 1:64:length(plaintext)
        block = plaintext[i:i+64-1]
		data = block .⊻ sha512_bigint(key+i)
        append!(ciphertext, data)
    end

	ciphertext
end

@assert decrypt(encrypt("hoi", big(3)), big(3)) == "hoi"

function kex(socket)
	device = RandomDevice()
	a = rand(device, big(1):big(2)^512)

	g = 2
	p = ffdhe8192

	# g^a % p
	A = powermod(g, a, p)

	# send A
	write(socket, string(A) * '\n')

	# receive B
	B = parse(BigInt, readline(socket))

	# calculate shared secret
	s = powermod(B, a, p)

	return s
end

function decode(hex, key)
	data = hex2bytes(hex)
	message = decrypt(data, key)
	hash,plaintext = split(message, ' ', limit=2)
	hash = parse(Int, hash)
	@assert crc32c(string(plaintext)) == hash
	return plaintext
end
	
function encode(plaintext, key)
	message = string(crc32c(plaintext)) * ' ' * plaintext
	data = encrypt(message, key)
	hex = bytes2hex(data)
	return hex
end

@assert decode(encode("hoi", big(3)), big(3)) == "hoi"


# server
global isclient
global socket
if length(ARGS) == 0
	isclient = false
	println("listening...")
	server = listen(IPv6(0),2000)
	socket = accept(server)
	println("accepted")
else
	isclient = true
	println("connecting...")
	socket = connect(ARGS[1], 2000)
	println("connected")
end

secret = kex(socket)
println("secret ", secret % 1_000_000_000)

# calculate key
key = secret % big(2)^512

# chat
clientoffset =  isclient ? 0 : 1_000_000_000
serveroffset = !isclient ? 0 : 1_000_000_000

# receive
@async begin
	index = 1
	try
		while true
			hex = readline(socket)
			if hex == ""
				println("disconnected")
				exit()
			end
			plaintext = decode(hex, key + clientoffset + index)
			println(plaintext)
			index += 1
		end
	catch
		println("protocol error")
		exit()
	end
end

# send
@async begin
	index = 1
	while true
		plaintext = readline()
		if plaintext == ""
			exit()
		end
		hex = encode(plaintext, key + serveroffset + index)
		println(socket, hex)
		index += 1
	end
end

sleep(1e10)
