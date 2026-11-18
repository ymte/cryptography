macos:
	cargo build --release

windows:
	RUSTC="$$(rustup which rustc)" \
	"$$(rustup which cargo)" build --release \
	--target x86_64-pc-windows-gnu

