# DTLS server

# compile

## wolfssl
git clone https://github.com/wolfSSL/wolfssl.git
./autogen.sh
./configure --enable-dtls --enable-debug
make
make install

## wolfssl_test2
cd wolfssl_test2
go build

./wolfssl_test2
