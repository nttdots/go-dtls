# dtls client

# compile

## wolfssl
git clone https://github.com/wolfSSL/wolfssl.git
./autogen.sh
./configure --enable-dtls --enable-debug
make
make install

## wolfssl_test4
cd wolfssl_test4
go build

./wolfssl_test4
