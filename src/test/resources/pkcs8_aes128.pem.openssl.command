openssl genpkey -algorithm RSA -aes-128-cbc -pass pass:password -pkeyopt rsa_keygen_bits:4096 -out pkcs8_aes128.pem
