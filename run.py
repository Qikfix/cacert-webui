import os
print(f"FULL CoMMAND HERE: openssl x509 -req -in /tmp/uploaded_cert_csr.pem -CA /tmp/wally/certs/ca.cert.pem -CAkey /tmp/wally/private/ca.key.pem -out /tmp/signed.crt -days 500 -sha256 -passin pass:waldirio123 -CAcreateserial")
os.system("openssl x509 -req -in /tmp/uploaded_cert_csr.pem -CA /tmp/wally/certs/ca.cert.pem -CAkey /tmp/wally/private/ca.key.pem -out /tmp/signed.crt -days 500 -sha256 -passin pass:waldirio123 -CAcreateserial")
