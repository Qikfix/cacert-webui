import os
print(f"FULL CoMMAND HERE: openssl ca -config DATA/intermediate/openssl.cnf -extensions server_cert -days 300 -notext -md sha256 -in /tmp/uploaded_cert_csr.pem -out /tmp/signed.crt -passin pass:waldirio123")
os.system("openssl ca -config DATA/intermediate/openssl.cnf -extensions server_cert -days 300 -notext -md sha256 -in /tmp/uploaded_cert_csr.pem -out /tmp/signed.crt -passin pass:waldirio123")
