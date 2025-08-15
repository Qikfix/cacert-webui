import os
print(f"FULL CoMMAND HERE: cat /tmp/wally/intermediate/certs/intermediate.cert.pem /tmp/wally/certs/ca.cert.pem > /tmp/wally/intermediate/certs/ca-chain.cert.pem")
os.system("cat /tmp/wally/intermediate/certs/intermediate.cert.pem /tmp/wally/certs/ca.cert.pem > /tmp/wally/intermediate/certs/ca-chain.cert.pem")
