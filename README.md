# cacert-webui
#### Video Demo:  [https://www.youtube.com/watch?v=6jOLHCiBOxg](https://www.youtube.com/watch?v=6jOLHCiBOxg)
#### Description:
The main idea of this project is to mimic the `ROOT CA`, `Intermediate CA`, and also the `Server CA`, passing through all the steps to:
- Create the folder structure
- Sign the files
- Improve the certificate knowledge

#### Use Case:
For those professionals who need to create a local `ROOT CA` to sign your own certificates, for troubleshooting, studies, labs, or any other purpose that you can think about, when talking about SSL/TLS/Certificates.

For me specifically, when working with `Red Hat Satellite`, or `Foreman`, enventually, I need to create custom certs to move on with my tests, and this tool will for sure help me in this process, making easier this certificate request `CSR`, and signing steps.

#### Code Structure:
For this application, I'm working with `Flask`, and the code was also divided in module, that I'm calling `cacert`

Also, after some implementation, I noticed that the lack of organization about the endpoints were causing issues, and then, I defined an standard
```
root ca
- /root_main
- /root_create
- /root_delete
- /root_verify

Intermediate
- /intermediate_main
- /intermediate_create
- /intermediate_delete
- /intermediate_verify
- /intermediate_verify_against_root_ca

bundle
- /bundle_main
- /bundle_download (nops)
- /bundle_view (nops)

sign certificate
- /sign_certificate_main
- /sign_certificate_upload_sign
- /sign_certificate_download
- /sign_certificate_view

custom ssl certificate
- /custom_ssl_certificate_main
- /custom_ssl_certificate_create
- /custom_ssl_certificate_delete
- /custom_ssl_certificate_view
- /custom_ssl_certificate_verify
```

At this moment, I'm not using all of them, but for sure, the nomenclature helped, specially when doing troubleshootings.

#### Functions:

##### Functions under `app.py`
- `sign_certificate_main()`
  - Endpoint to handle all the sign certificate calls. Visualization, deletion, and signing.
- `bundle_main()`
  - Endpoint to handle all the bundle/ca-chain certificate calls. Visualization, and download.
- `intermediate_delete()`
  - Endpoint responsible to remove the intermediate folder, and also responsible to revoke the certificate that was signed for that specific intermediate. Any time that a new one is created, a new `ID` is created, and any time that the intermediate is removed, the respective `ID` is also revoked.
- `root_delete()`
  - Endpoint responsible to remove the entire structure, including the `ROOT CA`, and the `Intermediate CA` as well.
- `intermediate_verify_against_root_ca()`
  - Enpoint responsible to verify if the `Intermediate CA` certificate is ok, when checking it against the `ROOT CA`
- `intermediate_verify()`
  - Endpoint responsible to verify the `Intermediate CA` certificate.
- `root_verify()`
  - Endpoint responsible to verify the `ROOT CA` certificate.
- `root()`
  - Endpoint responsible for the `ROOT CA` structure, certificates, and anything related to the `ROOT CA`
- `intermediate()`
  - Endpoint responsible for the `Intermediate CA` structure, certificates, and anything related to the `Intermediate CA`.
- `index()`
  - Endpoint "/", where the first call will land.
- `web()`
  - Endpoint for testing the web template
- `root_ca()`
  - Endpoint that will open the `ROOT CA` web page
- `intermediate_ca()`
  - Endpoint that will open the `Intermediate CA` web page
- `github()`
  - Endpoint that will open the `GitHub` web page
- `custom_ssl_certificate_main()`
  - Endpoint that will open the `Custom SSL Certificate` main web page
- `custom_ssl_certificate_create()`
  - Endpoint that will open the `Custom SSL Certificate` create web page
- `custom_ssl_certificate_delete()`
  - Endpoint that will open the `Custom SSL Certificate` delete web page


##### Functions under `cacert/cacert.py`

- `verify_signed_certificate()`
  - Function responsible for verify the signed certificates
- `sign_csr_cert()`
  - Function responsible for sign the CSR certificates
- `upload_cert_file(files)`
  - Function responsible for uploading the certificate file (CSR)
- `delete_root_folder(response, main_dir)`
  - Function responsible for deleting the whole `DATA` structure, removing the `ROOT CA`, and `Intermediate CA` as well.
- `checking_folder(main_dir, kind=None)`
  - Function responsible for checking if the folder is already around.
- `prepare_the_directory(main_dir, kind=None)`
  - Function responsible for preparing the folder, in case the same is not around.
- `prepare_the_configuration_file(dir, countryName="CA", stateOrProvinceName="British Columbia", localityName="Vancouver", organizationName="Wally's ACME", organizationalUnitName="IT", commonName="", emailAddress="user@king.lab", private_key="ca.key.pem", certificate="ca.cert.pem", crl="ca.crl.pem", policy="policy_loose")`
  - Function responsible for preparing the `openssl.cnf`
- `revoke_intermediate()`
  - Function responsible for `revoke` the intermediate, whenever removing the `Intermediate CA` folder.
- `create_the_root_key(main_dir, output_file, password, key_size=4096)`
  - Function responsible for the `ROOT CA` key creation
- `create_the_root_certificate(main_dir)`
  - Function responsible for the `ROOT CA` certificate creation
- `verify_the_root_certificate(main_dir)`
  - Function responsible for verify the `ROOT CA` certificate
- `create_the_intermediate_key(main_dir, password)`
  - Function responsible for the creation of the `Intermediate CA` key
- `create_the_intermediate_certificate(main_dir, password)`
  - Function responsible for the creation of the `Intermediate CA` certificate
- `verify_the_intermediate_certificate(main_dir)`
  - Function responsible for the `Intermediate CA` certificate verification
- `verify_the_intermediate_certificate_against_root_ca(main_dir)`
  - Function responsible for the verify of the `Intermediate CA` certificate, against the `ROOT CA`
- `create_the_certificate_chain(main_dir)`
  - Function responsible for the creation of the `certificate chain` or `bundle`
- `download_bundle_from_intermediate()`
  - Function responsible for `download` the bundle
- `view_bundle_from_intermediate()`
  - Function responsible for `view` the bundle
- `custom_ssl_certificate_create_flow(dns1, dns2, dns3, countryName, stateOrProvinceName, localityName, organizationName, organizationalUnitName, commonName)`
  - Function responsible for creation of the `custom ssl certificate`
- `list_of_custom_certs()`
  - Function responsible for listing all the `custom certs`, based on the `directory` listing.


#### References:
- Python
  - https://docs.python.org/
- Flask
  - https://flask.palletsprojects.com/
- Jinja
  - https://jinja.palletsprojects.com/


#### Container Friendly
Soon, I'll add the steps that you can follow, and just download the container, which will allow you to be executing this environment, with no further work. If you are already a `podman` or `docker` user, it should be very easy for you.

I'll keep you posted about it!


#### How to Contribute?
Please, feel free to share your ideas, feedbacks, via Issue on this project, or even via email `waldirio@gmail.com`. It will be a pleasure, and very welcome.

Thank you in advance!
Waldirio