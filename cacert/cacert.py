"""
docstring here
"""

import shutil
import os
import subprocess
from jinja2 import Environment, FileSystemLoader
from werkzeug.utils import secure_filename


# main_dir = input("Which directory would you like to use as main dir (It should be empty)?: ")
main_dir = "/tmp/wally"

file_loader = FileSystemLoader('templates')
env = Environment(loader=file_loader)

UPLOAD_FOLDER = "uploads"

def sign_csr_cert():
    # openssl x509 -req -in ../satellite_cert/satellite_cert_csr.pem -CA certs/ca.cert.pem -CAkey private/ca.key.pem -out /tmp/satellite_cert/satellite.crt -days 500 -sha256
    # openssl x509 -req -in /uploads/FILE_NAME_HERE -CA MAIN_DIR/certs/ca.cert.pem -CAkey MAIN_DIR/private/ca.key.pem -out /static/SIGNED.CRT -days 500 -sha256
    print(f"main_dir: {main_dir}")

    uploaded_cert_csr = "/tmp/uploaded_cert_csr.pem"
    output_signed_file = "/tmp/signed.crt"


    input_to_send = b"\n\n\n\n\n\n\n"
    try:
        command = "openssl x509 -req -in " + uploaded_cert_csr + " -CA " + main_dir + "/certs/ca.cert.pem -CAkey " + main_dir + "/private/ca.key.pem -out " + output_signed_file + " -days 500 -sha256 -passin pass:waldirio123 -CAcreateserial"

        template = env.get_template('run.py.template')
        output = template.render(command=command)
        with open("run.py", "w") as fp:
            print(output, file=fp)

        command = "run.py"
        print()
        print(command)
        process = subprocess.Popen(['python3', command], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

        # stdout_data, stderr_data = process.communicate(input=input_to_send)
        stdout_data, stderr_data = process.communicate()
        print(f"stdout: {stdout_data}")
        print(f"stderr: {stderr_data}")

    except subprocess.CalledProcessError as e:
        print(e)
    except FileNotFoundError:
        print("openssl not found")
    
    shutil.copy(output_signed_file, "static/signed.crt")


def upload_cert_file(files):
    # Create the upload folder if it doesn't exist
    if not os.path.exists(UPLOAD_FOLDER):
        os.makedirs(UPLOAD_FOLDER)
        
    print(f"files: {files}")
    if files:
        for file in files:
            filename = secure_filename(file.filename)
            if os.path.exists(UPLOAD_FOLDER + "/" + filename):
                print(f"AuDIT: File around, removing it")
                os.remove(UPLOAD_FOLDER + "/" + filename)
                file.save(os.path.join(UPLOAD_FOLDER, filename))
                # For the temporary file under /tmp
                shutil.copy(os.path.join(UPLOAD_FOLDER, filename), "/tmp/uploaded_cert_csr.pem")
            else:
                print(f"AuDIT: New file!")
                file.save(os.path.join(UPLOAD_FOLDER, filename))
                # For the temporary file under /tmp
                shutil.copy(os.path.join(UPLOAD_FOLDER, filename), "/tmp/uploaded_cert_csr.pem")



def delete_root_folder(response, main_dir):
    print(f"Here: {response} {main_dir}")
    if response == "yes":
        try:
            shutil.rmtree(main_dir)
            return True
        except FileNotFoundError as err:
            return err
        

def checking_folder(main_dir, kind=None):
    """
    docstring here
    """
    if os.path.isdir(main_dir):
        print("this folder exists")
        if len(os.listdir(main_dir)) == 0:
            print("this is an empty dir")
            prepare_the_directory()
        else:
            print("this is NOT an empty dir")
            print("exiting ...")
            # exit(1)
            # 10 means not an empty dir
            return 10
    else:
        print("this folder DOES NOT exists, creating it")
        try:
            os.mkdir(main_dir)
        except FileNotFoundError as err:
            return err
        prepare_the_directory(main_dir, kind)


# Prepare the directory
def prepare_the_directory(main_dir, kind=None):
    """
    docstring here
    """
    if kind == "intermediate":
        os.mkdir(main_dir + "/csr")
    os.mkdir(main_dir + "/certs")
    os.mkdir(main_dir + "/crl")
    os.mkdir(main_dir + "/newcerts")
    os.mkdir(main_dir + "/private")
    os.chmod(main_dir + "/private", 0o700)
    index_file = "index.txt"
    open(main_dir + "/" + index_file, "w").close()
    serial_file = "serial"
    with open(main_dir + "/" + serial_file, "w") as filep:
        filep.write("1000\n")


# Prepare the configuration file
def prepare_the_configuration_file(dir, countryName="CA", stateOrProvinceName="British Columbia", localityName="Vancouver", organizationName="Wally's ACME", organizationalUnitName="IT", commonName="", emailAddress="user@king.lab", private_key="ca.key.pem", certificate="ca.cert.pem", crl="ca.crl.pem", policy="policy_strict"):
    """
    docstring here
    """
    template = env.get_template('openssl.cnf.template')
    output = template.render(dir=dir, countryName=countryName, stateOrProvinceName=stateOrProvinceName, localityName=localityName, organizationName=organizationName, organizationalUnitName=organizationalUnitName, commonName=commonName, emailAddress=emailAddress, private_key=private_key, certificate=certificate, crl=crl, policy=policy)
    with open(dir + "/" + "openssl.cnf", "w") as fp:
        print(output, file=fp)


# Create the Root Key
def create_the_root_key(main_dir, output_file, password, key_size=4096):
    """
    docstring here
    """
    print("HERE")
    try:
        command = [
            "openssl",
            "genrsa",
            "-aes256",
            "-passout",
            f"pass:{password}",
            "-out",
            main_dir + "/" + output_file,
            str(key_size)
        ]
        result = subprocess.run(command, capture_output=True, text=True, check=True)
        print(result)

    except subprocess.CalledProcessError as e:
        print(e)
    except FileNotFoundError:
        print("openssl not found")

    os.chmod(main_dir + "/" + output_file, 0o400)


# Create the root certificate
def create_the_root_certificate(main_dir):
    """
    docstring here
    """
    input_to_send = b"\n\n\n\n\n\n\n"
    try:
        command = "openssl req -config " + main_dir + "/openssl.cnf -key " + main_dir + "/private/ca.key.pem -new -x509 -days 7300 -sha256 -extensions v3_ca -passin pass:waldirio123 -out " + main_dir + "/certs/ca.cert.pem"

        template = env.get_template('run.py.template')
        output = template.render(command=command)
        with open("run.py", "w") as fp:
            print(output, file=fp)

        command = "run.py"
        print()
        print(command)
        process = subprocess.Popen(['python3', command], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

        stdout_data, stderr_data = process.communicate(input=input_to_send)
        print(f"stdout: {stdout_data}")
        print(f"stderr: {stderr_data}")

    except subprocess.CalledProcessError as e:
        print(e)
    except FileNotFoundError:
        print("openssl not found")


# Verify the root certificate
def verify_the_root_certificate(main_dir):
    """
    docstring here
    """
    try:
        command = [
            "openssl",
            "x509",
            "-noout",
            "-text",
            "-in",
            main_dir + "/certs/ca.cert.pem"
        ]
        result = subprocess.run(command, capture_output=True, text=True, check=True)
        print(result.stdout)

    except subprocess.CalledProcessError as e:
        print(e)
    except FileNotFoundError:
        print("openssl not found")

    try:
        if result.stdout:
            return result.stdout
    except:
        return "Nothing here yet!"


def create_the_intermediate_key(main_dir, password):
    """
    docstring here
    """
    try:
        command = "openssl genrsa -aes256 -out " + main_dir + "/private/intermediate.key.pem 4096"
        command = [
            "openssl",
            "genrsa",
            "-aes256",
            "-passout",
            f"pass:{password}",
            "-out",
            main_dir + "/private/intermediate.key.pem",
            "4096"
        ]
        result = subprocess.run(command, capture_output=True, text=True, check=True)

    except subprocess.CalledProcessError as e:
        print(e)
    except FileNotFoundError:
        print("openssl not found")

    os.chmod(main_dir + "/private/intermediate.key.pem", 0o400)


def create_the_intermediate_certificate(main_dir, password):
    """
    docstring here
    """
    print("AUDIT - HERE")
    print(f"main_dir: {main_dir}")
    print(f"password: {password}")
    input_to_send = b"\n\n\n\n\n\n\n"
    try:
        command = "openssl req -config " + main_dir + "/openssl.cnf -new -sha256 -key " + main_dir + "/private/intermediate.key.pem -passin pass:" + password + " -out " + main_dir + "/csr/intermediate.csr.pem"

        template = env.get_template('run.py.template')
        output = template.render(command=command)
        with open("run.py", "w") as fp:
            print(output, file=fp)

        command = "run.py"
        print()
        print(command)
        process = subprocess.Popen(['python3', command], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

        stdout_data, stderr_data = process.communicate(input=input_to_send)
        print(f"stdout: {stdout_data}")
        print(f"stderr: {stderr_data}")

    except subprocess.CalledProcessError as e:
        print(e)
    except FileNotFoundError:
        print("openssl not found")

    input_to_send = b"y\ny\n"
    try:
        command = "openssl ca -config  " + main_dir + "/../openssl.cnf -extensions v3_intermediate_ca -days 3650 -notext -md sha256 -in  " + main_dir + "/csr/intermediate.csr.pem -passin pass:" + password + " -out  " + main_dir + "/certs/intermediate.cert.pem"

        template = env.get_template('run.py.template')
        output = template.render(command=command)
        with open("run.py", "w") as fp:
            print(output, file=fp)

        command = "run.py"
        print()
        print(command)
        process = subprocess.Popen(['python3', command], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

        stdout_data, stderr_data = process.communicate(input=input_to_send)
        print(f"stdout: {stdout_data}")
        print(f"stderr: {stderr_data}")

    except subprocess.CalledProcessError as e:
        print(e)
    except FileNotFoundError:
        print("openssl not found")

    #  wally
    os.chmod(main_dir + "/certs/intermediate.cert.pem", 0o444)


def verify_the_intermediate_certificate(main_dir):
    """
    docstring here
    """
    try:
        command = [
            "openssl",
            "x509",
            "-noout",
            "-text",
            "-in",
            main_dir + "/certs/intermediate.cert.pem"
        ]
        result = subprocess.run(command, capture_output=True, text=True, check=True)
        print(result.stdout)

    except subprocess.CalledProcessError as e:
        print(e)
    except FileNotFoundError:
        print("openssl not found")

    try:
        if result.stdout:
            return result.stdout
    except:
        return "Nothing here yet!"


def verify_the_intermediate_certificate_against_root_ca(main_dir):
    """
    docstring here
    """
    try:
        command = [
            "openssl",
            "verify",
            "-CAfile",
            main_dir + "/../certs/ca.cert.pem",
            main_dir + "/certs/intermediate.cert.pem"
        ]
        result = subprocess.run(command, capture_output=True, text=True, check=True)
        print(result.stdout)

    except subprocess.CalledProcessError as e:
        print(e)
    except FileNotFoundError:
        print("openssl not found")

    try:
        if result.stdout:
            return result.stdout
    except:
        return "Nothing here yet!"


def create_the_certificate_chain(main_dir):
    """
    docstring here
    """
    try:
        # command = "cat intermediate/certs/intermediate.cert.pem certs/ca.cert.pem > intermediates/certs/ca-chain.cert.pem"
        command = "cat " + main_dir + "/intermediate/certs/intermediate.cert.pem " + main_dir + "/certs/ca.cert.pem > " + main_dir + "/intermediate/certs/ca-chain.cert.pem"

        template = env.get_template('run.py.template')
        output = template.render(command=command)
        with open("run.py", "w") as fp:
            print(output, file=fp)

        command = "run.py"
        print()
        print(command)
        process = subprocess.Popen(['python3', command], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

        stdout_data, stderr_data = process.communicate()
        print(f"stdout: {stdout_data}")
        print(f"stderr: {stderr_data}")

    except subprocess.CalledProcessError as e:
        print(e)
    except FileNotFoundError:
        print("openssl not found")

    os.chmod(main_dir + "/intermediate/certs/ca-chain.cert.pem", 0o444)


def download_bundle_from_intermediate():
    
    if not os.path.exists("static/"):
        os.mkdir("static/")

    if os.path.exists("static/ca-chain.cert.pem"):
        print("removing and copying")
        os.remove("static/ca-chain.cert.pem")
        shutil.copy(main_dir + "/intermediate/certs/ca-chain.cert.pem", "static/ca-chain.cert.pem")
    else:
        print("just copying")
        shutil.copy(main_dir + "/intermediate/certs/ca-chain.cert.pem", "static/ca-chain.cert.pem")

def view_bundle_from_intermediate():
    with open("static/ca-chain.cert.pem", "r") as file:
        return file.read()
        # print(file)
    # return os.system("cat static/ca-chain.cert.pem")

# Main

## Create the root pair
# checking_folder(main_dir, kind="root") # this will call the def "prepare_the_directory()"
# prepare_the_configuration_file(main_dir, countryName="GB", stateOrProvinceName="England", localityName="", organizationName="Alice Ltd", organizationalUnitName="Alice Ltd Certificate Authority", commonName="Alice Ltd Root CA", emailAddress="")
# create_the_root_key(main_dir, "private/ca.key.pem", password="waldirio123")
# create_the_root_certificate(main_dir)
# verify_the_root_certificate(main_dir)


## Create the intermediate pair
# # Prepare the directory
# checking_folder(main_dir + "/intermediate", kind="intermediate") # this will call the def "prepare_the_directory()"

# # Copy the intermediate CA configuration file (openssl.cnf) and change for intermediate
# prepare_the_configuration_file(main_dir + "/intermediate", countryName="GB", stateOrProvinceName="England", localityName="", organizationName="Alice Ltd", organizationalUnitName="Alice Ltd Certificate Authority", commonName="Alice Ltd Intermediate CA", emailAddress="", private_key="intermediate.key.pem", certificate="intermediate.cert.pem", crl="intermediate.crl.pem", policy="policy_loose")

# # Create the intermediate key
# create_the_intermediate_key(main_dir + "/intermediate", password="waldirio123")

# # Create the intermediate certificate
# create_the_intermediate_certificate(main_dir + "/intermediate", password="waldirio123")

# # Verify the intermediate certificate
# verify_the_intermediate_certificate(main_dir + "/intermediate")

# verify_the_intermediate_certificate_against_root_ca(main_dir + "/intermediate")

# # Create the certificate chain file
# create_the_certificate_chain(main_dir)


## Sign server and client certificates
# Create a key
# Create a certificate
# Verify the certificate
# Deploy the certificate

## Certificate revocation lists
# Prepare the configuration file
# Create the CRL
# Revoke a certificate
# Server-side use of the CRL
# Client-side use of the CRL
