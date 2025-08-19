"""
docstring here
"""

import shutil
import os
import subprocess
from jinja2 import Environment, FileSystemLoader
from werkzeug.utils import secure_filename


# main_dir = input("Which directory would you like to use as main dir (It should be empty)?: ")
# main_dir = "/tmp/wally"
main_dir = "DATA/"
static = "static/"

# CSR and Signed Certs
uploaded_cert_csr = "/tmp/uploaded_cert_csr.pem"
output_signed_file = "/tmp/signed.crt"

file_loader = FileSystemLoader('templates')
env = Environment(loader=file_loader)

UPLOAD_FOLDER = "uploads"

def verify_signed_certificate():
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
            "/tmp/signed.crt"
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


def sign_csr_cert():
    """
    """
    # Working manually
    # openssl ca -config DATA/intermediate/openssl.cnf -extensions server_cert -days 300 -notext -md sha256 -in static/custom_ssl_certs/sat05.king.lab/csr_sat05.king.lab.pem -out static/custom_ssl_certs/sat05.king.lab/signed.crt

    print(f"main_dir: {main_dir}")

    # uploaded_cert_csr = "/tmp/uploaded_cert_csr.pem"
    # output_signed_file = "/tmp/signed.crt"

    # -extfile ../sat_cert/openssl.cnf -extensions v3_req

    input_to_send = b"y\ny\n"
    try:
        command = "openssl ca -config " + main_dir + "intermediate/openssl.cnf -extensions server_cert -days 300 -notext -md sha256 -in " + uploaded_cert_csr + " -out " + output_signed_file + " -passin pass:waldirio123"

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
    
    try:
        shutil.copy(output_signed_file, "static/signed.crt")
    except FileNotFoundError as err:
        print(f"ERROR: {err}")

    return str(stdout_data, encoding='utf-8'), str(stderr_data, encoding='utf-8')


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
# def prepare_the_configuration_file(dir, countryName="CA", stateOrProvinceName="British Columbia", localityName="Vancouver", organizationName="Wally's ACME", organizationalUnitName="IT", commonName="", emailAddress="user@king.lab", private_key="ca.key.pem", certificate="ca.cert.pem", crl="ca.crl.pem", policy="policy_strict"):
def prepare_the_configuration_file(dir, countryName="CA", stateOrProvinceName="British Columbia", localityName="Vancouver", organizationName="Wally's ACME", organizationalUnitName="IT", commonName="", emailAddress="user@king.lab", private_key="ca.key.pem", certificate="ca.cert.pem", crl="ca.crl.pem", policy="policy_loose"):
    """
    docstring here
    """
    print(f"AUDIT: dir: {dir}")
    template = env.get_template('openssl.cnf.template')
    output = template.render(dir=dir, countryName=countryName, stateOrProvinceName=stateOrProvinceName, localityName=localityName, organizationName=organizationName, organizationalUnitName=organizationalUnitName, commonName=commonName, emailAddress=emailAddress, private_key=private_key, certificate=certificate, crl=crl, policy=policy)
    with open(dir + "/" + "openssl.cnf", "w") as fp:
        print(output, file=fp)


def revoke_intermediate():
    """
    docstring here
    """
    # input_to_send = b"\n\n\n\n\n\n\n"
    try:
        # command = "openssl req -config " + main_dir + "/openssl.cnf -key " + main_dir + "/private/ca.key.pem -new -x509 -days 7300 -sha256 -extensions v3_ca -passin pass:waldirio123 -out " + main_dir + "/certs/ca.cert.pem"
        # command = "openssl ca -config /tmp/wally/openssl.cnf -revoke /tmp/wally/intermediate/certs/intermediate.cert.pem -passin pass:waldirio123"
        command = "openssl ca -config " + main_dir + "/openssl.cnf -revoke " + main_dir + "/intermediate/certs/intermediate.cert.pem -passin pass:waldirio123"
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

    except subprocess.CalledProcessError as err:
        print(err)
        return err

    except FileNotFoundError as err:
        print("openssl not found") 
        return err   

    return True


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
        command = "pwd && openssl req -config " + main_dir + "/openssl.cnf -new -sha256 -key " + main_dir + "/private/intermediate.key.pem -passin pass:" + password + " -out " + main_dir + "/csr/intermediate.csr.pem"

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

    except subprocess.CalledProcessError as err:
        print(err)
        return err
    except FileNotFoundError:
        print("python3 not found")

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

        # if stderr_data is not None:
        #     print("DEBUG: ENTREI AQUI!")
        #     return stderr_data

    except subprocess.CalledProcessError as err:
        print(err)
        return err
    except FileNotFoundError:
        print("python3 not found")

    #  wally
    os.chmod(main_dir + "/certs/intermediate.cert.pem", 0o444)

    return True


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
        try:
            shutil.copy(main_dir + "/intermediate/certs/ca-chain.cert.pem", "static/ca-chain.cert.pem")
        except FileNotFoundError as err:
            return "Error", err
    else:
        print("just copying")
        # shutil.copy(main_dir + "/intermediate/certs/ca-chain.cert.pem", "static/ca-chain.cert.pem")
        try:
            shutil.copy(main_dir + "/intermediate/certs/ca-chain.cert.pem", "static/ca-chain.cert.pem")
        except FileNotFoundError as err:
            return "Error", err

    return True, "top"

def view_bundle_from_intermediate():
    # context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    # context.load_verify_locations(static + "ca-chain.cert.pem")
    # complete_chain = context.get_ca_certs()
    # for b in complete_chain:
        # print(f"AUDIT: Chain: {b['issuer']}")

    chain_list = []
    chain_final_list = []
    l_stage = []
    str_stage = ""
    control = False

    with open("static/ca-chain.cert.pem", "r") as file:
        for line in file:
            if "BEGIN" in line or control is True:
                control = True
                print(f"== {line}")
                l_stage.append(line)

            if "END" in line and control is True:
                # print(f"== {line}")
                control = False
                # l_stage.append(line)
                chain_list.append(str_stage.join(l_stage))
                # chain_list.append(l_stage)
                l_stage = []
                
            # pass
            # return file.read()


    # print(f"AUDIT: chain_list")
    # print(f"AUDIT: chain_list: {chain_list}")

    for b in chain_list:
        # print(f"AUDIT:")
        # print(f"{b}")
        temp_file = "/tmp/xpto"
        with open(temp_file, "w") as temp_file:
            temp_file.write(b)

        
        # aux = os.system(command)
        # print(f"AUDIT: AUX: {aux}")

        # input_to_send = b"y\ny\n"
        try:
            # command = "openssl ca -config  " + main_dir + "/../openssl.cnf -extensions v3_intermediate_ca -days 3650 -notext -md sha256 -in  " + main_dir + "/csr/intermediate.csr.pem -passin pass:" + password + " -out  " + main_dir + "/certs/intermediate.cert.pem"
            command = "openssl x509 -noout -subject -issuer -in /tmp/xpto"

            template = env.get_template('run.py.template')
            output = template.render(command=command)
            with open("run.py", "w") as fp:
                print(output, file=fp)

            command = "run.py"
            print()
            print(command)
            process = subprocess.Popen(['python3', command], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

            stdout_data, stderr_data = process.communicate()
            # stdout_data, stderr_data = process.communicate(input=input_to_send)
            print(f"stdout: {stdout_data}")
            print(f"stderr: {stderr_data}")

            # if stderr_data is not None:
            #     print("DEBUG: ENTREI AQUI!")
            #     return stderr_data

        except subprocess.CalledProcessError as err:
            print(err)
            return err
        except FileNotFoundError:
            print("python3 not found")
        
        chain_final_list.append(str(stdout_data, encoding='utf-8'))
        chain_final_list.append(b)



    for b in chain_final_list:
        print(f"AUDIT: Final Chain List")
        print(f"{b}")

    # with open("static/ca-chain.cert.pem", "r") as file:
    #     return file.read()


    return chain_final_list


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

def custom_ssl_certificate_create_flow(dns1, dns2, dns3, countryName, stateOrProvinceName, localityName, organizationName, organizationalUnitName, commonName):
    """
    """
    BASE_CUSTOM_DIR = static + "/custom_ssl_certs/" + commonName + "/"
    # BASE_CUSTOM_DIR = main_dir + "/custom_ssl_certs/" + commonName + "/"

    # mkdir /root/satellite_cert
    if not os.path.exists(BASE_CUSTOM_DIR):
        os.makedirs(BASE_CUSTOM_DIR)

    # openssl genrsa -out /root/satellite_cert/satellite_cert_key.pem 4096
    command = "openssl genrsa -out " + BASE_CUSTOM_DIR + commonName + ".pem 4096"
    os.system(command)

    # /root/satellite_cert/openssl.cnf
    # ---
    # [ req ]
    # req_extensions = v3_req
    # distinguished_name = req_distinguished_name
    # prompt = no

    # [ req_distinguished_name ]
    # commonName = satellite.example.com

    # [ v3_req ]
    # basicConstraints = CA:FALSE
    # keyUsage = digitalSignature, keyEncipherment
    # extendedKeyUsage = serverAuth, clientAuth
    # subjectAltName = @alt_names

    # [ alt_names ]
    # DNS.1 = satellite.example.com
    # ---

    # Optional: If you want to add Distinguished Name (DN) details to the CSR, add the following information to the [ req_distinguished_name ] section:
    # ---
    # [req_distinguished_name]
    # CN = satellite.example.com
    # countryName = My_Country_Name 
    # stateOrProvinceName = My_State_Or_Province_Name 
    # localityName = My_Locality_Name 
    # organizationName = My_Organization_Or_Company_Name
    # organizationalUnitName = My_Organizational_Unit_Name 
    # ---

    template = env.get_template('openssl.cnf.custom.template')
    output = template.render(dir=dir, dns1=dns1, dns2=dns2, dns3=dns3, countryName=countryName, stateOrProvinceName=stateOrProvinceName, localityName=localityName, organizationName=organizationName, organizationalUnitName=organizationalUnitName, commonName=commonName)
    with open(BASE_CUSTOM_DIR + "openssl.cnf", "w") as fp:
        print(output, file=fp)

    # Generate the CSR
    # ---
    # openssl req -new \
    # -key /root/satellite_cert/satellite_cert_key.pem \
    # -config /root/satellite_cert/openssl.cnf \
    # -out /root/satellite_cert/satellite_cert_csr.pem
    # ---
    command = "openssl req -new -key " + BASE_CUSTOM_DIR + commonName + ".pem -config " + BASE_CUSTOM_DIR + "openssl.cnf -out " + BASE_CUSTOM_DIR + "csr_" + commonName + ".pem"
    os.system(command)

    return True

def list_of_custom_certs():
    if os.path.exists(static + "/custom_ssl_certs/"):
        return os.listdir(static + "/custom_ssl_certs/")