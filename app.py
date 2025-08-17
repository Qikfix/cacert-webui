"""
docstring here
"""

from flask import Flask, render_template, request, redirect
# import cacert
from cacert.cacert import *
import shutil
from werkzeug.utils import secure_filename

app = Flask(__name__)
# app.config['ENV'] = 'development'
# app.config['DEBUG'] = True

# UPLOAD_FOLDER = 'uploads'  # Directory to save uploaded files
# app.config['UPLOAD_FOLDER'] = 'uploads'



@app.route("/sign_certificate_main", methods=['GET', 'POST'])
def sign_certificate_main():
    """
    docstring here
    """
    if request.method == "GET":
        # download_bundle_from_intermediate()

        if request.args.get('delete_files') == "yes":
            if os.path.exists(output_signed_file):
                print(f"AUDIT: Removing the file '{output_signed_file}'")
                os.remove(output_signed_file)
            if os.path.exists(uploaded_cert_csr):
                print(f"AUDIT: Removing the file '{uploaded_cert_csr}'")
                os.remove(uploaded_cert_csr)
            

        response = None
        if request.args.get('view') == "yes":
            print("here we are")
            response = verify_signed_certificate()
            # return render_template("download_bundle.html", response = response)

        if os.path.exists("static/signed.crt"):
            is_file = True
        else:
            is_file = False

        return render_template('sign_csr.html', is_file=is_file, response=response)

    if request.method == 'POST':
        files = request.files.getlist('file[]')
        upload_cert_file(files)
        stdout_data, stderr_data = sign_csr_cert()
        return render_template('sign_csr.html', stdout_data=stdout_data, stderr_data=stderr_data)
        # return redirect('/sign_certificate_main')


@app.route("/bundle_main", methods=['GET', 'POST'])
def bundle_main():
    """
    docstring here
    """
    if request.method == "GET":
        response = download_bundle_from_intermediate()

        if request.args.get('view') == "yes":
            print("here we are")
            response = view_bundle_from_intermediate()
            return render_template("download_bundle.html", response = response)

        return render_template('download_bundle.html', response=response)


@app.route("/intermediate_delete", methods=['GET', 'POST'])
def intermediate_delete():
    """
    docstring here
    """
    if request.method == "GET":
        return render_template('intermediate_delete.html')
    if request.method == "POST":
        response = request.form.get('delete_intermediate')
        revoke = revoke_intermediate()
        if response:
            delete_response = delete_root_folder(response, main_dir + "/intermediate")

            if delete_response is not True:
                return render_template('error.html', msg=delete_response)

        return redirect('/intermediate_main')


@app.route("/root_delete", methods=['GET', 'POST'])
def root_delete():
    """
    docstring here
    """
    if request.method == "GET":
        return render_template('root_delete.html')
    if request.method == "POST":
        response = request.form.get('delete_root')
        delete_response = delete_root_folder(response, main_dir)
        if delete_response is not True:
            return render_template('error.html', msg=delete_response)
        return redirect('/root_main')

@app.route("/intermediate_verify_against_root_ca", methods=['GET', 'POST'])
def intermediate_verify_against_root_ca():
    """
    docstring here
    """
    if request.method == "GET":
        print("here in verify")

        # result_verify = verify_the_root_certificate(main_dir)
        result_verify = verify_the_intermediate_certificate_against_root_ca(main_dir + "/intermediate")

        return render_template('verify.html', result_verify=result_verify)


@app.route("/intermediate_verify", methods=['GET', 'POST'])
def intermediate_verify():
    """
    docstring here
    """
    if request.method == "GET":
        print("here in verify")

        # result_verify = verify_the_root_certificate(main_dir)
        result_verify = verify_the_intermediate_certificate(main_dir + "/intermediate")

        return render_template('verify.html', result_verify=result_verify)


@app.route("/root_verify", methods=['GET', 'POST'])
def root_verify():
    """
    docstring here
    """
    if request.method == "GET":
        print("here in verify")

        result_verify = verify_the_root_certificate(main_dir)
        # return redirect("/")
        return render_template('verify.html', result_verify=result_verify)

    # return render_template('root.html')


@app.route("/root_create", methods=['GET', 'POST'])
def root():
    """
    docstring here
    """
    if request.method == "POST":
        print("here in post")

        # main_dir = request.get.form('main_dir')
        countryName = request.form.get('countryName')
        stateOrProvinceName = request.form.get('stateOrProvinceName')
        localityName = request.form.get('localityName')
        organizationName = request.form.get('organizationName')
        organizationalUnitName = request.form.get('organizationalUnitName')
        commonName = request.form.get('commonName')
        emailAddress = request.form.get('emailAddress')

        status = checking_folder(main_dir, kind="root") # this will call the def "prepare_the_directory()"
        if status == 10:
            msg = "not an empty folder"
            return render_template('error.html', msg=msg)
        prepare_the_configuration_file(main_dir, countryName=countryName, stateOrProvinceName=stateOrProvinceName, localityName=localityName, organizationName=organizationName, organizationalUnitName=organizationalUnitName, commonName=commonName, emailAddress=emailAddress)
        # prepare_the_configuration_file(".", countryName=countryName, stateOrProvinceName=stateOrProvinceName, localityName=localityName, organizationName=organizationName, organizationalUnitName=organizationalUnitName, commonName=commonName, emailAddress=emailAddress)
        create_the_root_key(main_dir, "private/ca.key.pem", password="waldirio123")
        create_the_root_certificate(main_dir)
        # result_verify = verify_the_root_certificate(main_dir)
        return redirect("/root_main")

    return render_template('root_create.html')


@app.route("/intermediate_create", methods=['GET', 'POST'])
def intermediate():
    """
    docstring here
    """
    if request.method == "POST":
        # main_dir = request.get.form('main_dir')
        countryName = request.form.get('countryName')
        stateOrProvinceName = request.form.get('stateOrProvinceName')
        localityName = request.form.get('localityName')
        organizationName = request.form.get('organizationName')
        organizationalUnitName = request.form.get('organizationalUnitName')
        commonName = request.form.get('commonName')
        emailAddress = request.form.get('emailAddress')
        # Prepare the directory
        status = checking_folder(main_dir + "/intermediate", kind="intermediate") # this will call the def "prepare_the_directory()"
        if status == 10:
            msg = "not an empty folder"
            return render_template('error.html', msg=msg)
        if status is not None:
            msg = status
            return render_template('error.html', msg=msg)

        # Copy the intermediate CA configuration file (openssl.cnf) and change for intermediate
        prepare_the_configuration_file(main_dir + "intermediate", countryName=countryName, stateOrProvinceName=stateOrProvinceName, localityName=localityName, organizationName=organizationName, organizationalUnitName=organizationalUnitName, commonName=commonName, emailAddress=emailAddress, private_key="intermediate.key.pem", certificate="intermediate.cert.pem", crl="intermediate.crl.pem", policy="policy_loose")
        # prepare_the_configuration_file("./intermediate", countryName=countryName, stateOrProvinceName=stateOrProvinceName, localityName=localityName, organizationName=organizationName, organizationalUnitName=organizationalUnitName, commonName=commonName, emailAddress=emailAddress, private_key="intermediate.key.pem", certificate="intermediate.cert.pem", crl="intermediate.crl.pem", policy="policy_loose")

        # Create the intermediate key
        create_the_intermediate_key(main_dir + "/intermediate", password="waldirio123")

        # Create the intermediate certificate
        response = create_the_intermediate_certificate(main_dir + "/intermediate", password="waldirio123")
        print(f"DEBUG RESPONSE: {response}")
        if response is not True:
            return render_template('error.html', msg=response)

        # Create the certificate chain file
        create_the_certificate_chain(main_dir)

        return redirect("/intermediate_main")

    return render_template('intermediate_create.html')


@app.route("/")
def index():
    """
    docstring here
    """
    return render_template('index.html')

@app.route("/web")
def web():
    """
    docstring here
    """
    return render_template('web_template.html')

@app.route("/root_main")
def root_ca():
    """
    docstring here
    """
    return render_template('root_main.html')

@app.route("/intermediate_main")
def intermediate_ca():
    """
    docstring here
    """
    return render_template('intermediate_main.html')

@app.route("/github")
def github():
    """
    docstring here
    """
    return render_template('github.html')

@app.route("/custom_ssl_certificate_main")
def custom_ssl_certificate_main():
    """
    """
    if request.args.get('view') == "yes":
        print("AUDIT: HERE")
        # return render_template
        response = list_of_custom_certs()
        print(f"AUDIT: {response}")
        if response is not None and len(response) > 0:
            return render_template('custom_ssl_cert_main.html', response=response)
    return render_template('custom_ssl_cert_main.html')


@app.route("/custom_ssl_certificate_create", methods=['GET', 'POST'])
def custom_ssl_certificate_create():
    """
    """
    if request.method == 'POST':
        dns1 = request.form.get('dns1')
        dns2 = request.form.get('dns2')
        dns3 = request.form.get('dns3')
        countryName = request.form.get('countryName')
        stateOrProvinceName = request.form.get('stateOrProvinceName')
        localityName = request.form.get('localityName')
        organizationName = request.form.get('organizationName')
        organizationalUnitName = request.form.get('organizationalUnitName')
        commonName = request.form.get('commonName')

        response = custom_ssl_certificate_create_flow(dns1, dns2, dns3, countryName, stateOrProvinceName, localityName, organizationName, organizationalUnitName, commonName)
        if response:
            return redirect('/custom_ssl_certificate_main')

    return render_template('custom_ssl_certificate_create.html')

@app.route("/custom_ssl_certificate_delete")
def custom_ssl_certificate_delete():
    """
    """
    if request.args.get('delete') == "yes":
        cn_name = request.args.get('cn')
        print(f"AUDIT: Delete the Custom SSL Cert of: {cn_name}")
        if os.path.exists(static + "custom_ssl_certs/" + cn_name):
            shutil.rmtree(static + "custom_ssl_certs/" + cn_name)
            print(f"AUDIT: Removing the folder {static + 'custom_ss_certs/' + cn_name}")
            
    return redirect('/custom_ssl_certificate_main')
