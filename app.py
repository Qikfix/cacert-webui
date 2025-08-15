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



@app.route("/sign_csr", methods=['GET', 'POST'])
def sign_csr():
    """
    docstring here
    """
    if request.method == "GET":
        # download_bundle_from_intermediate()

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
        sign_csr_cert()
        return redirect('/sign_csr')


@app.route("/download_bundle", methods=['GET', 'POST'])
def download_bundle():
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


@app.route("/delete_intermediate", methods=['GET', 'POST'])
def delete_intermediate():
    """
    docstring here
    """
    if request.method == "GET":
        return render_template('delete_intermediate.html')
    if request.method == "POST":
        response = request.form.get('delete_intermediate')
        delete_response = delete_root_folder(response, main_dir + "/intermediate")
        if delete_response is not True:
            return render_template('error.html', msg=delete_response)
        return redirect('/intermediate_ca')


@app.route("/delete_root", methods=['GET', 'POST'])
def delete_root():
    """
    docstring here
    """
    if request.method == "GET":
        return render_template('delete_root.html')
    if request.method == "POST":
        response = request.form.get('delete_root')
        delete_response = delete_root_folder(response, main_dir)
        if delete_response is not True:
            return render_template('error.html', msg=delete_response)
        return redirect('/root_ca')

@app.route("/verify_intermediate_against_root", methods=['GET', 'POST'])
def verify_intermediate_against_root():
    """
    docstring here
    """
    if request.method == "GET":
        print("here in verify")

        # result_verify = verify_the_root_certificate(main_dir)
        result_verify = verify_the_intermediate_certificate_against_root_ca(main_dir + "/intermediate")

        return render_template('verify.html', result_verify=result_verify)


@app.route("/verify_intermediate", methods=['GET', 'POST'])
def verify_intermediate():
    """
    docstring here
    """
    if request.method == "GET":
        print("here in verify")

        # result_verify = verify_the_root_certificate(main_dir)
        result_verify = verify_the_intermediate_certificate(main_dir + "/intermediate")

        return render_template('verify.html', result_verify=result_verify)


@app.route("/verify_root", methods=['GET', 'POST'])
def verify_root():
    """
    docstring here
    """
    if request.method == "GET":
        print("here in verify")

        result_verify = verify_the_root_certificate(main_dir)
        # return redirect("/")
        return render_template('verify.html', result_verify=result_verify)

    # return render_template('root.html')


@app.route("/root", methods=['GET', 'POST'])
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
        create_the_root_key(main_dir, "private/ca.key.pem", password="waldirio123")
        create_the_root_certificate(main_dir)
        # result_verify = verify_the_root_certificate(main_dir)
        return redirect("/root_ca")

    return render_template('root.html')


@app.route("/intermediate", methods=['GET', 'POST'])
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
        prepare_the_configuration_file(main_dir + "/intermediate", countryName=countryName, stateOrProvinceName=stateOrProvinceName, localityName=localityName, organizationName=organizationName, organizationalUnitName=organizationalUnitName, commonName=commonName, emailAddress=emailAddress, private_key="intermediate.key.pem", certificate="intermediate.cert.pem", crl="intermediate.crl.pem", policy="policy_loose")

        # Create the intermediate key
        create_the_intermediate_key(main_dir + "/intermediate", password="waldirio123")

        # Create the intermediate certificate
        response = create_the_intermediate_certificate(main_dir + "/intermediate", password="waldirio123")
        print(f"DEBUG RESPONSE: {response}")
        if response is not True:
            return render_template('error.html', msg=response)

        # Create the certificate chain file
        create_the_certificate_chain(main_dir)

        return redirect("/intermediate_ca")

    return render_template('intermediate.html')


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

@app.route("/root_ca")
def root_ca():
    """
    docstring here
    """
    return render_template('root_ca.html')

@app.route("/intermediate_ca")
def intermediate_ca():
    """
    docstring here
    """
    return render_template('intermediate_ca.html')

@app.route("/github")
def github():
    """
    docstring here
    """
    return render_template('github.html')