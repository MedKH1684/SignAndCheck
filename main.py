from flask import Flask, redirect, url_for, request, render_template, send_file
from werkzeug.utils import secure_filename
from werkzeug.datastructures import  FileStorage
import OpenSSL
from OpenSSL import crypto
import base64
import hashlib
import os

#create necessary directories 
if "verification" not in os.listdir("."):
   os.system("mkdir verification")
if "signatures" not in os.listdir("."):
   os.system("mkdir signatures")
if "uploads" not in os.listdir("."):
   os.system("mkdir uploads")

#create PUB/PRIV server keys
if "server_private_key.pem" not in os.listdir("."):
   os.system("openssl genrsa -aes128 -passout pass:foobar -out server_private_key.pem 3072")
   os.system("openssl rsa -in server_private_key.pem  -passin pass:iccn -pubout -out server_public_key.pem")

# clear uploaded files + signatures
os.system("rm -rf signatures/* uploads/* verification/*")

app = Flask(__name__)

# the "Welcome" page. It load template/index.html
@app.route('/',methods = ['GET','POST'])
def index():
   return render_template('index.html')

# the "File Upload" page. It load template/upload.html
@app.route('/upload',methods = ['GET', 'POST'])
def upload_file():
   return render_template('upload.html')

# save the uploaded file from File Upload page to "uploads" folder
@app.route('/uploader', methods = ['GET', 'POST'])
def uploader():
   if request.method == 'POST':
      file = request.files['file']
      if file:
         file.save("uploads/"+secure_filename(file.filename))
         return redirect(url_for('signature', file_name = secure_filename(file.filename)))
      else:
         return render_template('upload.html')

# the process of signing the previously uploaded file, storing the generated signature in "signatures" folder, then loading the "Download Signature" page from templates/download.html to provide user with button to download the signature 
@app.route('/signature/<file_name>', methods = ['GET', 'POST'])
def signature(file_name):
   key = open("server_private_key.pem", "rb").read()
   password = b"iccn"
   pkey = crypto.load_privatekey(crypto.FILETYPE_PEM, key, password)
   
   data = open("uploads/"+secure_filename(file_name),"rb").read()
   signature = OpenSSL.crypto.sign(pkey, data, "sha256")

   signature_name = secure_filename(file_name).split(".")[0]+".sig"

   with open("signatures/"+signature_name,"wb") as sig:
      sig.write(signature)

   return render_template('download.html', file_name=file_name, signature_name=signature_name)

# popup save file screen after clicking on "Download" button, to download the signature file
@app.route('/downloader/<signature_name>', methods = ['GET', 'POST'])
def downloader(signature_name):
   return send_file("signatures/"+secure_filename(signature_name), as_attachment=True)

# the "Verify Signature" page
@app.route('/verification', methods = ['GET', 'POST'])
def verification():
   return render_template('verification.html')

# save the uploaded file+signature into "verification" folder 
@app.route('/uploader2', methods = ['GET', 'POST'])
def uploader2():
   if request.method == 'POST':
      file = request.files['file']
      signature = request.files['signature']
      if file and signature:
         file.save("verification/"+secure_filename(file.filename))
         signature.save("verification/"+secure_filename(signature.filename))
         return redirect(url_for('checking', file_name = secure_filename(file.filename), signature_name = secure_filename(signature.filename)))
      else:
         return render_template('verification.html')

# check if the signature is valid and rediredt to "Valid Signature" page if the signature is valid and "Not Valid Signature" page if it is not
@app.route('/checking/<file_name>/<signature_name>', methods=['GET','POST'])
def checking(file_name, signature_name):
   key = open("server_private_key.pem", "rb").read()
   password = b"iccn"
   pkey = crypto.load_privatekey(crypto.FILETYPE_PEM, key, password)

   data = open("verification/"+secure_filename(file_name),"rb").read()
   signature = OpenSSL.crypto.sign(pkey, data, "sha256")
   uploaded_signature = open("verification/"+secure_filename(signature_name),"rb").read()

   if signature == uploaded_signature:
      return redirect(url_for('success'))
   else:
      return redirect(url_for('fail'))

# load "Valid Signature" from templates/success.html
@app.route('/success', methods=['GET','POST'])
def success():
   return render_template('success.html')

# load "Not Valid Signature" from templates/fail.html
@app.route('/fail', methods=['GET','POST'])
def fail():
   return render_template('fail.html')

if __name__ == '__main__':
   app.run()