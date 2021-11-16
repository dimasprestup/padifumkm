import email, smtplib, ssl
import random
import string
from flask import Flask, request, abort, g, json, jsonify, redirect, url_for, session
from flask_restful import Resource, Api
from flask_restful import reqparse
from flaskext.mysql import MySQL
from flask_cors import CORS
from functools import wraps
from flask_httpauth import HTTPBasicAuth, HTTPTokenAuth, MultiAuth
from werkzeug.exceptions import InternalServerError
from werkzeug.security import generate_password_hash, check_password_hash
from itsdangerous import TimedJSONWebSignatureSerializer as JWS


#MIME email HTML
from email import encoders
from email.mime.base import MIMEBase
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

#from pyblake2 import blake2b
from datetime import datetime
from flask_mail import Mail, Message

# hazmat encrypted
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.fernet import Fernet

# Generate Alphabet dan numerik
# -----------------------------
def get_random_alphanumeric_string(length):
    letters_and_digits = string.ascii_letters + string.digits
    result_str = ''.join((random.choice(letters_and_digits) for i in range(length)))
    return result_str

#load configurations
with open('./config/config.json', 'r') as f:
    #config is the json file
    #loaded up configurations to spec_names, specifications
    configuration = json.load(f)

#assign port number
portNumber = configuration["port"]
#assign hostname
hostName = configuration["host"]
DB_Server = configuration["DB_Server"]
DB_User = configuration["DB_User"]
DB_Password = configuration["DB_Password"]
DB_Name = configuration["DB_Name"]
Expired = configuration["Expired"]
API_prefix = configuration["API_prefix"]
API_key = configuration["API_key"]

#assign mail server
MAIL_SERVER = configuration["MAIL_SERVER"]
MAIL_PORT = configuration["MAIL_PORT"]
MAIL_USERNAME = configuration["MAIL_USERNAME"]
MAIL_PASSWORD = configuration["MAIL_PASSWORD"]
MAIL_USE_TLS = configuration["MAIL_USE_TLS"]
MAIL_USE_SSL = configuration["MAIL_USE_SSL"]

#assign debug boolean
debugBoolean = configuration["debug"]

mysql = MySQL()
app = Flask(__name__)
cors = CORS(app, resources={r"*": {"origins": "*"}})

# MySQL configurations
app.config['MYSQL_DATABASE_USER'] = DB_User
app.config['MYSQL_DATABASE_PASSWORD'] = DB_Password
app.config['MYSQL_DATABASE_DB'] = DB_Name
app.config['MYSQL_DATABASE_HOST'] = DB_Server
app.config['SECRET_KEY'] = 'top secret!'
jws = JWS(app.config['SECRET_KEY'], expires_in=Expired)

basic_auth = HTTPBasicAuth()
token_auth = HTTPTokenAuth('Bearer')
multi_auth = MultiAuth(basic_auth, token_auth)

mysql.init_app(app)

api = Api(app, prefix=API_prefix)

#context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
#context.load_cert_chain('server.crt', 'server.key')

SECRETKEY = b'pseudorandomly generated server secret key'
AUTH_SIZE = 16

key = 'DB7x0bKPrQWlv-Yq3GyeEMaA-IMFUToC8M6OmWgUImM='.encode()
f = Fernet(key)

#def sign(cookie):
#    h = blake2b(data=cookie, digest_size=AUTH_SIZE, key=SECRETKEY)
#    return h.hexdigest()

#def verify(cookie, sig):
#    good_sig = sign(cookie)
#    if len(sig) != len(good_sig):
#        return False
    # Use constant-time comparison to avoid timing attacks.
#    result = 0
#    for x, y in zip(sig, good_sig):
#        result |= ord(x) ^ ord(y)
#    return result == 0

# The actual decorator function
def require_appkey(view_function):

    @wraps(view_function)
    # the new, post-decoration function. Note *args and **kwargs here.
    def decorated_function(*args, **kwargs):
        if request.args.get('key') and request.args.get('key') == API_key:
            return view_function(*args, **kwargs)
        else:
            abort(401)

    return decorated_function

users = {
    "john": generate_password_hash("travolta"),
    "susan": generate_password_hash("susanti")
}

for user in users.keys():
    token = jws.dumps({'username': user})
    print('*** token for {}: {}\n'.format(user, token))

@basic_auth.verify_password
def verify_password(username, password):
    g.user = None
    if username in users:
        if check_password_hash(users.get(username), password):
            g.user = username
            return True
    return False

@token_auth.verify_token
def verify_token(token):
    g.user = None
    try:
        data = jws.loads(token)
    except:  # noqa: E722
        return False
    if 'username' in data:
        g.user = data['username']
        return True
    return False


### -------- KELOLA DATA PENGGUNA LOGIN SISTEM ----- ###
### ------------------------------------------------ ###

class CreatePengguna(Resource):
    
    @require_appkey
    @multi_auth.login_required
    def post(self):
        try:
            # Parse the arguments
            parser = reqparse.RequestParser()
            parser.add_argument('user_email', type=str, help='1. user_email')
            parser.add_argument('no_handphone', type=str, help='2. no_handphone')
            parser.add_argument('user_password', type=str, help='3. user_password')
            parser.add_argument('user_privileges', type=str, help='4. user_privileges')
            parser.add_argument('user_status', type=str, help='5. user_status')
            parser.add_argument('user_kode', type=str, help='6. user_kode')
            #parser.add_argument('ket_lain', type=str, help='6. ket_lain')        
            args = parser.parse_args()

            _user_email = args['user_email']
            _no_handphone = args['no_handphone']
            _user_password = args['user_password']
            _user_privileges = args['user_privileges']
            _user_status = args['user_status']
            _user_kode = args['user_kode']
            #_ket_lain = args['ket_lain']

            # message_paswd = _user_password.encode('UTF8')
            res_user_password = _user_password.encode()
            enc_paswd = f.encrypt(res_user_password)
            res_enc_password = enc_paswd.decode()

            conn = mysql.connect()
            cursor = conn.cursor()
            cursor.callproc('sp_CreatePengguna', (_user_email, _no_handphone, res_enc_password, _user_privileges, _user_status, _user_kode,))
            data = cursor.fetchall()

            if len(data) == 0:
                conn.commit()
                return jsonify({'StatusCode':'200', 'message': 'Sukses simpan..!'})
            else:
                return jsonify({'StatusCode':'100', 'message': str(data[0])})

        except Exception as e:
            return {'error': str(e)}


class DeletePengguna(Resource):
    
    @require_appkey
    @multi_auth.login_required
    def delete(self):
        try:
            # Parse the arguments
            parser = reqparse.RequestParser()
            parser.add_argument('user_email', type=str, help='1. user_email')   
            args = parser.parse_args()

            _user_email = args['user_email']

            conn = mysql.connect()
            cursor = conn.cursor()
            cursor.callproc('sp_DeletePengguna', (_user_email,))
            data = cursor.fetchall()

            if len(data) == 0:
                conn.commit()
                return jsonify({'StatusCode':'200', 'message': 'Sukses hapus pengguna..!'})
            else:
                return jsonify({'StatusCode':'100', 'message': str(data[0])})

        except Exception as e:
            return {'error': str(e)}


class ReadPengguna(Resource):
    
    @require_appkey
    @multi_auth.login_required
    def get(self):
        try: 
            conn = mysql.connect()
            cursor = conn.cursor()
            cursor.callproc('sp_ReadAllPengguna')
            data = cursor.fetchall()

            items_ReadPengguna = [];
            for item in data:
                i = {
                    'user_email':item[0], 'no_handphone':item[1], 'user_password':item[2],
                    'user_privileges':item[3], 'user_status':item[4], 'user_kode':item[5]
                }

                items_ReadPengguna.append(i)

            return jsonify(items_ReadPengguna)

        except Exception as e:
            return jsonify({'StatusCode':'100', 'Message': str(e)})


class ResetPassword(Resource):
    
    @require_appkey
    @multi_auth.login_required
    def put(self):
        try:
            # Parse the arguments
            parser = reqparse.RequestParser()
            parser.add_argument('user_email', type=str, help='Email to create user')
            parser.add_argument('user_password', type=str, help='Password to create user')
            args = parser.parse_args()

            _user_email = args['user_email']
            _user_password = args['user_password']

            # message_paswd = _user_password.encode('UTF8')
            _user_password = _user_password.encode()
            enc_paswd = f.encrypt(_user_password)
            enc_password = enc_paswd.decode()

            conn = mysql.connect()
            cursor = conn.cursor()
            cursor.callproc('sp_ResetPassword', (_user_email, enc_password,))
            data = cursor.fetchall()

            if len(data) == 0:
                conn.commit()
                return {'StatusCode':'200', 'Message': 'Reset Password success'}
            else:
                return {'StatusCode':'100', 'Message': str(data[0])}

        except Exception as e:
            return {'error': str(e)}


class AuthenticateAndroid(Resource):
    
    @require_appkey
    @multi_auth.login_required
    def get(self):
        try:
            # Parse the arguments
            parser = reqparse.RequestParser()
            parser.add_argument('user_email', type=str, help='1. user_email')
            parser.add_argument('user_password', type=str, help='2. user_password')
            args = parser.parse_args()

            _user_email = args['user_email']
            _user_password = args['user_password']

            conn = mysql.connect()
            cursor = conn.cursor()
            cursor.callproc('sp_AuthenticateAndroid', (_user_email,))
            data = cursor.fetchall()

            list_Pengguna = [];
            for list1 in data:
                user_email = list1[0]
                no_handphone = list1[1]
                user_password = list1[2]
                user_privileges = list1[3]
                user_status = list1[4]
                user_kode = list1[5]

                key_password = user_password.encode()
                user_password = f.decrypt(key_password)
                dec_user_password = user_password.decode()

                i = {
                    'user_email':user_email,
                    'no_handphone':no_handphone,
                    'user_password':dec_user_password,
                    'user_privileges':user_privileges,
                    'user_status':user_status,
                    'user_kode':user_kode,
                }
                
                list_Pengguna.append(i)

            if(len(data) > 0):
                if(dec_user_password == _user_password):
                    return jsonify({'StatusCode':'200', 'message':'Authentication success', 'data':list_Pengguna})
                else:
                    return jsonify({'StatusCode':'100', 'message':'Akses sistem ditolak...!'})
            else:
                    return jsonify({'StatusCode':'100', 'message':'Akses sistem ditolak...!'})

        except Exception as e:
            return jsonify({'StatusCode':'100', 'Message': str(e)})


### KELOLA DATA PROFILE UMKM ----------- ###
### ------------------------------------ ###
class CreateProfile(Resource):
    
    @require_appkey
    @multi_auth.login_required
    def post(self):
        try:
            # Parse the arguments
            parser = reqparse.RequestParser()
            parser.add_argument('kode_profile', type=str, help='1. kode_profile')
            parser.add_argument('id_pemilik', type=str, help='2. id_pemilik')
            parser.add_argument('nama_usaha', type=str, help='3. nama_usaha')
            parser.add_argument('jenis_usaha', type=str, help='4. jenis_usaha')
            parser.add_argument('produk_utama', type=str, help='5. produk_utama')
            parser.add_argument('pasar_utama', type=str, help='6. pasar_utama')

            parser.add_argument('alamat', type=str, help='7. alamat')
            parser.add_argument('kelurahan', type=str, help='8. kelurahan')
            parser.add_argument('kecamatan', type=str, help='9. kecamatan')
            parser.add_argument('kabupaten', type=str, help='10. kabupaten')
            parser.add_argument('propinsi', type=str, help='11. propinsi')

            parser.add_argument('link', type=str, help='12. link')
            parser.add_argument('jumlah_karyawan', type=int, help='13. jumlah_karyawan')
            parser.add_argument('berdiri_sejak', type=str, help='14. berdiri_sejak')
            parser.add_argument('email', type=str, help='15. email')
            parser.add_argument('telepon', type=str, help='16. telepon')
            
            args = parser.parse_args()

            _kode_profile = args['kode_profile']
            _id_pemilik = args['id_pemilik']
            _nama_usaha = args['nama_usaha']
            _jenis_usaha = args['jenis_usaha']
            _produk_utama = args['produk_utama']
            _pasar_utama = args['pasar_utama']

            _alamat = args['alamat']
            _kelurahan = args['kelurahan']
            _kecamatan = args['kecamatan']
            _kabupaten = args['kabupaten']
            _propinsi = args['propinsi']

            _link = args['link']
            _jumlah_karyawan = args['jumlah_karyawan']
            _berdiri_sejak = args['berdiri_sejak']
            _email = args['email']
            _telepon = args['telepon']

            conn = mysql.connect()
            cursor = conn.cursor()
            cursor.callproc('sp_CreateProfile', (_kode_profile, _id_pemilik, _nama_usaha, _jenis_usaha, _produk_utama, _pasar_utama, _alamat, _kelurahan, _kecamatan, _kabupaten, _propinsi, _link, _jumlah_karyawan, _berdiri_sejak, _email, _telepon,))
            data = cursor.fetchall()

            if len(data) == 0:
                conn.commit()
                return jsonify({'StatusCode':'200', 'message': 'Sukses simpan..!'})
            else:
                return jsonify({'StatusCode':'100', 'message': str(data[0])})

        except Exception as e:
            return {'error': str(e)}


class DeleteProfile(Resource):
    
    @require_appkey
    @multi_auth.login_required
    def delete(self):
        try:
            # Parse the arguments
            parser = reqparse.RequestParser()
            parser.add_argument('email', type=str, help='1. email')   
            args = parser.parse_args()

            _email = args['email']

            conn = mysql.connect()
            cursor = conn.cursor()
            cursor.callproc('sp_DeleteProfile', (_email,))
            data = cursor.fetchall()

            if len(data) == 0:
                conn.commit()
                return jsonify({'StatusCode':'200', 'message': 'Sukses hapus profile..!'})
            else:
                return jsonify({'StatusCode':'100', 'message': str(data[0])})

        except Exception as e:
            return {'error': str(e)}


class ReadAllProfile(Resource):
    
    @require_appkey
    @multi_auth.login_required
    def get(self):
        try: 
            conn = mysql.connect()
            cursor = conn.cursor()
            cursor.callproc('sp_ReadAllProfile')
            data = cursor.fetchall()

            items_ReadProfile = [];
            for item in data:
                i = {
                    'kode_profile':item[0], 'id_pemilik':item[1], 'nama_usaha':item[2], 'jenis_usaha':item[3], 
                    'produk_utama':item[4], 'pasar_utama':item[5],'alamat':item[6], 'kelurahan':item[7], 
                    'kecamatan':item[8], 'kabupaten':item[9], 'propinsi':item[10], 'link':item[11], 'jumlah_karyawan':item[12], 'berdiri_sejak':item[13], 'email':item[14], 'telepon':item[15]
                }

                items_ReadProfile.append(i)

            return jsonify(items_ReadProfile)

        except Exception as e:
            return jsonify({'StatusCode':'100', 'Message': str(e)})


class ReadProfile(Resource):
    
    @require_appkey
    @multi_auth.login_required
    def get(self):
        try:
            # Parse the arguments
            parser = reqparse.RequestParser()
            parser.add_argument('email', type=str, help='1. email')   
            args = parser.parse_args()

            _email = args['email']

            conn = mysql.connect()
            cursor = conn.cursor()
            cursor.callproc('sp_ReadProfile', (_email,))
            data = cursor.fetchall()

            items_ReadProfile = [];
            for item in data:
                i = {
                    'kode_profile':item[0], 'id_pemilik':item[1], 'nama_usaha':item[2], 'jenis_usaha':item[3], 
                    'produk_utama':item[4], 'pasar_utama':item[5],'alamat':item[6], 'kelurahan':item[7], 
                    'kecamatan':item[8], 'kabupaten':item[9], 'propinsi':item[10], 'link':item[11], 'jumlah_karyawan':item[12], 'berdiri_sejak':item[13], 'email':item[14], 'telepon':item[15]
                }

                items_ReadProfile.append(i)

            return jsonify(items_ReadProfile)

        except Exception as e:
            return jsonify({'StatusCode':'100', 'Message': str(e)})


class UpdateProfile(Resource):
    
    @require_appkey
    @multi_auth.login_required
    def put(self):
        try:
            # Parse the arguments
            parser = reqparse.RequestParser()
            parser.add_argument('kode_profile', type=str, help='1. kode_profile')
            parser.add_argument('id_pemilik', type=str, help='2. id_pemilik')
            parser.add_argument('nama_usaha', type=str, help='3. nama_usaha')
            parser.add_argument('jenis_usaha', type=str, help='4. jenis_usaha')
            parser.add_argument('produk_utama', type=str, help='5. produk_utama')
            parser.add_argument('pasar_utama', type=str, help='6. pasar_utama')

            parser.add_argument('alamat', type=str, help='7. alamat')
            parser.add_argument('kelurahan', type=str, help='8. kelurahan')
            parser.add_argument('kecamatan', type=str, help='9. kecamatan')
            parser.add_argument('kabupaten', type=str, help='10. kabupaten')
            parser.add_argument('propinsi', type=str, help='11. propinsi')

            parser.add_argument('link', type=str, help='12. link')
            parser.add_argument('jumlah_karyawan', type=str, help='13. jumlah_karyawan')
            parser.add_argument('berdiri_sejak', type=str, help='14. berdiri_sejak')
            parser.add_argument('email', type=str, help='15. email')
            parser.add_argument('telepon', type=str, help='16. telepon')                
            args = parser.parse_args()

            _kode_profile = args['kode_profile']
            _id_pemilik = args['id_pemilik']
            _nama_usaha = args['nama_usaha']
            _jenis_usaha = args['jenis_usaha']
            _produk_utama = args['produk_utama']
            _pasar_utama = args['pasar_utama']

            _alamat = args['alamat']
            _kelurahan = args['kelurahan']
            _kecamatan = args['kecamatan']
            _kabupaten = args['kabupaten']
            _propinsi = args['propinsi']

            _link = args['link']
            _jumlah_karyawan = args['jumlah_karyawan']
            _berdiri_sejak = args['berdiri_sejak']
            _email = args['email']
            _telepon = args['telepon']

            conn = mysql.connect()
            cursor = conn.cursor()
            cursor.callproc('sp_UpdateProfile', (_kode_profile, _id_pemilik, _nama_usaha, _jenis_usaha, _produk_utama, _pasar_utama, _alamat, _kelurahan, _kecamatan, _kabupaten, _propinsi, _link, _jumlah_karyawan, _berdiri_sejak, _email, _telepon))
            data = cursor.fetchall()

            if len(data) == 0:
                conn.commit()
                return jsonify({'StatusCode':'200', 'message': 'Sukses update ...!'})
            else:
                return jsonify({'StatusCode':'100', 'message': str(data[0])})

        except Exception as e:
            return {'error': str(e)}



# SEND EMAIL PERMINTAAN
# -----------------------

class SendMail(Resource):
    
    @require_appkey
    @multi_auth.login_required
    def post(self):
        try:
            parser = reqparse.RequestParser()
            parser.add_argument('nama', type=str, help='name ...')
            parser.add_argument('kantor', type=str, help='kantor ...')
            parser.add_argument('paket', type=str, help='paket ...')
            parser.add_argument('email', type=str, help='email...')
            parser.add_argument('pesan', type=str, help='pesan...')
            args = parser.parse_args()


            _nama = args['nama']
            _kantor = args['kantor']
            _paket = args['paket']
            receiver_email = args['email']
            _pesan = args['pesan']
            _kode = get_random_alphanumeric_string(10)

            subject = "[PERMINTAAN] - Ujian Sertifikasi pada LSP Animedia"
            sender_email = MAIL_USERNAME
            password = MAIL_PASSWORD

            now = datetime.now()
            dt_string = now.strftime("%d/%m/%Y %H:%M:%S")

            # Create a multipart message and set headers
            message = MIMEMultipart("alternative")
            message["From"] = sender_email
            message["To"] = receiver_email
            message["Subject"] = subject
            message["Bcc"] = receiver_email  # Recommended for mass emails

            # Add body to email
            #message.attach(MIMEText(body, "plain"))

            # Create the plain-text and HTML version of your message
            text = """\
            Hi,
            How are you?
            Real Python has many great tutorials:
            www.realpython.com"""
            html = """\
            <html>
              <body>
                <p>
                    Terima Kasih atas kepercayaan Anda telah menghubungi LSP Animedia Semarang.<br>
                    Berikut merupakan informasi permintaan yang telah Anda lakukan:

                    <table>
                      <tr>
                        <td>Tanggal/Jam</td>
                        <td>:</td>
                        <td>""" + dt_string + """</td>
                      </tr>
                      <tr>
                        <td>Jenis Transaksi</td>
                        <td>:</td>
                        <td>Permintaan Ujian Sertifikasi</td>
                      </tr>
                      <tr>
                        <td>Paket</td>
                        <td>:</td>
                        <td>""" + _paket + """</td>
                      </tr>
                      <tr>
                        <td>Nama PIC</td>
                        <td>:</td>
                        <td>""" + _nama + """</td>
                      </tr>
                      <tr>
                        <td>Dari Kantor</td>
                        <td>:</td>
                        <td>""" + _kantor + """</td>
                      </tr>
                      <tr>
                        <td>Email</td>
                        <td>:</td>
                        <td>""" + receiver_email + """</td>
                      </tr>
                      <tr>
                        <td>Pesan Permintaan</td>
                        <td>:</td>
                        <td>""" + _pesan + """</td>
                      </tr>
                      <tr>
                        <td>Kode permintaan</td>
                        <td>:</td>
                        <td>""" + _kode + """</td>
                      </tr>
                      <tr>
                        <td>Status</td>
                        <td>:</td>
                        <td>Menunggu antrian</td>
                      </tr>
                    </table> 
                    <br>

                    Kami menyarankan Anda untuk menyimpan email ini sebagai bukti permintaan Anda. Semoga informasi ini bermanfaat bagi Anda<br><br><br>

                    Hormat kami,<br><br>

                    MANAJEMEN LSP ANIMEDIA - SEMARANG
                </p>
              </body>
            </html>
            """

            # Turn these into plain/html MIMEText objects
            part1 = MIMEText(text, "plain")
            part2 = MIMEText(html, "html")

            # Add HTML/plain-text parts to MIMEMultipart message
            # The email client will try to render the last part first
            message.attach(part1)
            message.attach(part2)

            #-filename = "KAI-01122019.pdf"  # In same directory as script

            # Open PDF file in binary mode
            #-with open(filename, "rb") as attachment:
                # Add file as application/octet-stream
                # Email client can usually download this automatically as attachment
            #-    part = MIMEBase("application", "octet-stream")
            #-    part.set_payload(attachment.read())

            # Encode file in ASCII characters to send by email    
            #-encoders.encode_base64(part)

            # Add header as key/value pair to attachment part
            #-part.add_header(
            #-    "Content-Disposition",
            #-    f"attachment; filename= {filename}",
            #-)

            # Add attachment to message and convert message to string
            #message.attach(part)
            text = message.as_string()

            # Log in to server using secure context and send email
            context = ssl.create_default_context()
            with smtplib.SMTP_SSL("smtp.gmail.com", 465, context=context) as server:
                server.login(sender_email, password)
                server.sendmail(sender_email, receiver_email, text)

            return jsonify({'StatusCode':'200', 'message': 'Email sukses terkirim ...!'})

        except Exception as e:
            return jsonify({'StatusCode':'100', 'error': str(e)})


### --- KELOLOA DATA PRODUK UMKM  ---- ###
### ---------------------------------- ###

class CreateProduk(Resource):
    
    @require_appkey
    @multi_auth.login_required
    def post(self):
        try:
            # Parse the arguments
            parser = reqparse.RequestParser()
            parser.add_argument('kode_produk', type=str, help='1. kode_produk')
            parser.add_argument('kode_profile', type=str, help='2. kode_profile')
            parser.add_argument('id_kategori', type=int, help='3. id_kategori')
            parser.add_argument('jenis_produk', type=str, help='4. jenis_produk')
            parser.add_argument('judul_produk', type=str, help='5. judul_produk')
            parser.add_argument('harga_produk', type=int, help='6. harga_produk')

            parser.add_argument('gambar', type=str, help='7. gambar')
            parser.add_argument('deskripsi', type=str, help='8. deskripsi')
            parser.add_argument('satuan', type=str, help='9. satuan')
            parser.add_argument('berat', type=int, help='10. berat')
            parser.add_argument('warna', type=str, help='11. warna')
            parser.add_argument('stok', type=int, help='12. stok')
            args = parser.parse_args()

            _kode_produk = args['kode_produk']
            _kode_profile = args['kode_profile']
            _id_kategori = args['id_kategori']
            _jenis_produk = args['jenis_produk']
            _judul_produk = args['judul_produk']
            _harga_produk = args['harga_produk']

            _gambar = args['gambar']
            _deskripsi = args['deskripsi']
            _satuan = args['satuan']
            _berat = args['berat']
            _warna = args['warna']

            _stok = args['stok']

            conn = mysql.connect()
            cursor = conn.cursor()
            cursor.callproc('sp_CreateProduk', (_kode_produk, _kode_profile, _id_kategori, _jenis_produk, _judul_produk, _harga_produk, _gambar, _deskripsi, _satuan, _berat, _warna, _stok,))
            data = cursor.fetchall()

            if len(data) == 0:
                conn.commit()
                return jsonify({'StatusCode':'200', 'message': 'Sukses simpan..!'})
            else:
                return jsonify({'StatusCode':'100', 'message': str(data[0])})

        except Exception as e:
            return {'error': str(e)}


class DeleteProduk(Resource):
    
    @require_appkey
    @multi_auth.login_required
    def delete(self):
        try:
            # Parse the arguments
            parser = reqparse.RequestParser()
            parser.add_argument('kode_produk', type=str, help='1. kode_produk')
            parser.add_argument('kode_profile', type=str, help='2. kode_profile') 
            args = parser.parse_args()

            _kode_produk = args['kode_produk']
            _kode_profile = args['kode_profile']

            conn = mysql.connect()
            cursor = conn.cursor()
            cursor.callproc('sp_DeleteProduk', (_kode_produk, _kode_profile,))
            data = cursor.fetchall()

            if len(data) == 0:
                conn.commit()
                return jsonify({'StatusCode':'200', 'message': 'Sukses hapus ...!'})
            else:
                return jsonify({'StatusCode':'100', 'message': str(data[0])})

        except Exception as e:
            return {'error': str(e)}


class ReadAllProduk(Resource):
    
    @require_appkey
    @multi_auth.login_required
    def get(self):
        try: 
            conn = mysql.connect()
            cursor = conn.cursor()
            cursor.callproc('sp_ReadAllProduk')
            data = cursor.fetchall()

            items_ReadAllProduk = [];
            for item in data:
                i = {
                    'kode_produk':item[0], 'kode_profile':item[1], 'id_kategori':item[2],
                    'jenis_produk':item[3], 'judul_produk':item[4], 'harga_produk':item[5],
                    'gambar':item[6], 'deskripsi':item[7], 'satuan':item[8],
                    'berat':item[9], 'warna':item[10], 'stok':item[11], 'status':item[12]
                }

                items_ReadAllProduk.append(i)

            return jsonify(items_ReadAllProduk)

        except Exception as e:
            return jsonify({'StatusCode':'100', 'Message': str(e)})


class ReadProduk(Resource):
    
    @require_appkey
    @multi_auth.login_required
    def get(self):
        try:
            # Parse the arguments
            parser = reqparse.RequestParser()
            parser.add_argument('kode_produk', type=str, help='1. kode_produk')
            parser.add_argument('kode_profile', type=str, help='2. kode_profile')
            args = parser.parse_args()

            _kode_produk = args['kode_produk']
            _kode_profile = args['kode_profile']

            conn = mysql.connect()
            cursor = conn.cursor()
            cursor.callproc('sp_ReadProduk',(_kode_produk, _kode_profile))
            data = cursor.fetchall()

            items_ReadProduk = [];
            for item in data:
                i = {
                    'kode_produk':item[0], 'kode_profile':item[1], 'id_kategori':item[2],
                    'jenis_produk':item[3], 'judul_produk':item[4], 'harga_produk':item[5],
                    'gambar':item[6], 'deskripsi':item[7], 'satuan':item[8],
                    'berat':item[9], 'warna':item[10], 'stok':item[11], 'status':item[12]
                }

                items_ReadProduk.append(i)

            return jsonify(items_ReadProduk)

        except Exception as e:
            return jsonify({'StatusCode':'100', 'Message': str(e)})


class UpdateProduk(Resource):
    
    @require_appkey
    @multi_auth.login_required
    def put(self):
        try:
            # Parse the arguments
            parser = reqparse.RequestParser()
            parser.add_argument('kode_produk', type=str, help='1. kode_produk')
            parser.add_argument('kode_profile', type=str, help='2. kode_profile')
            parser.add_argument('id_kategori', type=str, help='3. id_kategori')
            parser.add_argument('jenis_produk', type=str, help='4. jenis_produk')
            parser.add_argument('judul_produk', type=str, help='5. judul_produk')
            parser.add_argument('harga_produk', type=str, help='6. harga_produk')

            parser.add_argument('gambar', type=str, help='7. gambar')
            parser.add_argument('deskripsi', type=str, help='8. deskripsi')
            parser.add_argument('satuan', type=str, help='9. satuan')
            parser.add_argument('berat', type=str, help='10. berat')
            parser.add_argument('warna', type=str, help='11. warna')

            parser.add_argument('stok', type=str, help='12. stok')
            parser.add_argument('status', type=str, help='13. status')

            args = parser.parse_args()

            _kode_produk = args['kode_produk']
            _kode_profile = args['kode_profile']
            _id_kategori = args['id_kategori']
            _jenis_produk = args['jenis_produk']
            _judul_produk = args['judul_produk']
            _harga_produk = args['harga_produk']

            _gambar = args['gambar']
            _deskripsi = args['deskripsi']
            _satuan = args['satuan']
            _berat = args['berat']
            _warna = args['warna']

            _stok = args['stok']
            _status = args['status']

            conn = mysql.connect()
            cursor = conn.cursor()
            cursor.callproc('sp_UpdateProduk', (_kode_produk, _kode_profile, _id_kategori, _jenis_produk, _judul_produk, _harga_produk, _gambar, _deskripsi, _satuan, _berat, _warna, _stok, _status,))
            data = cursor.fetchall()

            if len(data) == 0:
                conn.commit()
                return jsonify({'StatusCode':'200', 'message': 'Sukses update ...!'})
            else:
                return jsonify({'StatusCode':'100', 'message': str(data[0])})

        except Exception as e:
            return {'error': str(e)}


### --- KELOLOA DATA KATEGORI PRODUK UMKM  ---- ###
### ---------------------------------- ###

class CreateKategori(Resource):
    
    @require_appkey
    @multi_auth.login_required
    def post(self):
        try:
            # Parse the arguments
            parser = reqparse.RequestParser()
            parser.add_argument('nama_kategori', type=str, help='1. nama_kategori')
            args = parser.parse_args()

            _nama_kategori = args['nama_kategori']

            conn = mysql.connect()
            cursor = conn.cursor()
            cursor.callproc('sp_CreateKategori', (_nama_kategori,))
            data = cursor.fetchall()

            if len(data) == 0:
                conn.commit()
                return jsonify({'StatusCode':'200', 'message': 'Sukses simpan..!'})
            else:
                return jsonify({'StatusCode':'100', 'message': str(data[0])})

        except Exception as e:
            return {'error': str(e)}


class DeleteKategori(Resource):
    
    @require_appkey
    @multi_auth.login_required
    def delete(self):
        try:
            # Parse the arguments
            parser = reqparse.RequestParser()
            parser.add_argument('id_kategori', type=str, help='1. id_kategori')
            args = parser.parse_args()

            _id_kategori = args['id_kategori']

            conn = mysql.connect()
            cursor = conn.cursor()
            cursor.callproc('sp_DeleteKategori', (_id_kategori,))
            data = cursor.fetchall()

            if len(data) == 0:
                conn.commit()
                return jsonify({'StatusCode':'200', 'message': 'Sukses hapus ...!'})
            else:
                return jsonify({'StatusCode':'100', 'message': str(data[0])})

        except Exception as e:
            return {'error': str(e)}


class ReadAllKategori(Resource):
    
    @require_appkey
    @multi_auth.login_required
    def get(self):
        try: 
            conn = mysql.connect()
            cursor = conn.cursor()
            cursor.callproc('sp_ReadAllKategori')
            data = cursor.fetchall()

            items_ReadAllKategori = [];
            for item in data:
                i = {
                    'id_kategori':item[0], 'nama_kategori':item[1]
                }

                items_ReadAllKategori.append(i)

            return jsonify(items_ReadAllKategori)

        except Exception as e:
            return jsonify({'StatusCode':'100', 'Message': str(e)})


class ReadKategori(Resource):
    
    @require_appkey
    @multi_auth.login_required
    def get(self):
        try:
            # Parse the arguments
            parser = reqparse.RequestParser()
            parser.add_argument('id_kategori', type=str, help='1. id_kategori')
            args = parser.parse_args()

            _id_kategori = args['id_kategori']

            conn = mysql.connect()
            cursor = conn.cursor()
            cursor.callproc('sp_ReadKategori',(_id_kategori,))
            data = cursor.fetchall()

            items_ReadKategori = [];
            for item in data:
                i = {
                    'id_kategori':item[0], 'nama_kategori':item[1]
                }

                items_ReadKategori.append(i)

            return jsonify(items_ReadKategori)

        except Exception as e:
            return jsonify({'StatusCode':'100', 'Message': str(e)})


class UpdateKategori(Resource):
    
    @require_appkey
    @multi_auth.login_required
    def put(self):
        try:
            # Parse the arguments
            parser = reqparse.RequestParser()
            parser.add_argument('id_kategori', type=str, help='1. id_kategori')
            parser.add_argument('nama_kategori', type=str, help='2. id_kategori')
            args = parser.parse_args()

            _id_kategori = args['id_kategori']
            _nama_kategori = args['nama_kategori']

            conn = mysql.connect()
            cursor = conn.cursor()
            cursor.callproc('sp_UpdateKategori', (_id_kategori, _nama_kategori,))
            data = cursor.fetchall()

            if len(data) == 0:
                conn.commit()
                return jsonify({'StatusCode':'200', 'message': 'Sukses update ...!'})
            else:
                return jsonify({'StatusCode':'100', 'message': str(data[0])})

        except Exception as e:
            return {'error': str(e)}



class ReadAllJnsProduk(Resource):
    
    @require_appkey
    @multi_auth.login_required
    def get(self):
        try: 
            conn = mysql.connect()
            cursor = conn.cursor()
            cursor.callproc('sp_ReadAllJnsProduk')
            data = cursor.fetchall()

            items_ReadAllJnsProduk = [];
            for item in data:
                i = {
                    'id_jenis':item[0], 'nama_jenis':item[1]
                }

                items_ReadAllJnsProduk.append(i)

            return jsonify(items_ReadAllJnsProduk)

        except Exception as e:
            return jsonify({'StatusCode':'100', 'Message': str(e)})


class ReadAllStatus(Resource):
    
    @require_appkey
    @multi_auth.login_required
    def get(self):
        try: 
            conn = mysql.connect()
            cursor = conn.cursor()
            cursor.callproc('sp_ReadAllStatus')
            data = cursor.fetchall()

            items_ReadAllStatus = [];
            for item in data:
                i = {
                    'id_status':item[0], 'nama_status':item[1]
                }

                items_ReadAllStatus.append(i)

            return jsonify(items_ReadAllStatus)

        except Exception as e:
            return jsonify({'StatusCode':'100', 'Message': str(e)})


#### ------ KELOLA DATA BUYER PADA UMKM -------- ####
#### ------------------------------------------- ####
class CreateBuyer(Resource):
    
    @require_appkey
    @multi_auth.login_required
    def post(self):
        try:
            # Parse the arguments
            parser = reqparse.RequestParser()
            parser.add_argument('kode_buyer', type=str, help='1. kode_buyer')
            parser.add_argument('nama_buyer', type=str, help='2. nama_buyer')
            parser.add_argument('nama_usaha', type=str, help='3. nama_usaha')
            parser.add_argument('jenis_usaha', type=str, help='4. jenis_usaha')
            parser.add_argument('alamat', type=str, help='5. alamat')

            parser.add_argument('kelurahan', type=str, help='6. kelurahan')
            parser.add_argument('kecamatan', type=str, help='7. kecamatan')
            parser.add_argument('kabupaten', type=str, help='8. kabupaten')
            parser.add_argument('propinsi', type=str, help='9. propinsi')
            parser.add_argument('email', type=str, help='10. email')
            parser.add_argument('telepon', type=str, help='11. telepon')
            args = parser.parse_args()

            _kode_buyer = args['kode_buyer']
            _nama_buyer = args['nama_buyer']
            _nama_usaha = args['nama_usaha']
            _jenis_usaha = args['jenis_usaha']
            _alamat = args['alamat']

            _kelurahan = args['kelurahan']
            _kecamatan = args['kecamatan']
            _kabupaten = args['kabupaten']
            _propinsi = args['propinsi']
            _email = args['email']

            _telepon = args['telepon']

            conn = mysql.connect()
            cursor = conn.cursor()
            cursor.callproc('sp_CreateBuyer', (_kode_buyer, _nama_buyer, _nama_usaha, _jenis_usaha, _alamat, _kelurahan, _kecamatan, _kabupaten, _propinsi, _email, _telepon,))
            data = cursor.fetchall()

            if len(data) == 0:
                conn.commit()
                return jsonify({'StatusCode':'200', 'message': 'Sukses simpan..!'})
            else:
                return jsonify({'StatusCode':'100', 'message': str(data[0])})

        except Exception as e:
            return {'error': str(e)}


class DeleteBuyer(Resource):
    
    @require_appkey
    @multi_auth.login_required
    def delete(self):
        try:
            # Parse the arguments
            parser = reqparse.RequestParser()
            parser.add_argument('kode_buyer', type=str, help='1. kode_buyer')
            args = parser.parse_args()

            _kode_buyer = args['kode_buyer']

            conn = mysql.connect()
            cursor = conn.cursor()
            cursor.callproc('sp_DeleteBuyer', (_kode_buyer,))
            data = cursor.fetchall()

            if len(data) == 0:
                conn.commit()
                return jsonify({'StatusCode':'200', 'message': 'Sukses hapus ...!'})
            else:
                return jsonify({'StatusCode':'100', 'message': str(data[0])})

        except Exception as e:
            return {'error': str(e)}


class ReadAllBuyer(Resource):
    
    @require_appkey
    @multi_auth.login_required
    def get(self):
        try: 
            conn = mysql.connect()
            cursor = conn.cursor()
            cursor.callproc('sp_ReadAllBuyer')
            data = cursor.fetchall()

            items_ReadAllBuyer = [];
            for item in data:
                i = {
                    'kode_buyer':item[0], 'nama_buyer':item[1],
                    'nama_usaha':item[2], 'jenis_usaha':item[3], 'alamat':item[4],
                    'kelurahan':item[5], 'kecamatan':item[6], 'kabupaten':item[7],
                    'propinsi':item[8], 'email':item[9], 'telepon':item[10]
                }

                items_ReadAllBuyer.append(i)

            return jsonify(items_ReadAllBuyer)

        except Exception as e:
            return jsonify({'StatusCode':'100', 'Message': str(e)})


class ReadBuyer(Resource):
    
    @require_appkey
    @multi_auth.login_required
    def get(self):
        try:
            # Parse the arguments
            parser = reqparse.RequestParser()
            parser.add_argument('kode_buyer', type=str, help='1. kode_buyer')
            args = parser.parse_args()

            _kode_buyer = args['kode_buyer']

            conn = mysql.connect()
            cursor = conn.cursor()
            cursor.callproc('sp_ReadBuyer',(_kode_buyer,))
            data = cursor.fetchall()

            items_ReadBuyer = [];
            for item in data:
                i = {
                    'kode_buyer':item[0], 'nama_buyer':item[1],
                    'nama_usaha':item[2], 'jenis_usaha':item[3], 'alamat':item[4],
                    'kelurahan':item[5], 'kecamatan':item[6], 'kabupaten':item[7],
                    'propinsi':item[8], 'email':item[9], 'telepon':item[10]
                }

                items_ReadBuyer.append(i)

            return jsonify(items_ReadBuyer)

        except Exception as e:
            return jsonify({'StatusCode':'100', 'Message': str(e)})


class UpdateBuyer(Resource):
    
    @require_appkey
    @multi_auth.login_required
    def put(self):
        try:
            # Parse the arguments
            parser = reqparse.RequestParser()
            parser.add_argument('kode_buyer', type=str, help='1. kode_buyer')
            parser.add_argument('nama_buyer', type=str, help='2. nama_buyer')
            parser.add_argument('nama_usaha', type=str, help='3. nama_usaha')
            parser.add_argument('jenis_usaha', type=str, help='4. jenis_usaha')
            parser.add_argument('alamat', type=str, help='5. alamat')

            parser.add_argument('kelurahan', type=str, help='6. kelurahan')
            parser.add_argument('kecamatan', type=str, help='7. kecamatan')
            parser.add_argument('kabupaten', type=str, help='8. kabupaten')
            parser.add_argument('propinsi', type=str, help='9. propinsi')
            parser.add_argument('email', type=str, help='10. email')

            parser.add_argument('telepon', type=str, help='11. telepon')
            args = parser.parse_args()

            _kode_buyer = args['kode_buyer']
            _nama_buyer = args['nama_buyer']
            _nama_usaha = args['nama_usaha']
            _jenis_usaha = args['jenis_usaha']
            _alamat = args['alamat']

            _kelurahan = args['kelurahan']
            _kecamatan = args['kecamatan']
            _kabupaten = args['kabupaten']
            _propinsi = args['propinsi']
            _email = args['email']

            _telepon = args['telepon']

            conn = mysql.connect()
            cursor = conn.cursor()
            cursor.callproc('sp_UpdateBuyer', (_kode_buyer, _nama_buyer, _nama_usaha, _jenis_usaha, _alamat, _kelurahan, _kecamatan, _kabupaten, _propinsi, _email, _telepon,))
            data = cursor.fetchall()

            if len(data) == 0:
                conn.commit()
                return jsonify({'StatusCode':'200', 'message': 'Sukses update ...!'})
            else:
                return jsonify({'StatusCode':'100', 'message': str(data[0])})

        except Exception as e:
            return {'error': str(e)}


#### ------ KELOLA DATA PEMILIK PADA UMKM -------- ####
#### ------------------------------------------- ####
class CreatePemilik(Resource):
    
    @require_appkey
    @multi_auth.login_required
    def post(self):
        try:
            # Parse the arguments
            parser = reqparse.RequestParser()
            parser.add_argument('id_pemilik', type=str, help='1. id_pemilik')
            parser.add_argument('nama_pemilik', type=str, help='2. nama_pemilik')
            parser.add_argument('alamat_pemilik', type=str, help='3. alamat_pemilik')
            parser.add_argument('kota', type=str, help='4. kota')
            parser.add_argument('telpon', type=str, help='5. telpon')
            parser.add_argument('email', type=str, help='6. email')
            parser.add_argument('logo', type=str, help='7. logo')

            args = parser.parse_args()

            _id_pemilik = args['id_pemilik']
            _nama_pemilik = args['nama_pemilik']
            _alamat_pemilik = args['alamat_pemilik']
            _kota = args['kota']
            _telpon = args['telpon']
            _email = args['email']
            _logo = args['logo']

            conn = mysql.connect()
            cursor = conn.cursor()
            cursor.callproc('sp_CreatePemilik', (_id_pemilik, _nama_pemilik, _alamat_pemilik, _kota, _telpon, _email, _logo,))
            data = cursor.fetchall()

            if len(data) == 0:
                conn.commit()
                return jsonify({'StatusCode':'200', 'message': 'Sukses simpan..!'})
            else:
                return jsonify({'StatusCode':'100', 'message': str(data[0])})

        except Exception as e:
            return {'error': str(e)}


class DeletePemilik(Resource):
    
    @require_appkey
    @multi_auth.login_required
    def delete(self):
        try:
            # Parse the arguments
            parser = reqparse.RequestParser()
            parser.add_argument('id_pemilik', type=str, help='1. id_pemilik')
            args = parser.parse_args()

            _id_pemilik = args['id_pemilik']

            conn = mysql.connect()
            cursor = conn.cursor()
            cursor.callproc('sp_DeletePemilik', (_id_pemilik,))
            data = cursor.fetchall()

            if len(data) == 0:
                conn.commit()
                return jsonify({'StatusCode':'200', 'message': 'Sukses hapus ...!'})
            else:
                return jsonify({'StatusCode':'100', 'message': str(data[0])})

        except Exception as e:
            return {'error': str(e)}


class ReadAllPemilik(Resource):
    
    @require_appkey
    @multi_auth.login_required
    def get(self):
        try: 
            conn = mysql.connect()
            cursor = conn.cursor()
            cursor.callproc('sp_ReadAllPemilik')
            data = cursor.fetchall()

            items_ReadAllPemilik = [];
            for item in data:
                i = {
                    'id_pemilik':item[0], 'nama_pemilik':item[1], 'alamat_pemilik':item[2], 'kota':item[3],
                    'telpon':item[4], 'email':item[5], 'logo':item[6]
                }

                items_ReadAllPemilik.append(i)

            return jsonify(items_ReadAllPemilik)

        except Exception as e:
            return jsonify({'StatusCode':'100', 'Message': str(e)})


class ReadPemilik(Resource):
    
    @require_appkey
    @multi_auth.login_required
    def get(self):
        try:
            # Parse the arguments
            parser = reqparse.RequestParser()
            parser.add_argument('id_pemilik', type=str, help='1. id_pemilik')
            args = parser.parse_args()

            _id_pemilik = args['id_pemilik']

            conn = mysql.connect()
            cursor = conn.cursor()
            cursor.callproc('sp_ReadPemilik',(_id_pemilik,))
            data = cursor.fetchall()

            items_ReadPemilik = [];
            for item in data:
                i = {
                    'id_pemilik':item[0], 'nama_pemilik':item[1], 'alamat_pemilik':item[2], 'kota':item[3],
                    'telpon':item[4], 'email':item[5], 'logo':item[6]
                }

                items_ReadPemilik.append(i)

            return jsonify(items_ReadPemilik)

        except Exception as e:
            return jsonify({'StatusCode':'100', 'Message': str(e)})


class UpdatePemilik(Resource):
    
    @require_appkey
    @multi_auth.login_required
    def put(self):
        try:
            # Parse the arguments
            parser = reqparse.RequestParser()
            parser.add_argument('id_pemilik', type=str, help='1. id_pemilik')
            parser.add_argument('nama_pemilik', type=str, help='2. nama_pemilik')
            parser.add_argument('alamat_pemilik', type=str, help='3. alamat_pemilik')
            parser.add_argument('kota', type=str, help='4. kota')
            parser.add_argument('telpon', type=str, help='5. telpon')
            parser.add_argument('email', type=str, help='6. email')
            parser.add_argument('logo', type=str, help='7. logo')

            args = parser.parse_args()

            _id_pemilik = args['id_pemilik']
            _nama_pemilik = args['nama_pemilik']
            _alamat_pemilik = args['alamat_pemilik']
            _kota = args['kota']
            _telpon = args['telpon']
            _email = args['email']
            _logo = args['logo']

            conn = mysql.connect()
            cursor = conn.cursor()
            cursor.callproc('sp_UpdatePemilik', (_id_pemilik, _nama_pemilik, _alamat_pemilik, _kota, _telpon, _email, _logo))
            data = cursor.fetchall()

            if len(data) == 0:
                conn.commit()
                return jsonify({'StatusCode':'200', 'message': 'Sukses update ...!'})
            else:
                return jsonify({'StatusCode':'100', 'message': str(data[0])})

        except Exception as e:
            return {'error': str(e)}


#### ------ KELOLA DATA TRANSAKSI BUYER PADA UMKM -------- ####
#### ------------------------------------------- ####
class CreateTransaksi(Resource):
    
    @require_appkey
    @multi_auth.login_required
    def post(self):
        try:
            # Parse the arguments
            parser = reqparse.RequestParser()
            parser.add_argument('kode_transaksi', type=str, help='1. kode_transaksi')
            parser.add_argument('kode_buyer', type=str, help='2. kode_buyer')
            parser.add_argument('kode_produk', type=str, help='3. kode_produk')
            parser.add_argument('kode_profile', type=str, help='4. kode_profile')
            parser.add_argument('jumlah_pesan', type=int, help='5. jumlah_pesan')

            parser.add_argument('tanggal_transaksi', type=str, help='6. tanggal_transaksi')
            parser.add_argument('status_transaksi', type=str, help='7. status_transaksi')

            args = parser.parse_args()

            _kode_transaksi = args['kode_transaksi']
            _kode_buyer = args['kode_buyer']
            _kode_produk = args['kode_produk']
            _kode_profile = args['kode_profile']
            _jumlah_pesan = args['jumlah_pesan']

            _tanggal_transaksi = args['tanggal_transaksi']
            _status_transaksi = args['status_transaksi']


            conn = mysql.connect()
            cursor = conn.cursor()
            cursor.callproc('sp_CreateTransaksi', (_kode_transaksi, _kode_buyer, _kode_produk, _kode_profile, _jumlah_pesan, _tanggal_transaksi, _status_transaksi,))
            data = cursor.fetchall()

            if len(data) == 0:
                conn.commit()
                return jsonify({'StatusCode':'200', 'message': 'Sukses simpan..!'})
            else:
                return jsonify({'StatusCode':'100', 'message': str(data[0])})

        except Exception as e:
            return {'error': str(e)}


class ReadAllTransaksi(Resource):
    
    @require_appkey
    @multi_auth.login_required
    def get(self):
        try: 
            conn = mysql.connect()
            cursor = conn.cursor()
            cursor.callproc('sp_ReadAllTransaksi')
            data = cursor.fetchall()

            items_ReadAllTransaksi = [];
            for item in data:
                i = {
                    'kode_transaksi':item[0], 'kode_buyer':item[1], 'kode_produk':item[2], 'kode_profile':item[3],
                    'jumlah_pesan':item[4], 'tanggal_transaksi':item[5], 'status_transaksi':item[6]
                }

                items_ReadAllTransaksi.append(i)

            return jsonify(items_ReadAllTransaksi)

        except Exception as e:
            return jsonify({'StatusCode':'100', 'Message': str(e)})


#### ------------------------------
#### ------- Lain-lain -----
class CreateOrder(Resource):
    
    @require_appkey
    @multi_auth.login_required
    def post(self):
        try:
            # Parse the arguments
            parser = reqparse.RequestParser()
            parser.add_argument('kode_order', type=str, help='1. kode order')
            parser.add_argument('tgl_order', type=str, help='2. tgl order')
            parser.add_argument('nama_pemesan', type=str, help='3. nama pemesan')
            parser.add_argument('email_pemesan', type=str, help='4. email pemesan')
            parser.add_argument('nama_penerima', type=str, help='5. nama penerima')
            parser.add_argument('email_penerima', type=int, help='6. email penerima')
            parser.add_argument('telpon_penerima', type=str, help='7. telpon penerima')
            parser.add_argument('alamat_penerima', type=str, help='8. alamat penerima')
            parser.add_argument('propinsi_penerima', type=str, help='9. propinsi penerima')
            parser.add_argument('kabupaten_penerima', type=str, help='10. kabupaten penerima')
            parser.add_argument('kecamatan_penerima', type=str, help='11. kecamatan penerima')
            parser.add_argument('desa_penerima', type=str, help='12. desa penerima')
            args = parser.parse_args()

            _kode_order = args['kode_order']
            _tgl_order = args['tgl_order']
            _nama_pemesan = args['nama_pemesan']
            _email_pemesan = args['email_pemesan']
            _nama_penerima = args['nama_penerima']
            _email_penerima = args['email_penerima']
            _telpon_penerima = args['telpon_penerima']
            _alamat_penerima = args['alamat_penerima']
            _propinsi_penerima = args['propinsi_penerima']
            _kabupaten_penerima = args['kabupaten_penerima']
            _kecamatan_penerima = args['kecamatan_penerima']
            _desa_penerima = args['desa_penerima']

            conn = mysql.connect()
            cursor = conn.cursor()
            cursor.callproc('sp_CreateOrder', (_kode_order, _tgl_order, _nama_pemesan, _email_pemesan, _nama_penerima,
                                _email_penerima, _telpon_penerima, _alamat_penerima, _propinsi_penerima, _kabupaten_penerima,
                                _kecamatan_penerima, _desa_penerima,))
            data = cursor.fetchall()

            if len(data) == 0:
                conn.commit()
                return jsonify({'StatusCode':'200', 'Message': 'Create Order success'})
            else:
                return jsonify({'StatusCode':'100', 'Message': str(data[0])})

        except Exception as e:
            return {'error': str(e)}


class CreateTagihan(Resource):
    
    @require_appkey
    @multi_auth.login_required
    def post(self):
        try:
            # Parse the arguments
            parser = reqparse.RequestParser()
            parser.add_argument('kode_tagihan', type=str, help='1. kode_tagihan')
            parser.add_argument('kode_akun', type=str, help='2. kode_akun')
            parser.add_argument('kode_skema', type=str, help='3. kode_skema')
            parser.add_argument('tgl_tagihan', type=str, help='4. tgl_tagihan')
            parser.add_argument('jumlah_bayar', type=str, help='5. jumlah_bayar')  
            args = parser.parse_args()

            _kode_tagihan = args['kode_tagihan']
            _kode_akun = args['kode_akun']
            _kode_skema = args['kode_skema']
            _tgl_tagihan = args['tgl_tagihan']
            _jumlah_bayar = args['jumlah_bayar']

            conn = mysql.connect()
            cursor = conn.cursor()
            cursor.callproc('sp_CreateTagihan', (_kode_tagihan, _kode_akun, _kode_skema, _tgl_tagihan, _jumlah_bayar,))
            data = cursor.fetchall()

            if len(data) == 0:
                conn.commit()
                return jsonify({'StatusCode':'200', 'Message': 'Sukses buat tagihan...!'})
            else:
                return jsonify({'StatusCode':'100', 'Message': str(data[0])})

        except Exception as e:
            return {'error': str(e)}


class UpdateTagihan(Resource):
    
    @require_appkey
    @multi_auth.login_required
    def put(self):
        try:
            # Parse the arguments
            parser = reqparse.RequestParser()
            parser.add_argument('kode_tagihan', type=str, help='1. kode_tagihan')
            parser.add_argument('kode_akun', type=str, help='2. kode_akun')
            parser.add_argument('tgl_tagihan', type=str, help='3. tgl_tagihan')
            parser.add_argument('tgl_bayar', type=str, help='4. tgl_bayar')
            parser.add_argument('dari_bank', type=str, help='5. dari_bank')
            parser.add_argument('norek_bank', type=str, help='6.norek_bank')
            parser.add_argument('nama_pemilik', type=str, help='7. nama_pemilik')
            parser.add_argument('ke_bank', type=str, help='8. ke_bank')
            parser.add_argument('jumlah_bayar', type=str, help='9. jumlah_bayar')
            parser.add_argument('keterangan', type=str, help='10. keterangan')        
            args = parser.parse_args()

            _kode_tagihan = args['kode_tagihan']
            _kode_akun = args['kode_akun']
            _tgl_tagihan = args['tgl_tagihan']
            _tgl_bayar = args['tgl_bayar']
            _dari_bank = args['dari_bank']

            _norek_bank = args['norek_bank']
            _nama_pemilik = args['nama_pemilik']
            _ke_bank = args['ke_bank']
            _jumlah_bayar = args['jumlah_bayar']
            _keterangan = args['keterangan']

            conn = mysql.connect()
            cursor = conn.cursor()
            cursor.callproc('sp_UpdateTagihan', (_kode_tagihan, _kode_akun, _tgl_tagihan, _tgl_bayar, _dari_bank,
                    _norek_bank, _nama_pemilik, _ke_bank, _jumlah_bayar, _keterangan,))
            data = cursor.fetchall()

            if len(data) == 0:
                return jsonify({'StatusCode':'200', 'Message': 'Sukses update tagihan..!'})
            else:
                return jsonify({'StatusCode':'100', 'Message': str(data[0])})

        except Exception as e:
            return {'error': str(e)}


class ReadTagihan(Resource):
    
    @require_appkey
    @multi_auth.login_required
    def get(self):
        try: 
            conn = mysql.connect()
            cursor = conn.cursor()
            cursor.callproc('sp_ReadTagihan')
            data = cursor.fetchall()

            items_ReadTagihan = [];
            for item in data:
                i = {
                    'kode_tagihan':item[0],
                    'kode_akun':item[1],
                    'kode_skema':item[2],
                    'tgl_tagihan':item[3].strftime("%d-%m-%Y"),
                    'tgl_bayar':item[4].strftime("%d-%m-%Y"),
                    'dari_bank':item[5],
                    'norek_bank':item[6],
                    'nama_pemilik':item[7],
                    'ke_bank':item[8],
                    'jumlah_bayar':'{:,.2f}'.format(item[9]),
                    'keterangan':item[10]
                }
                items_ReadTagihan.append(i)

            return jsonify(items_ReadTagihan)

        except Exception as e:
            return jsonify({'StatusCode':'100', 'Message': str(e)})


### ------ Tabel Referensi lainnya
### ------------------------------
class GetNegara(Resource):
    
    @require_appkey
    @multi_auth.login_required
    def get(self):
        try: 
            conn = mysql.connect()
            cursor = conn.cursor()
            cursor.callproc('sp_GetNegara')
            data = cursor.fetchall()

            items_getNegara = [];
            for item in data:
                i = {
                    'id':item[0],
                    'country_code':item[1],
                    'country_name':item[2]
                }
                items_getNegara.append(i)

            return jsonify(items_getNegara)

        except Exception as e:
            return jsonify({'StatusCode':'100', 'Message': str(e)})


class GetPropinsi(Resource):
    
    @require_appkey
    @multi_auth.login_required
    def get(self):
        try: 
            conn = mysql.connect()
            cursor = conn.cursor()
            cursor.callproc('sp_GetProvinces')
            data = cursor.fetchall()

            items_getpropinsi = [];
            for item in data:
                i = {
                    'id':item[0],
                    'name':item[1]
                }
                items_getpropinsi.append(i)

            return jsonify(items_getpropinsi)

        except Exception as e:
            return jsonify({'StatusCode':'100', 'Message': str(e)})


class GetKabupaten(Resource):
    
    @require_appkey
    @multi_auth.login_required
    def get(self):
        try: 
            conn = mysql.connect()
            cursor = conn.cursor()
            cursor.callproc('sp_GetRegencies')
            data = cursor.fetchall()

            items_getregensi = [];
            for item in data:
                i = {
                    'id':item[0],
                    'province_id':item[1],
                    'kabupaten':item[2],
                    'propinsi':item[3]
                }
                items_getregensi.append(i)

            return jsonify(items_getregensi)

        except Exception as e:
            return jsonify({'StatusCode':'100', 'Message': str(e)})


class GetKabupatenJateng(Resource):
    
    @require_appkey
    @multi_auth.login_required
    def get(self):
        try: 
            conn = mysql.connect()
            cursor = conn.cursor()
            cursor.callproc('sp_GetKabupaten')
            data = cursor.fetchall()

            items_getkabupaten = [];
            for item in data:
                i = {
                    'id':item[0],
                    'province_id':item[1],
                    'kabupaten':item[2],
                    'propinsi':item[3]
                }
                items_getkabupaten.append(i)

            return jsonify(items_getkabupaten)

        except Exception as e:
            return jsonify({'StatusCode':'100', 'Message': str(e)})


class GetKecamatan(Resource):
    
    @require_appkey
    @multi_auth.login_required
    def get(self):
        try: 
            conn = mysql.connect()
            cursor = conn.cursor()
            cursor.callproc('sp_GetDistrik')
            data = cursor.fetchall()

            items_getdistrik = [];
            for item in data:
                i = {
                    'id':item[0],
                    'regency_id':item[1],
                    'name':item[2]
                }
                items_getdistrik.append(i)

            return jsonify(items_getdistrik)

        except Exception as e:
            return jsonify({'StatusCode':'100', 'Message': str(e)})


class GetDesa(Resource):
    
    @require_appkey
    @multi_auth.login_required
    def get(self):
        try: 
            conn = mysql.connect()
            cursor = conn.cursor()
            cursor.callproc('sp_GetDesa')
            data = cursor.fetchall()

            items_getdesa = [];
            for item in data:
                i = {
                    'id':item[0],
                    'district_id':item[1],
                    'name':item[2]
                }
                items_getdesa.append(i)

            return jsonify(items_getdesa)

        except Exception as e:
            return jsonify({'StatusCode':'100', 'Message': str(e)})


class GetKategori(Resource):
    
    @require_appkey
    @multi_auth.login_required
    def get(self):
        try: 
            conn = mysql.connect()
            cursor = conn.cursor()
            cursor.callproc('sp_GetKategori')
            data = cursor.fetchall()

            items_getkategori = [];
            for item in data:
                i = {
                    'kode':item[0],
                    'deskripsi':item[1]
                }
                items_getkategori.append(i)

            return jsonify({'StatusCode':'200', 'data':items_getkategori})

        except Exception as e:
            return jsonify({'StatusCode':'100', 'Message': str(e)})


class GetInvoiceStatus(Resource):
    
    @require_appkey
    @multi_auth.login_required
    def get(self):
        try: 
            conn = mysql.connect()
            cursor = conn.cursor()
            cursor.callproc('sp_GetInvoiceStatus')
            data = cursor.fetchall()

            items_getinvoicestatus = [];
            for item in data:
                i = {
                    'kode':item[0],
                    'deskripsi':item[1]
                }
                items_getinvoicestatus.append(i)

            return jsonify(items_getinvoicestatus)

        except Exception as e:
            return jsonify({'StatusCode':'100', 'Message': str(e)})



class KodeBank(Resource):
    
    @require_appkey
    @multi_auth.login_required
    def get(self):
        try: 
            conn = mysql.connect()
            cursor = conn.cursor()
            cursor.callproc('sp_KodeBank')
            data = cursor.fetchall()

            items_getkodebank = [];
            for item in data:
                i = {
                    'kode':item[0],
                    'nama_bank':item[1]
                }
                items_getkodebank.append(i)

            return jsonify(items_getkodebank)

        except Exception as e:
            return jsonify({'StatusCode':'100', 'Message': str(e)})


### --- KELOLOA DATA INVOICE PRODUKSI  ---- ###
### ---------------------------------- ###

class CreateInvProduksi(Resource):
    
    @require_appkey
    @multi_auth.login_required
    def post(self):
        try:
            # Parse the arguments
            parser = reqparse.RequestParser()
            parser.add_argument('inv_number', type=str, help='1. inv_number')
            parser.add_argument('kd_barang', type=str, help='2. kd_barang')
            parser.add_argument('nm_barang', type=int, help='3. nm_barang')
            parser.add_argument('harga', type=str, help='4. harga')
            parser.add_argument('jumlah', type=str, help='5. jumlah')
            parser.add_argument('total', type=int, help='6. total')
            parser.add_argument('tgl_pesan', type=str, help='7. tgl_pesan')
            parser.add_argument('penerima', type=str, help='8. penerima')
            parser.add_argument('alamat', type=str, help='9. alamat')
            args = parser.parse_args()

            _inv_number = args['inv_number']
            _kd_barang = args['kd_barang']
            _nm_barang = args['nm_barang']
            _harga = args['harga']
            _jumlah = args['jumlah']
            _total = args['total']
            _tgl_pesan = args['tgl_pesan']
            _penerima = args['penerima']
            _alamat = args['alamat']

            conn = mysql.connect()
            cursor = conn.cursor()
            cursor.callproc('sp_CreateInvProduksi', (_inv_number, _kd_barang, _nm_barang, _harga, _jumlah, _total, _tgl_pesan, _penerima, _alamat,))
            data = cursor.fetchall()

            if len(data) == 0:
                conn.commit()
                return jsonify({'StatusCode':'200', 'message': 'Sukses simpan..!'})
            else:
                return jsonify({'StatusCode':'100', 'message': str(data[0])})

        except Exception as e:
            return {'error': str(e)}


class DeleteInvProduksi(Resource):
    
    @require_appkey
    @multi_auth.login_required
    def delete(self):
        try:
            # Parse the arguments
            parser = reqparse.RequestParser()
            parser.add_argument('inv_number', type=str, help='1. inv_number')
            args = parser.parse_args()

            _inv_number = args['inv_number']

            conn = mysql.connect()
            cursor = conn.cursor()
            cursor.callproc('sp_DeleteInvProduksi', (_inv_number,))
            data = cursor.fetchall()

            if len(data) == 0:
                conn.commit()
                return jsonify({'StatusCode':'200', 'message': 'Sukses hapus ...!'})
            else:
                return jsonify({'StatusCode':'100', 'message': str(data[0])})

        except Exception as e:
            return {'error': str(e)}


class ReadAllInvProduksi(Resource):
    
    @require_appkey
    @multi_auth.login_required
    def get(self):
        try: 
            conn = mysql.connect()
            cursor = conn.cursor()
            cursor.callproc('sp_ReadAllInvProduksi')
            data = cursor.fetchall()

            items_ReadAllProduk = [];
            for item in data:
                i = {
                    'inv_number':item[0], 'kd_barang':item[1], 'nm_barang':item[2],
                    'harga':item[3], 'jumlah':item[4], 'total':item[5],
                    'tgl_pesan':item[6], 'penerima':item[7], 'alamat':item[8]
                }

                items_ReadAllProduk.append(i)

            return jsonify(items_ReadAllProduk)

        except Exception as e:
            return jsonify({'StatusCode':'100', 'Message': str(e)})


class UpdateInvProduksi(Resource):
    
    @require_appkey
    @multi_auth.login_required
    def put(self):
        try:
            # Parse the arguments
            parser = reqparse.RequestParser()
            parser.add_argument('inv_number', type=str, help='1. inv_number')
            parser.add_argument('kd_barang', type=str, help='2. kd_barang')
            parser.add_argument('nm_barang', type=int, help='3. nm_barang')
            parser.add_argument('harga', type=str, help='4. harga')
            parser.add_argument('jumlah', type=str, help='5. jumlah')
            parser.add_argument('total', type=int, help='6. total')
            parser.add_argument('tgl_pesan', type=str, help='7. tgl_pesan')
            parser.add_argument('penerima', type=str, help='8. penerima')
            parser.add_argument('alamat', type=str, help='9. alamat')
            args = parser.parse_args()

            _inv_number = args['inv_number']
            _kd_barang = args['kd_barang']
            _nm_barang = args['nm_barang']
            _harga = args['harga']
            _jumlah = args['jumlah']
            _total = args['total']
            _tgl_pesan = args['tgl_pesan']
            _penerima = args['penerima']
            _alamat = args['alamat']

            conn = mysql.connect()
            cursor = conn.cursor()
            cursor.callproc('sp_UpdateInvProduksi', (_inv_number, _kd_barang, _nm_barang, _harga, _jumlah, _total, _tgl_pesan, _penerima, _alamat,))
            data = cursor.fetchall()

            if len(data) == 0:
                conn.commit()
                return jsonify({'StatusCode':'200', 'message': 'Sukses update ...!'})
            else:
                return jsonify({'StatusCode':'100', 'message': str(data[0])})

        except Exception as e:
            return {'error': str(e)}
### --- EOF Invoice Produksi --- ###
### ---------------------------- ###


### --- KELOLOA DATA STATUS PRODUKSI  ---- ###
### ---------------------------------- ###

class CreateStProduksi(Resource):
    
    @require_appkey
    @multi_auth.login_required
    def post(self):
        try:
            # Parse the arguments
            parser = reqparse.RequestParser()
            parser.add_argument('inv_number', type=str, help='1. inv_number')
            parser.add_argument('status', type=str, help='2. status')
            parser.add_argument('catatan', type=int, help='3. catatan')
            parser.add_argument('tgl_masuk', type=str, help='4. tgl_masuk')
            parser.add_argument('tgl_produksi', type=str, help='5. tgl_produksi')
            parser.add_argument('tgl_selesai', type=int, help='6. tgl_selesai')
            args = parser.parse_args()

            _inv_number = args['inv_number']
            _status = args['status']
            _catatan = args['catatan']
            _tgl_masuk = args['tgl_masuk']
            _tgl_produksi = args['tgl_produksi']
            _tgl_selesai = args['tgl_selesai']

            conn = mysql.connect()
            cursor = conn.cursor()
            cursor.callproc('sp_CreateStProduksi', (_inv_number, _status, _catatan, _tgl_masuk, _tgl_produksi, _tgl_selesai,))
            data = cursor.fetchall()

            if len(data) == 0:
                conn.commit()
                return jsonify({'StatusCode':'200', 'message': 'Sukses simpan..!'})
            else:
                return jsonify({'StatusCode':'100', 'message': str(data[0])})

        except Exception as e:
            return {'error': str(e)}


class DeleteStProduksi(Resource):
    
    @require_appkey
    @multi_auth.login_required
    def delete(self):
        try:
            # Parse the arguments
            parser = reqparse.RequestParser()
            parser.add_argument('inv_number', type=str, help='1. inv_number')
            args = parser.parse_args()

            _inv_number = args['inv_number']

            conn = mysql.connect()
            cursor = conn.cursor()
            cursor.callproc('sp_DeleteStProduksi', (_inv_number,))
            data = cursor.fetchall()

            if len(data) == 0:
                conn.commit()
                return jsonify({'StatusCode':'200', 'message': 'Sukses hapus ...!'})
            else:
                return jsonify({'StatusCode':'100', 'message': str(data[0])})

        except Exception as e:
            return {'error': str(e)}


class ReadAllStProduksi(Resource):
    
    @require_appkey
    @multi_auth.login_required
    def get(self):
        try: 
            conn = mysql.connect()
            cursor = conn.cursor()
            cursor.callproc('sp_ReadAllStProduksi')
            data = cursor.fetchall()

            items_ReadAllProduk = [];
            for item in data:
                i = {
                    'inv_number':item[0], 'status':item[1], 'catatan':item[2],
                    'tgl_masuk':item[3], 'tgl_produksi':item[4], 'tgl_selesai':item[5]
                }

                items_ReadAllProduk.append(i)

            return jsonify(items_ReadAllProduk)

        except Exception as e:
            return jsonify({'StatusCode':'100', 'Message': str(e)})


class UpdateStProduksi(Resource):
    
    @require_appkey
    @multi_auth.login_required
    def put(self):
        try:
            # Parse the arguments
            parser = reqparse.RequestParser()
            parser.add_argument('inv_number', type=str, help='1. inv_number')
            parser.add_argument('status', type=str, help='2. status')
            parser.add_argument('catatan', type=int, help='3. catatan')
            parser.add_argument('tgl_masuk', type=str, help='4. tgl_masuk')
            parser.add_argument('tgl_produksi', type=str, help='5. tgl_produksi')
            parser.add_argument('tgl_selesai', type=int, help='6. tgl_selesai')
            args = parser.parse_args()

            _inv_number = args['inv_number']
            _status = args['status']
            _catatan = args['catatan']
            _tgl_masuk = args['tgl_masuk']
            _tgl_produksi = args['tgl_produksi']
            _tgl_selesai = args['tgl_selesai']

            conn = mysql.connect()
            cursor = conn.cursor()
            cursor.callproc('sp_UpdateStProduksi', (_inv_number, _status, _catatan, _tgl_masuk, _tgl_produksi, _tgl_selesai,))
            data = cursor.fetchall()

            if len(data) == 0:
                conn.commit()
                return jsonify({'StatusCode':'200', 'message': 'Sukses update ...!'})
            else:
                return jsonify({'StatusCode':'100', 'message': str(data[0])})

        except Exception as e:
            return {'error': str(e)}
### --- EOF Invoice Produksi --- ###
### ---------------------------- ###


### --- KELOLOA DATA STATUS PEMBAYARAN  ---- ###
### ---------------------------------- ###

class CreateStPembayaran(Resource):
    
    @require_appkey
    @multi_auth.login_required
    def post(self):
        try:
            # Parse the arguments
            parser = reqparse.RequestParser()
            parser.add_argument('inv_number', type=str, help='1. inv_number')
            parser.add_argument('mode_bayar', type=str, help='2. mode_bayar')
            parser.add_argument('bukti_bayar', type=int, help='3. bukti_bayar')
            parser.add_argument('status', type=str, help='4. status')
            parser.add_argument('tgl_bayar', type=str, help='5. tgl_bayar')
            args = parser.parse_args()

            _inv_number = args['inv_number']
            _mode_bayar = args['mode_bayar']
            _bukti_bayar = args['bukti_bayar']
            _status = args['status']
            _tgl_bayar = args['tgl_bayar']

            conn = mysql.connect()
            cursor = conn.cursor()
            cursor.callproc('sp_CreateStPembayaran', (_inv_number, _mode_bayar, _bukti_bayar, _status, _tgl_bayar,))
            data = cursor.fetchall()

            if len(data) == 0:
                conn.commit()
                return jsonify({'StatusCode':'200', 'message': 'Sukses simpan..!'})
            else:
                return jsonify({'StatusCode':'100', 'message': str(data[0])})

        except Exception as e:
            return {'error': str(e)}


class DeleteStPembayaran(Resource):
    
    @require_appkey
    @multi_auth.login_required
    def delete(self):
        try:
            # Parse the arguments
            parser = reqparse.RequestParser()
            parser.add_argument('inv_number', type=str, help='1. inv_number')
            args = parser.parse_args()

            _inv_number = args['inv_number']

            conn = mysql.connect()
            cursor = conn.cursor()
            cursor.callproc('sp_DeleteStPembayaran', (_inv_number,))
            data = cursor.fetchall()

            if len(data) == 0:
                conn.commit()
                return jsonify({'StatusCode':'200', 'message': 'Sukses hapus ...!'})
            else:
                return jsonify({'StatusCode':'100', 'message': str(data[0])})

        except Exception as e:
            return {'error': str(e)}


class ReadAllStPembayaran(Resource):
    
    @require_appkey
    @multi_auth.login_required
    def get(self):
        try: 
            conn = mysql.connect()
            cursor = conn.cursor()
            cursor.callproc('sp_ReadAllStPembayaran')
            data = cursor.fetchall()

            items_ReadAllProduk = [];
            for item in data:
                i = {
                    'inv_number':item[0], 'mode_bayar':item[1], 'bukti_bayar':item[2],
                    'status':item[3], 'tgl_bayar':item[4]
                }

                items_ReadAllProduk.append(i)

            return jsonify(items_ReadAllProduk)

        except Exception as e:
            return jsonify({'StatusCode':'100', 'Message': str(e)})


class UpdateStPembayaran(Resource):
    
    @require_appkey
    @multi_auth.login_required
    def put(self):
        try:
            # Parse the arguments
            parser = reqparse.RequestParser()
            parser.add_argument('inv_number', type=str, help='1. inv_number')
            parser.add_argument('mode_bayar', type=str, help='2. mode_bayar')
            parser.add_argument('bukti_bayar', type=int, help='3. bukti_bayar')
            parser.add_argument('status', type=str, help='4. status')
            parser.add_argument('tgl_bayar', type=str, help='5. tgl_bayar')
            args = parser.parse_args()

            _inv_number = args['inv_number']
            _mode_bayar = args['mode_bayar']
            _bukti_bayar = args['bukti_bayar']
            _status = args['status']
            _tgl_bayar = args['tgl_bayar']

            conn = mysql.connect()
            cursor = conn.cursor()
            cursor.callproc('sp_UpdateStPembayaran', (_inv_number, _mode_bayar, _bukti_bayar, _status, _tgl_bayar,))
            data = cursor.fetchall()

            if len(data) == 0:
                conn.commit()
                return jsonify({'StatusCode':'200', 'message': 'Sukses update ...!'})
            else:
                return jsonify({'StatusCode':'100', 'message': str(data[0])})

        except Exception as e:
            return {'error': str(e)}
### --- EOF Invoice Produksi --- ###
### ---------------------------- ###



### ------- API Kelola Pengguna UMKM ----- ####
api.add_resource(CreatePengguna, '/CreatePengguna')
api.add_resource(DeletePengguna, '/DeletePengguna')
api.add_resource(ReadPengguna, '/ReadPengguna')
api.add_resource(AuthenticateAndroid,'/AuthenticateAndroid')
api.add_resource(ResetPassword, '/ResetPassword')
api.add_resource(SendMail,'/SendMail')

### ---- API Kelola Data Profile ----- ####
api.add_resource(CreateProfile,'/CreateProfile')
api.add_resource(DeleteProfile,'/DeleteProfile')
api.add_resource(ReadAllProfile,'/ReadAllProfile')
api.add_resource(ReadProfile,'/ReadProfile')
api.add_resource(UpdateProfile,'/UpdateProfile')

### ----- API Kelola Kategori Produk UMKM ----- ###
### ----------------------------- ###
api.add_resource(CreateKategori,'/CreateKategori')
api.add_resource(DeleteKategori,'/DeleteKategori')
api.add_resource(ReadAllKategori,'/ReadAllKategori')
api.add_resource(ReadKategori,'/ReadKategori')
api.add_resource(UpdateKategori,'/UpdateKategori')

### ----- API Kelola Produk UMKM ----- ###
### ----------------------------- ###
api.add_resource(CreateProduk,'/CreateProduk')
api.add_resource(DeleteProduk,'/DeleteProduk')
api.add_resource(ReadAllProduk,'/ReadAllProduk')
api.add_resource(ReadProduk,'/ReadProduk')
api.add_resource(UpdateProduk,'/UpdateProduk')

api.add_resource(ReadAllJnsProduk,'/ReadAllJnsProduk')
api.add_resource(ReadAllStatus,'/ReadAllStatus')

### ----- API Kelola Buyer pada UMKM ----- ###
### -------------------------------------- ###
api.add_resource(CreateBuyer,'/CreateBuyer')
api.add_resource(DeleteBuyer,'/DeleteBuyer')
api.add_resource(ReadAllBuyer,'/ReadAllBuyer')
api.add_resource(ReadBuyer,'/ReadBuyer')
api.add_resource(UpdateBuyer,'/UpdateBuyer')

### ----- API Kelola Pemilik pada UMKM ----- ###
### -------------------------------------- ###
api.add_resource(CreatePemilik,'/CreatePemilik')
api.add_resource(DeletePemilik,'/DeletePemilik')
api.add_resource(ReadAllPemilik,'/ReadAllPemilik')
api.add_resource(ReadPemilik,'/ReadPemilik')
api.add_resource(UpdatePemilik,'/UpdatePemilik')

### ------ API Kelola Transaksi Buyer ---- ###
### -------------------------------------- ###
api.add_resource(CreateTransaksi,'/CreateTransaksi')
api.add_resource(ReadAllTransaksi,'/ReadAllTransaksi')

#api Tagihan pelanggan
api.add_resource(CreateTagihan, '/CreateTagihan')
api.add_resource(UpdateTagihan, '/UpdateTagihan')
api.add_resource(ReadTagihan, '/ReadTagihan')


#api propinsi, kabupaten, kecamatan, desa
api.add_resource(GetNegara, '/GetNegara')
api.add_resource(GetPropinsi, '/GetPropinsi')
api.add_resource(GetKabupaten, '/GetKabupaten')
api.add_resource(GetKabupatenJateng, '/GetKabupatenJateng')
api.add_resource(GetKecamatan, '/GetKecamatan')
api.add_resource(GetDesa, '/GetDesa')
api.add_resource(GetKategori, '/GetKategori')
api.add_resource(GetInvoiceStatus, '/GetInvoiceStatus')

#api referensi lainnya
api.add_resource(KodeBank, '/KodeBank')

### --- REST API Invoice Produksi --- #
api.add_resource(CreateInvProduksi,'/CreateInvProduksi')
api.add_resource(DeleteInvProduksi,'/DeleteInvProduksi')
api.add_resource(ReadAllInvProduksi,'/ReadAllInvProduksi')
api.add_resource(UpdateInvProduksi,'/UpdateInvProduksi')

### --- REST API Status Produksi --- #
api.add_resource(CreateStProduksi,'/CreateStProduksi')
api.add_resource(DeleteStProduksi,'/DeleteStProduksi')
api.add_resource(ReadAllStProduksi,'/ReadAllStProduksi')
api.add_resource(UpdateStProduksi,'/UpdateStProduksi')

### --- REST API Status Pembayaran --- #
api.add_resource(CreateStPembayaran,'/CreateStPembayaran')
api.add_resource(DeleteStPembayaran,'/DeleteStPembayaran')
api.add_resource(ReadAllStPembayaran,'/ReadAllStPembayaran')
api.add_resource(UpdateStPembayaran,'/UpdateStPembayaran')


if __name__ == '__main__':
    app.run(host=hostName, port=portNumber, debug=debugBoolean)
