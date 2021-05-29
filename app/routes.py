import email
from logging import log
import re

from sqlalchemy.sql.operators import notmatch_op
from app import app,db, cors
from flask import render_template, request, flash, redirect, url_for, send_file, make_response, jsonify, session, send_file
from app.models.File import fileModel, SignTable, Skripsi, temp
from flask_login import login_required, current_user, logout_user, login_user
import os
import base64
from datetime import timedelta, datetime
from sqlalchemy import and_
from flask_cors import CORS, cross_origin
from werkzeug.utils import secure_filename
from config import Config
from sqlalchemy import or_
from app.mail import send_mail

from app.models.Users import User, load_user, Permission
from app.decorators import permission_required, admin_required, check_confirmed
# from app.errors import forbidden, page_not_found, internal_server_error


from oscrypto import keys
from certvalidator import ValidationContext
from pyhanko.pdf_utils.reader import PdfFileReader
from pyhanko.sign.validation import validate_pdf_signature, validate_pdf_ltv_signature, RevocationInfoValidationType
from io import BytesIO
from pyhanko.sign.fields import SigFieldSpec, append_signature_field
from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
from pyhanko.sign import fields
from pyhanko.sign.diff_analysis import (
    SuspiciousModification, ModificationLevel, DEFAULT_DIFF_POLICY, DiffPolicy,
    DiffResult,
)
#STAMP
from app.PyHanko import buat_qr, create_sign, pretty, create_sign_new, create_field1, create_field2, create_field3, create_field4, create_field5, create_field6, create_field7
from app.pyCertificate import create_cert
from cryptography import x509
from cryptography.hazmat.primitives.serialization import load_pem_private_key


#Auth#####################################
@app.route('/login', methods=['POST','GET'])
def login():
    if request.method == 'POST':
        nomor = request.form['nm']
        password = request.form['password']
        user = User.query.filter_by(nomor=nomor).first()
        if user is not None and user.verify_password(password):
            login_user(user)
            next = request.args.get('next')
            if next is None or not next.startswith('/'):
                next = url_for('dashboard')
            return redirect(next)
        flash('Invalid NIM/NIDN or password.')
    return render_template('/login/login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    # flash('You have been logged out.')
    return redirect(url_for('index'))

@app.route('/register', methods=['POST'])
def register():
    if request.method == 'POST':
        name = request.form['name']
        nomor = request.form['nomor']
        email =  request.form['email']
        password = request.form['password']
        if '@mhs.pelitabangsa.ac.id' in email:
            try:
                usermhs = User(name = name, nomor = nomor, email = email, password = password, role_id = 1)
                db.session.add(usermhs)
                db.session.commit()
                token = usermhs.generate_confirmation_token()
                confirm_url = url_for('confirm', token = token, _external=True)
                html = render_template('/mail/activate.html', user= usermhs.name, nomor = usermhs.nomor, confirm_url = confirm_url)
                send_mail(usermhs.email, 'Confirm Your Account', html)
                login_user(usermhs)
                flash('A confirmation email has been sent to you by email.','success')
                return redirect(url_for('login'))
            except Exception as err:
                flash(str(err), 'warning')
                return redirect(url_for('login'))
        elif '@pelitabangsa.ac.id' in email:
            userdosen = User(name = name, nomor = nomor, email = email, password = password, role_id = 2)
            db.session.add(userdosen)
            db.session.commit()
            token = userdosen.generate_confirmation_token()
            confirm_url = url_for('confirm', token = token, _external=True)
            html = render_template('/mail/activate.html', user= userdosen.name, nomor= userdosen.nomor, confirm_url = confirm_url)
            send_mail(userdosen.email, 'Confirm Your Account', html)
            flash('A confirmation email has been sent to you by email.','success')
            login_user(userdosen)
            return redirect(url_for('login'))
        else:
            flash('Anda harus mengunakan email dari Pelita Bangsa', 'warning')
            return redirect(url_for('login'))
    return render_template('/login/login.html')
    
@app.route('/confirm/<token>')
@login_required
def confirm(token):
    if current_user.confirmed:
        return redirect(url_for('dashboard'))
    if current_user.confirm(token):
        db.session.commit()
        flash('You have confirmed your account. Terima Kasih !','success')
        return redirect(url_for('dashboard'))
    else:
        flash('The confirmation link is invalid or has expired.')
        return redirect(url_for('login'))

@app.route('/confirm')
@login_required
def resend_confirmation():
    try:
        token = current_user.generate_confirmation_token()
        confirm_url = url_for('confirm', token = token, _external=True)
        html = render_template('/mail/activate.html', user= current_user.name, nomor = current_user.nomor, confirm_url = confirm_url)
        send_mail(current_user.email, 'Confirm Your Account', html)
        flash('A new confirmation email has been sent to you by email.')
    except Exception as e:
        flash(str(e), 'warning')
        return redirect(url_for('login'))
    return redirect(url_for('login'))

@app.route('/unconfirmed')
@login_required
def unconfirmed():
    if current_user.confirmed:
        return redirect(url_for('dashboard'))
    # flash('Please confirm your account!', 'warning')
    return render_template('/login/unconfirmed.html')




# @app.before_request
# def before_request():
#     session.permanent = True
#     app.permanent_session_lifetime = timedelta(minutes=1)


#################  MAIN  ############################
@app.route('/')
def index():
   return render_template('landing.html')

@app.route('/dashboard')
@login_required
@check_confirmed
def dashboard():
    dosen = User.query.filter_by(role_id = 2).count()
    file = data = Skripsi.query.filter_by(user_id = current_user.id).count()
    data = Skripsi.query.filter(or_(Skripsi.peng1 == current_user.name, Skripsi.peng2==current_user.name, Skripsi.pem1==current_user.name, Skripsi.pem2 == current_user.name,
                                        Skripsi.dekan == current_user.name, Skripsi.prodi == current_user.name)).count()
    if current_user.can(8) and not current_user.can(Permission.ADMIN):
        if current_user.signature is None:
            flash('Lengkapi Profil anda dengan membuat tanda tangan pada menu Settings > Tanda tangan', 'danger')
        if current_user.sertifikat is None:
            flash('Lengkapi Profil anda dengan membuat sertifikat pada menu Settings > Sertifikat', 'danger')
    return render_template('index.html', dosen = dosen, data = data, file = file)
##################  DOKUEMEN KONTROL  ############################
@app.route('/delete/<id>')
@login_required
@check_confirmed
def delete_file(id):
   data = fileModel.query.filter_by(id=id).first_or_404()
   try:
       db.session.delete(data)
       db.session.commit()
       flash('Data berhasil di hapus','success')
       return redirect(url_for('diupload'))
   except Exception as err:
       return str(err)
   return redirect(url_for('diupload'))

@app.route('/delete_sign/<id>')
@login_required
@check_confirmed
def delete_sign(id):
    data = SignTable.query.filter_by(id=id).first_or_404()
    try:
       db.session.delete(data)
       db.session.commit()
       flash('Data berhasil di hapus','success')
       return redirect(url_for('sign_file'))
    except Exception as err:
        return str(err)
    return redirect(url_for('sign_file'))


@app.route('/view/<id>')
@login_required
@cross_origin()
def view_doc(id):
   data = fileModel.query.filter_by(id=id).first_or_404()
   pdf =BytesIO(data.file)
   name = data.filename
#    encoded_data = base64.b64encode(pdf).encode('utf-8')
   return send_file(pdf,cache_timeout=0, attachment_filename='kk.pdf',as_attachment=False)

@app.route('/view_doc_skripsi/<name>')
@login_required
@cross_origin()
def view_doc_skripsi(name):
   data = Skripsi.query.filter_by(filename=name).first_or_404()
   pdf =BytesIO(data.file)
   name = data.filename
#    encoded_data = base64.b64encode(pdf).encode('utf-8')
   return send_file(pdf,cache_timeout=0, attachment_filename='kk.pdf',as_attachment=False)

@app.route('/view_bytes/<id>')
@login_required
@permission_required(Permission.SIGN)
def view_bytes(id):
    if current_user.role_id == 2:
        data = fileModel.query.filter_by(id=id).first_or_404()
        pdf =bytes(data.file)
        encoded_data = base64.b64encode(pdf).decode('utf-8')
        return render_template('/signature/index.html', data = encoded_data, file = data)
    else:
        data = SignTable.query.filter_by(id=id).first_or_404()
        pdf =bytes(data.file)
        encoded_data = base64.b64encode(pdf).decode('utf-8')
        return render_template('/signature/index.html', data = encoded_data, file = data.sign)

#    return encoded_data
    return render_template('/signature/index.html', data = encoded_data, file = data)

@app.route('/sign_skripsi/<name>')
@login_required
@permission_required(Permission.SIGN)
def sign_skripsi(name):
    # if current_user.role_id == 2:
    data = Skripsi.query.filter_by(filename=name).first_or_404()
    pdf =bytes(data.file)
    encoded_data = base64.b64encode(pdf).decode('utf-8')
    return render_template('/signature/index.html', data = encoded_data, file = data)
    # else:
    #     data = SignTable.query.filter_by(id=id).first_or_404()
    #     pdf =bytes(data.file)
    #     encoded_data = base64.b64encode(pdf).decode('utf-8')
    #     return render_template('/signature/index.html', data = encoded_data, file = data.sign)

#    return encoded_data
    # return render_template('/signature/index.html', data = encoded_data, file = data)

@app.route('/view_bytes_sign/<id>')
@login_required
@permission_required(Permission.SIGN)
def view_bytes_sign(id):
   data = SignTable.query.filter_by(id=id).first_or_404()
   pdf =bytes(data.file)
   encoded_data = base64.b64encode(pdf).decode('utf-8')
#    return encoded_data
   return render_template('/signature/index.html', data = encoded_data, file = data)

@app.route('/view_sign/<id>')
@login_required
@cross_origin()
def view_doc_sign(id):
   data = SignTable.query.filter_by(id=id).first_or_404()
   pdf =BytesIO(data.file)
   return send_file(pdf,cache_timeout=0, attachment_filename='kk.pdf',as_attachment=False)

@app.route('/detail/<id>')
@login_required
def detail_file(id):
    data = fileModel.query.filter_by(id=id).first_or_404()
    return render_template('/document/detail.html', data = data)

@app.route('/detail_file_skripsi/<name>')
@login_required
@check_confirmed
def detail_skripsi(name):
    data = Skripsi.query.filter_by(filename=name).first_or_404()
    if current_user.can(8):
        if current_user.signature is None:
            flash('Untuk melakukan tanda tangan. Pastikan anda sudah membuat tanda tangan pada menu Settings > Tanda tangan', 'danger')
        if current_user.sertifikat is None:
            flash('Untuk melakukan tanda tangan. Pastikan anda sudah membuat sertifikat pada menu Settings > Sertifikat', 'danger')
    return render_template('/document/skripsi.html', data = data)

@app.route('/detail_sign/<id>')
@login_required
def detail_sign_file(id):
    data = SignTable.query.filter_by(id=id).first_or_404()
    return render_template('/document/detail_sign.html', data = data)

@app.route('/detail_skripsi_sign/<name>')
@login_required
@check_confirmed
def detail_skripsi_sign(name):
    data = Skripsi.query.filter_by(filename=name).first_or_404()
    return render_template('/document/skripsi_sign.html', data = data)

def allowed_file_pdf(filename):
    return '.' in filename and \
        filename.rsplit('.', 1)[1].lower() in Config.ALLOWED_EXTENSIONS[0]

###################################UPLOAD##############################################

@app.route('/upload', methods=['POST', 'GET'])
@login_required
@check_confirmed
def upload_file():
    if request.method == 'POST':
        file = request.files['file']
        file_name = request.form['filename']
        page = request.form['page']
        dosen1 = request.form['dosen1']
        dosen2 = request.form['dosen2']
        dosen3 = request.form['dosen3']

        if file.filename != '' and allowed_file_pdf(file.filename):
            try:
                #fields
                output_file = file_name +' ' + current_user.name+'.pdf'
                path1 = os.path.join(app.config['UPLOAD_FILE'],output_file)
                file.save(path1)
            except Exception as e:
                flash(str(e), 'warning')
                return redirect(url_for('upload_file'))
                #Open File
            with open(path1, 'rb') as doc:
                try:
                    up = fileModel( filename = file_name, file = doc.read(), user_id = current_user.id,  dosen1 = dosen1, dosen2= dosen2, dosen3 = dosen3, page=page)
                    db.session.add(up)
                    db.session.commit()
                    flash('File Berhasil Diupload','success')
                    return redirect(url_for('diupload'))
                except Exception as e:
                    flash(str(e), 'warning')
                    return redirect(url_for('upload_file'))
            
    return render_template('/upload/index.html')

@app.route('/upload_skripsi', methods=['POST','GET'])
@login_required
@check_confirmed
def upload_skripsi():
    dosen = User.query.filter_by(role_id=2)
    prodi = User.query.filter_by(role_id=3)
    dekan = User.query.filter_by(role_id=4)
    if request.method == "POST":
        f_name = request.form['filename']
        files = request.files['fileskripsi']
        page = request.form['page']
        pem1 = request.form['pembimbing1']
        pem2 = request.form['pembimbing2']
        peng1 = request.form['penguji1']
        peng2 = request.form['penguji2']
        prodi = request.form['prodi']
        dekan = request.form['dekan']
        # check = Skripsi.query.filter_by(filename = f_name).first_or_404()
        # if check.filename != f_name:
        if files.filename != '' and allowed_file_pdf(files.filename):
            try:
                #file
                input_file = str(current_user.id)+current_user.name+f_name+files.filename
                path_file = os.path.join(app.config['TEMP_FILE'],input_file)
                files.save(path_file)
            except Exception as e:
                flash(str(e), 'warning')
                return redirect(url_for('upload_skripsi'))
            try:
                up = temp( user_id = current_user.id, filename = f_name, path = input_file, page = page, pem1 = pem1, pem2 = pem2,
                                peng1 = peng1, peng2 = peng2, prodi = prodi, dekan = dekan)
                db.session.add(up)
                db.session.commit()
                flash('Berhasil menambah info dokumen','success')
                return redirect(url_for('upload_skripsi_n2', name = input_file))
            except Exception as e:
                flash('File dengan nama {} sudah ada pada database, harap gunakan nama lain'.format(f_name), 'danger')
                return redirect(url_for('upload_skripsi'))
        # else:
        #     flash('File dengan nama {} sudah ada pada database, harap gunakan nama lain'.format(f_name), 'danger')
        #     return redirect(url_for('upload_skripsi'))

    return render_template('/upload/upload_skripsi_step_1.html', data = dosen, data1= prodi, dekan = dekan)

################ 1 
@app.route('/upload_skripsi_next_2/<name>', methods=['POST','GET'])
@login_required
@check_confirmed
def upload_skripsi_n2(name):
    data = temp.query.filter_by(path = name ).first_or_404()
    return render_template('/upload/upload_skripsi_step_2.html', data = data)

@app.route('/add_field1/<id>')
@check_confirmed
def add_field1(id):
    data = temp.query.filter_by(id = id ).first_or_404()
    path = os.path.join(app.config['TEMP_FILE'],data.path)
    with open(path, 'rb')as doc:
        encoded_data = base64.b64encode(doc.read()).decode('utf-8')
    return render_template('/signature/add_field1.html', data = encoded_data, file = data)

@app.route('/field1/<id>', methods=['POST', 'GET'])
@check_confirmed
def field1(id):
    data = temp.query.filter_by(id = id ).first_or_404()
    if request.method == 'POST':
        x = request.form['x-post']
        y = request.form['y-post']
        x = int((int(float(x)) / 96)*72)
        y = int((int(float(y)) / 96)*72)
        path = os.path.join(app.config['TEMP_FILE'],data.path)
        output = 'field1'+data.path
        path2 = os.path.join(app.config['TEMP_FILE'],output)
        page = data.page -1
        try:
            create_field1(input_file= path,output_file = path2, x= x,y= y,page= page)
            return redirect(url_for('upload_skripsi_n3', name = data.path))
        except Exception as e:
            print(e)
            flash(str(e), 'warning')
            return redirect(url_for('add_field1', id = data.id))

    return render_template('/upload/upload_skripsi_step_2.html', data = data)
    # return redirect(url_for('add_field1', id = data.id))


################ 2
@app.route('/upload_skripsi_next_3/<name>', methods=['POST','GET'])
@login_required
@check_confirmed
def upload_skripsi_n3(name):
    data = temp.query.filter_by(path = name ).first_or_404()
    return render_template('/upload/upload_skripsi_step_3.html', data = data)

@app.route('/add_field2/<id>')
@check_confirmed
def add_field2(id):
    data = temp.query.filter_by(id = id ).first_or_404()
    fname = 'field1'+data.path
    path = os.path.join(app.config['TEMP_FILE'],fname)
    with open(path, 'rb')as doc:
        encoded_data = base64.b64encode(doc.read()).decode('utf-8')
    return render_template('/signature/add_field2.html', data = encoded_data, file = data)

@app.route('/field2/<id>', methods=['POST', 'GET'])
@check_confirmed
def field2(id):
    if request.method == 'POST':
        x = request.form['x-post']
        y = request.form['y-post']
        x = int((int(float(x)) / 96)*72)
        y = int((int(float(y)) / 96)*72)
        data = temp.query.filter_by(id = id ).first_or_404()
        input_f = 'field1'+data.path 
        path = os.path.join(app.config['TEMP_FILE'],input_f)
        output = 'field2'+data.path
        path2 = os.path.join(app.config['TEMP_FILE'],output)
        page = data.page -1
        try:
            create_field2(input_file= path,output_file = path2, x= x,y= y,page= page)
            flash('Berhasil menambah lokasi tanda tangan','success')
            return redirect(url_for('upload_skripsi_n4', name = data.path))
        except Exception as e:
            print(e)
            flash(str(e), 'warning')
            return redirect(url_for('add_field2', id = data.id))
    return render_template('/signature/add_field2.html')

############ 3

@app.route('/upload_skripsi_next_4/<name>', methods=['POST','GET'])
@login_required
@check_confirmed
def upload_skripsi_n4(name):
    data = temp.query.filter_by(path = name ).first_or_404()
    return render_template('/upload/upload_skripsi_step_4.html', data = data)

@app.route('/add_field3/<id>')
@check_confirmed
def add_field3(id):
    data = temp.query.filter_by(id = id ).first_or_404()
    fname = 'field2'+data.path
    path = os.path.join(app.config['TEMP_FILE'],fname)
    with open(path, 'rb')as doc:
        encoded_data = base64.b64encode(doc.read()).decode('utf-8')
    return render_template('/signature/add_field3.html', data = encoded_data, file = data)

@app.route('/field3/<id>', methods=['POST', 'GET'])
@check_confirmed
def field3(id):
    if request.method == 'POST':
        x = request.form['x-post']
        y = request.form['y-post']
        x = int((int(float(x)) / 96)*72)
        y = int((int(float(y)) / 96)*72)
        data = temp.query.filter_by(id = id ).first_or_404()
        input_f = 'field2'+data.path 
        path = os.path.join(app.config['TEMP_FILE'],input_f)
        output = 'field3'+data.path
        path2 = os.path.join(app.config['TEMP_FILE'],output)
        page = data.page -1
        try:
            create_field3(input_file= path,output_file = path2, x= x,y= y,page= page)
            flash('Berhasil menambah lokasi tanda tangan','success')
            return redirect(url_for('upload_skripsi_n5', name = data.path))
        except Exception as e:
            print(e)
            flash(str(e), 'warning')
            return redirect(url_for('add_field3', id = data.id))
    return render_template('/signature/add_field3.html')

############ 4

@app.route('/upload_skripsi_next_5/<name>', methods=['POST','GET'])
@login_required
@check_confirmed
def upload_skripsi_n5(name):
    data = temp.query.filter_by(path = name ).first_or_404()
    return render_template('/upload/upload_skripsi_step_5.html', data = data)

@app.route('/add_field4/<id>')
@check_confirmed
def add_field4(id):
    data = temp.query.filter_by(id = id ).first_or_404()
    fname = 'field3'+data.path
    path = os.path.join(app.config['TEMP_FILE'],fname)
    with open(path, 'rb')as doc:
        encoded_data = base64.b64encode(doc.read()).decode('utf-8')
    return render_template('/signature/add_field4.html', data = encoded_data, file = data)

@app.route('/field4/<id>', methods=['POST', 'GET'])
@check_confirmed
def field4(id):
    if request.method == 'POST':
        x = request.form['x-post']
        y = request.form['y-post']
        x = int((int(float(x)) / 96)*72)
        y = int((int(float(y)) / 96)*72)
        data = temp.query.filter_by(id = id ).first_or_404()
        input_f = 'field3'+data.path 
        path = os.path.join(app.config['TEMP_FILE'],input_f)
        output = 'field4'+data.path
        path2 = os.path.join(app.config['TEMP_FILE'],output)
        page = data.page -1
        try:
            create_field4(input_file= path,output_file = path2, x= x,y= y,page= page)
            flash('Berhasil menambah lokasi tanda tangan','success')
            return redirect(url_for('upload_skripsi_n6', name = data.path))
        except Exception as e:
            print(e)
            flash(str(e), 'warning')
            return redirect(url_for('add_field4', id = data.id))
    return render_template('/signature/add_field4.html')

############ 5

@app.route('/upload_skripsi_next_6/<name>', methods=['POST','GET'])
@check_confirmed
@login_required
def upload_skripsi_n6(name):
    data = temp.query.filter_by(path = name ).first_or_404()
    return render_template('/upload/upload_skripsi_step_6.html', data = data)

@app.route('/add_field5/<id>')
@check_confirmed
def add_field5(id):
    data = temp.query.filter_by(id = id ).first_or_404()
    fname = 'field4'+data.path
    path = os.path.join(app.config['TEMP_FILE'],fname)
    with open(path, 'rb')as doc:
        encoded_data = base64.b64encode(doc.read()).decode('utf-8')
    return render_template('/signature/add_field5.html', data = encoded_data, file = data)

@app.route('/field5/<id>', methods=['POST', 'GET'])
@check_confirmed
def field5(id):
    if request.method == 'POST':
        x = request.form['x-post']
        y = request.form['y-post']
        x = int((int(float(x)) / 96)*72)
        y = int((int(float(y)) / 96)*72)
        data = temp.query.filter_by(id = id ).first_or_404()
        input_f = 'field4'+data.path 
        path = os.path.join(app.config['TEMP_FILE'],input_f)
        output = 'field5'+data.path
        path2 = os.path.join(app.config['TEMP_FILE'],output)
        page = data.page -1
        try:
            create_field5(input_file= path,output_file = path2, x= x,y= y,page= page)
            flash('Berhasil menambah lokasi tanda tangan','success')
            return redirect(url_for('upload_skripsi_n7', name = data.path))
        except Exception as e:
            print(e)
            flash(str(e), 'warning')
            return redirect(url_for('add_field5', id = data.id))
    return render_template('/signature/add_field5.html')

############ 6

@app.route('/upload_skripsi_next_7/<name>', methods=['POST','GET'])
@check_confirmed
@login_required
def upload_skripsi_n7(name):
    data = temp.query.filter_by(path = name ).first_or_404()
    return render_template('/upload/upload_skripsi_step_7.html', data = data)

@app.route('/add_field6/<id>')
@check_confirmed
def add_field6(id):
    data = temp.query.filter_by(id = id ).first_or_404()
    fname = 'field5'+data.path
    path = os.path.join(app.config['TEMP_FILE'],fname)
    with open(path, 'rb')as doc:
        encoded_data = base64.b64encode(doc.read()).decode('utf-8')
    return render_template('/signature/add_field6.html', data = encoded_data, file = data)

@app.route('/field6/<id>', methods=['POST', 'GET'])
@check_confirmed
def field6(id):
    if request.method == 'POST':
        x = request.form['x-post']
        y = request.form['y-post']
        x = int((int(float(x)) / 96)*72)
        y = int((int(float(y)) / 96)*72)
        data = temp.query.filter_by(id = id ).first_or_404()
        input_f = 'field5'+data.path 
        path = os.path.join(app.config['TEMP_FILE'],input_f)
        output = data.path
        path2 = os.path.join(app.config['UPLOAD_FILE'],output)
        page = data.page -1
        del1 = os.path.join(app.config['TEMP_FILE'],'field1'+output)
        del2 = os.path.join(app.config['TEMP_FILE'],'field2'+output)
        del3 = os.path.join(app.config['TEMP_FILE'],'field3'+output)
        del4 = os.path.join(app.config['TEMP_FILE'],'field4'+output)
        del5 = os.path.join(app.config['TEMP_FILE'],'field5'+output)
        del6 = os.path.join(app.config['TEMP_FILE'],output)
        
        try:
            create_field6(input_file= path,output_file = path2, x= x,y= y,page= page)
        except Exception as e:
            print(e)
            flash(str(e), 'warning')
            return redirect(url_for('add_field6', id = data.id))
        with open(path2, 'rb') as doc:
            file_data = doc.read()
            try:
                f = Skripsi(user_id = data.user_id, filename = data.filename, file = file_data, 
                            path = data.path, date_upload = data.date_upload, page = data.page,
                            pem1 = data.pem1, pem2 = data.pem2, peng1 = data.peng1, peng2 = data.peng2,
                            prodi = data.prodi, dekan = data.dekan )
                db.session.add(f)
                db.session.commit()
                if del1 and del2 and del3 and del4 and del5 and del6:
                    os.remove(del1)
                    os.remove(del2)
                    os.remove(del3)
                    os.remove(del4)
                    os.remove(del5)
                    os.remove(del6)
                    print('delete success')
                else:
                    print("The file does not exist")
                flash('File berhasil di upload', 'success')
                return redirect(url_for('skripsi_diupload'))
            except Exception as err:
                    flash(str(err), 'danger')
                    return redirect(url_for('upload_skripsi_n7', name = data.path))

    return render_template('/signature/add_field7.html')

# SIGN PENGUJI 1
@app.route('/sign_penguji_1/<id>', methods = ['POST','GET'])
@login_required
@check_confirmed
@permission_required(Permission.SIGN)
def sign_penguji_1(id):
    if request.method == "POST":
        password = request.form['password']
        data = Skripsi.query.filter_by(id = id).first_or_404()
        inputFile =  data.path
        path1 = os.path.join(app.config['UPLOAD_FILE'],inputFile)
        back_g = current_user.signature
        key = current_user.key_sertifikat
        path_key= os.path.join(app.config['CERTIFICATE'],key)
        cert = current_user.sertifikat
        path_cert = os.path.join(app.config['CERTIFICATE'],cert)
        link = 'https://sign-stamp-pdf.herokuapp.com/sign/detail/'+data.filename+'/'+current_user.name+'/'+data.skrip.name+'/'+datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S %a')
        if password == current_user.password_sertifikat:
            if current_user.name == data.peng1:
                try:
                    create_sign(path1, back_g, path_cert, path_key, password, link,
                                'Signature1', 'Approval Skripsi', current_user.name
                                )
                    data.peng1_sign = True
                    data.peng1_date = datetime.utcnow()
                    data.progres = data.progres + 17
                    db.session.commit()
                except Exception as err:
                    print(err)
                    flash(str(err), 'warning')
                    return redirect(url_for('p_penguji_1'))
            elif current_user.name == data.peng2:
                try:
                    create_sign(path1, back_g, path_cert, path_key, password, link,
                                'Signature2', 'Approval Skripsi', current_user.name
                    )
                    data.peng2_sign = True
                    data.peng1_sign = False
                    data.peng2_date = datetime.utcnow()
                    data.progres = data.progres + 17
                    db.session.commit()
                except Exception as err:
                    print(err)
                    flash(str(err), 'warning')
                    return redirect(url_for('p_penguji_2'))
            elif current_user.name == data.pem1:
                try:
                    create_sign(path1, back_g, path_cert, path_key, password, link,
                                'Signature3', 'Approval Skripsi', current_user.name
                    )
                    data.pem1_sign = True
                    data.peng2_sign = False
                    data.pem1_date = datetime.utcnow()
                    data.progres = data.progres + 17
                    db.session.commit()
                except Exception as err:
                    print(err)
                    flash(str(err), 'warning')
                    return redirect(url_for('p_pembimbing_1'))
            elif current_user.name == data.pem2:
                try:
                    create_sign(path1, back_g, path_cert, path_key, password, link,
                                'Signature4', 'Approval Skripsi', current_user.name
                    )
                    data.pem2_sign = True
                    data.pem1_sign = False
                    data.pem2_date = datetime.utcnow()
                    data.progres = data.progres + 17
                    db.session.commit()
                except Exception as err:
                    print(err)
                    flash(str(err), 'warning')
                    return redirect(url_for('p_pembimbing_1'))
            elif current_user.name == data.prodi:
                try:
                    create_sign(path1, back_g, path_cert, path_key, password, link ,
                                'Signature5', 'Approval Skripsi', current_user.name
                    )
                    data.prodi_sign = True
                    data.pem2_sign = False
                    data.prodi_date = datetime.utcnow()
                    data.progres = data.progres + 17
                    db.session.commit()
                except Exception as err:
                    print(err)
                    flash(str(err), 'warning')
                    return redirect(url_for('p_prodi'))
            else:
                try:
                    create_sign(path1, back_g, path_cert, path_key, password, link ,
                                'Signature6', 'Approval Skripsi', current_user.name
                    )
                    data.dekan_sign = True
                    data.prodi_sign = False
                    data.dekan_date = datetime.utcnow()
                    data.progres = data.progres + 15
                    data.done = True
                    db.session.commit()
                except Exception as err:
                    print(err)
                    flash(str(err), 'warning')
                    return redirect(url_for('p_dekan'))
            with open(path1, 'rb') as doc:
                file_data = doc.read()
                try:
                    data.file = file_data
                    db.session.commit()
                    flash('File Berhasil Di tanda tangan','success')
                    return redirect(url_for('skripsi_complete'))
                except Exception as err:
                    flash(str(err), 'danger')
                    return redirect(url_for('skripsi_complete'))
        else:
            flash('Password Salah','warning')
            return redirect(url_for('detail_skripsi', name = data.filename))
    return redirect(url_for('detail_skripsi', name = data.filename))

    



@app.route('/diupload')
@login_required
@check_confirmed
def diupload():
    data = fileModel.query.filter_by(user_id = current_user.id)
    return render_template('/diupload/index.html', a = data )

@app.route('/skripsi_diupload')
@login_required
@check_confirmed
def skripsi_diupload():
    data = Skripsi.query.filter_by(user_id = current_user.id)
    return render_template('/diupload/skripsi.html', a = data )

@app.route('/download_template')
@login_required
@check_confirmed
def download_template():
   res = send_file(os.path.join(app.config['TEMPLATE_FOLDER'],'template.docx'), as_attachment= True)
   return res

@app.route('/template')
@check_confirmed
def template():
    return render_template('/settings/template.html')

@app.route('/upload_template', methods = ['POST', 'GET'])
@check_confirmed
def upload_template():
    if request.method == "POST":
        file = request.files['file']
        if file.filename != '':
            try:
                file.save(os.path.join(app.config['TEMPLATE_FOLDER'],file.filename))
                flash('template berhasil di upload', 'success')
                return redirect(url_for('template'))
            except Exception as err:
                flash(str(err), 'warning')
                return redirect(url_for('template'))
    return redirect(url_for('template'))


#################  VALIDASI  ############################
@app.route('/validity')
@check_confirmed
@login_required
def valid_main():
    return render_template('/validity/validity.html')

@app.route('/validity', methods = ['POST'])
@check_confirmed
@login_required
def valid():
    cert_name = 'upb-root-new.crt'
    key_name = 'upb-key-new.pem'
    cert = os.path.join(app.config['CERTIFICATE'],cert_name)
    key = os.path.join(app.config['CERTIFICATE'],key_name)
    cert = open(cert, 'r')
    file = request.files['file']
    # with open(cert, 'r') as f2:
    if file.filename != '':
        data = cert.read()
        data = bytes(data, encoding='utf-8')
        root_cert = keys.parse_certificate(data)
        vc = ValidationContext(trust_roots=[root_cert])

        r = PdfFileReader(file)
        try:
            l = []
            sig = r.embedded_signatures
            for i, item in enumerate(sig):
                status = validate_pdf_signature(item, vc)
                hasil  = pretty(status)
                l.append(hasil)
                a = status.signing_cert.subject.human_friendly
                # x = type(l)
                # return x
            return render_template('/validity/result.html', data =l, name = file.filename )
        except Exception as e:
            flash('dokumen tidak memiliki tanda tangan atau dokumen telah dimodifikasi', 'danger')
            return redirect(url_for('dashboard'))  
        return render_template('/validity/result.html', data = hasil, a = a)

@app.route('/validity_form', methods = ['POST'])
def validity_form():
    cert_name = 'upb-root-new.crt'
    key_name = 'upb-key-new.pem'
    cert = os.path.join(app.config['CERTIFICATE'],cert_name)
    key = os.path.join(app.config['CERTIFICATE'],key_name)
    cert = open(cert, 'r')
    file = request.files['file']
    # with open(cert, 'r') as f2:
    if file.filename != '':
        data = cert.read()
        data = bytes(data, encoding='utf-8')
        root_cert = keys.parse_certificate(data)
        vc = ValidationContext(trust_roots=[root_cert])

        r = PdfFileReader(file)
        try:
            l = []
            sig = r.embedded_signatures
            for i, item in enumerate(sig):
                status = validate_pdf_signature(item, vc)
                hasil  = pretty(status)
                l.append(hasil)
                a = status.signing_cert.subject.human_friendly
                # x = type(l)
                # return x
            return render_template('/validity/result_landing.html', data =l, name = file.filename )
        except Exception as e:
            flash('dokumen tidak memiliki tanda tangan atau dokumen telah dimodifikasi', 'danger')
            return render_template('/validity/result_landing.html', data =l, name = file.filename )
        return render_template('/validity/result_landing.html', data = hasil, a = a)


#################  DOSEN AREA  ############################
@app.route('/_namadosen', methods=['GET'])
def namaDosen():
    res =User.query.filter_by(role_id = 2)
    list_dosen = [r.as_dict() for r in res]
    return jsonify(list_dosen)

@app.route('/_namaprodi', methods=['GET'])
def namaProdi():
    res =User.query.filter_by(role_id = 3)
    list_dosen = [r.as_dict() for r in res]
    return jsonify(list_dosen)


@app.route('/sign/detail/<namafile>/<namadosen>/<nama>/<date>', methods=['GET', 'POST'])
def detail_dosen(namafile, namadosen,nama, date):
    return render_template('/validity/result_new.html', namafile= namafile, namadosen = namadosen,nama= nama, date = date)

@app.route('/permintaan', methods=['GET','POST'])
@login_required
@check_confirmed
@permission_required(Permission.SIGN)
def permintaan():
    a = SignTable.sign3
    data_1 = fileModel.query.filter((fileModel.dosen1_sign == False),(fileModel.dosen1== current_user.name))
    data_2 = fileModel.query.filter((fileModel.dosen2_sign == False),(fileModel.dosen2== current_user.name))
    data3 = db.session.query(SignTable,fileModel ).join(SignTable). \
            filter((fileModel.dosen3_sign == False),(fileModel.dosen3 == current_user.name))
    return render_template('/permintaan/index.html', data = data_1, data1= data_2, data3 = data3)

########### permintaan
@app.route('/permintaan_penguji_1', methods=['GET','POST'])
@login_required
@check_confirmed
@permission_required(Permission.SIGN)
def p_penguji_1():
    data = Skripsi.query.filter(and_(Skripsi.peng1 == current_user.name, Skripsi.peng1_date== None))
    return render_template('/permintaan/penguji1.html', data = data)

@app.route('/permintaan_penguji_2', methods=['GET','POST'])
@login_required
@check_confirmed
@permission_required(Permission.SIGN)
def p_penguji_2():
    data = Skripsi.query.filter(and_(Skripsi.peng2 == current_user.name,Skripsi.peng1_sign==True))
    return render_template('/permintaan/penguji2.html', data = data)

@app.route('/permintaan_pembimbing_1', methods=['GET','POST'])
@login_required
@check_confirmed
@permission_required(Permission.SIGN)
def p_pembimbing_1():
    data = Skripsi.query.filter((Skripsi.pem1 == current_user.name),(Skripsi.peng2_sign==True))
    return render_template('/permintaan/pembimbing1.html', data = data)

@app.route('/permintaan_pembimbing_2', methods=['GET','POST'])
@login_required
@check_confirmed
@permission_required(Permission.SIGN)
def p_pembimbing_2():
    data = Skripsi.query.filter((Skripsi.pem2 == current_user.name),(Skripsi.pem1_sign==True))
    return render_template('/permintaan/pembimbing2.html', data = data)

@app.route('/permintaan_prodi', methods=['GET','POST'])
@login_required
@check_confirmed
@permission_required(Permission.SIGN)
def p_prodi():
    data = Skripsi.query.filter((Skripsi.prodi == current_user.name),(Skripsi.pem2_sign==True))
    return render_template('/permintaan/prodi.html', data = data)

@app.route('/permintaan_dekan', methods=['GET','POST'])
@login_required
@check_confirmed
@permission_required(Permission.SIGN)
def p_dekan():
    data = Skripsi.query.filter((Skripsi.dekan == current_user.name),(Skripsi.prodi_sign== True))
    return render_template('/permintaan/dekan.html', data = data)

@app.route('/stamp1/<id>', methods=['GET','POST'])
@login_required
@check_confirmed
@permission_required(Permission.SIGN)
def stampOne(id):
    if request.method == "POST":
        x = request.form['x-post']
        y = request.form['y-post']
        password = request.form['password']
        x = int((int(float(x)) / 96)*72)
        y = int((int(float(y)) / 96)*72)
        file = fileModel.query.filter_by(id=id).first_or_404()
        inputFile =  file.filename+ ' '+file.doc.name+'.pdf'
        path1 = os.path.join(app.config['UPLOAD_FILE'],inputFile)
        output1 = file.filename+ ' '+file.doc.name+' stamp1.pdf'
        path2 = os.path.join(app.config['UPLOAD_FILE'],output1)
        jo = db.session.query(User,fileModel ).join(fileModel). \
                filter(fileModel.dosen1 == current_user.name)
        back_g = current_user.signature
        key = current_user.key_sertifikat
        path_key= os.path.join(app.config['CERTIFICATE'],key)
        cert = current_user.sertifikat
        path_cert = os.path.join(app.config['CERTIFICATE'],cert)
        if password == current_user.password_sertifikat:
            try:
                create_sign_new(input_file=path1, output_file=path2, bg=back_g, key_file=path_key, crt_file= path_cert, field=str(current_user.id), url='https://sign-stamp-pdf.herokuapp.com/sign/detail/'+file.filename+'/'+current_user.name+'/'+file.doc.name+'/'+datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S %a'), reason='Digital Signature',
                    name= current_user.name, password=password,page=int(file.page-1), x= x, y= y)
                
                # buat_qr( back_g, path1,path2, 'http://127.0.0.1:5000/sign/detail/'+file.filename+'/'+current_user.name+'/'+file.doc.name+'/'+datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S %a') ,current_user.name,0, x, y)
            except Exception as err:
                print(err)
                flash(str(err), 'warning')
                return redirect(url_for('permintaan'))
            with open(path2, 'rb') as doc:
                file_id_data = file.id
                file_data = doc.read()
                sign1_data = current_user.name 
                try:
                    data = SignTable(file_id = file_id_data, file=file_data, sign1 = sign1_data, sign1_date = datetime.utcnow())
                    db.session.add(data)
                    file.dosen1_sign = True
                    db.session.commit()
                    if path1:
                        os.remove(path1)
                        print('delete success')
                    else:
                        print("The file does not exist")
                    flash('File Berhasil Di tanda tangan','success')
                    return redirect(url_for('permintaan'))
                except Exception as err:
                    flash(str(err), 'danger')
                    return redirect(url_for('permintaan'))
        else:
            flash('Password Salah','warning')
            return redirect(url_for('permintaan'))
                ################################
    #     elif valid is not None:
    #         flash('bisa sign ke 2', 'info')
    #         return redirect(url_for('permintaan'))
    # except Exception as err:
    #     flash(str(err), 'danger')
    #     return redirect(url_for('permintaan'))
    return redirect(url_for('permintaan'))

@app.route('/sudah_ditandatangani', methods=['POST','GET'])
@login_required
@check_confirmed
def sign_file():
    try:
        name = fileModel.query.filter(fileModel.id == SignTable.file_id)
    except Exception as err:
        flash('Tidak ada data', 'warning')
        return render_template('/ditandatangani/index.html')
    try:
        data = SignTable.query.filter((SignTable.sign1 == current_user.name) | (SignTable.sign2 == current_user.name)| (SignTable.sign3 == current_user.name))
    except Exception as err:
        flash('Tidak ada data', 'warning')
        return render_template('/ditandatangani/index.html')
    return render_template('/ditandatangani/index.html', data = data, name = name)

@app.route('/sudah_ditandatangani_dosen', methods=['POST','GET'])
@login_required
@check_confirmed
def sign_file_all():
    try:
        file = fileModel.query.filter_by(user_id = current_user.id).first_or_404()
        data = SignTable.query.filter_by(file_id = file.id)
        jo = db.session.query(SignTable,fileModel ).join(fileModel). \
            filter(fileModel.user_id == current_user.id)
    except Exception as err:
        flash('Tidak ada data', 'warning')
        return render_template('/ditandatangani/index_mhs.html')
    return render_template('/ditandatangani/index_mhs.html', data = data, file = jo)

@app.route('/skripsi_complette', methods=['POST','GET'])
@login_required
@check_confirmed
def skripsi_complete():
    # try:
    data = Skripsi.query.filter(or_(Skripsi.peng1 == current_user.name, Skripsi.peng2==current_user.name, Skripsi.pem1==current_user.name, Skripsi.pem2 == current_user.name,
                                        Skripsi.dekan == current_user.name, Skripsi.prodi == current_user.name), (Skripsi.done == True))
    pro = Skripsi.query.filter_by(done = False)
    return render_template('/ditandatangani/skripsi.html', data = data, a = pro)


@app.route('/stamp2/<id>', methods=['GET','POST'])
@permission_required(Permission.SIGN)
@login_required
@check_confirmed
def stampTwo(id):
    if request.method == "POST":
        password = request.form['password']
        x = request.form['x-post']
        y = request.form['y-post']
        x = int((int(float(x)) / 96)*72)
        y = int((int(float(y)) / 96)*72)
        file = fileModel.query.filter_by(id=id).first_or_404()
        output1 = file.filename+ ' '+file.doc.name+' stamp1.pdf'
        path1 = os.path.join(app.config['UPLOAD_FILE'],output1)
        output2 = file.filename+ ' '+file.doc.name+' stamp2.pdf'
        path2 = os.path.join(app.config['UPLOAD_FILE'],output2)
        back_g = current_user.signature
        key = current_user.key_sertifikat
        path_key= os.path.join(app.config['CERTIFICATE'],key)
        cert = current_user.sertifikat
        path_cert = os.path.join(app.config['CERTIFICATE'],cert)
        if password == current_user.password_sertifikat:
            try:
                create_sign_new(input_file=path1, output_file=path2, bg=back_g, key_file=path_key, crt_file= path_cert, field=str(current_user.id), url='https://sign-stamp-pdf.herokuapp.com/sign/detail/'+file.filename+'/'+current_user.name+'/'+file.doc.name+'/'+datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S %a'), reason='Digital Signature',
                    name= current_user.name, password='rahasia',page=int(file.page-1), x = x, y= y)
                # buat_qr(back_g, path1,path2, 'http://127.0.0.1:5000/sign/detail/'+file.filename+'/'+current_user.name+'/'+file.doc.name+'/'+datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S %a')  ,current_user.name,0,x, y)# 330, 325)
            except Exception as err:
                flash(str('Penguji Pertama Belum Tanda Tangan'), 'danger')
                return redirect(url_for('permintaan'))
            with open(path2, 'rb') as doc:
                file_id_data = file.id
                file_data = doc.read()
                sign1_data = current_user.name 
                try:
                    data = SignTable.query.filter_by(file_id = file_id_data).first_or_404()
                    data.sign2 = current_user.name
                    data.sign2_date = datetime.utcnow()
                    data.file = file_data
                    file.dosen2_sign = True
                    db.session.commit()
                    if path1:
                        os.remove(path1)
                        print('delete success')
                    else:
                        print("The file does not exist")
                    flash('File Berhasil Di tanda tangan','success')
                    return redirect(url_for('permintaan'))
                except Exception as err:
                    flash(str(err), 'danger')
                    return redirect(url_for('permintaan'))
        else:
            flash('Password Salah','warning')
            return redirect(url_for('permintaan'))
    return redirect(url_for('permintaan'))

@app.route('/stamp3/<id>', methods=['GET','POST'])
@permission_required(Permission.SIGN)
@login_required
@check_confirmed
def stampThree(id):
    if request.method == "POST":
        password = request.form['password']
        x = request.form['x-post']
        y = request.form['y-post']
        x = int((int(float(x)) / 96)*72)
        y = int((int(float(y)) / 96)*72)
        file = SignTable.query.filter_by(id=id).first_or_404()
        final = file.sign.filename+ ' '+file.sign.doc.name+'.pdf'
        output2 = file.sign.filename+ ' '+file.sign.doc.name+' stamp2.pdf'
        output3 = file.sign.filename+ ' '+file.sign.doc.name+' stamp3.pdf'
        path1 = os.path.join(app.config['UPLOAD_FILE'],output2)
        path2 = os.path.join(app.config['UPLOAD_FILE'],output3)
        path3 = os.path.join(app.config['UPLOAD_FILE'],final)
        key = current_user.key_sertifikat
        path_key= os.path.join(app.config['CERTIFICATE'],key)
        cert = current_user.sertifikat
        path_cert = os.path.join(app.config['CERTIFICATE'],cert)
        back_g = current_user.signature
        if password == current_user.password_sertifikat:
            try:
                create_sign_new(input_file=path1, output_file=path2, bg=back_g, key_file=path_key, crt_file= path_cert, field=str(current_user.id), url='https://sign-stamp-pdf.herokuapp.com/sign/detail/'+file.sign.filename+'/'+current_user.name+'/'+file.sign.doc.name+'/'+datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S %a'), reason='Digital Signature',
                    name= current_user.name, password='rahasia',page=int(file.sign.page-1), x = x, y= y)
                # buat_qr(back_g, path1,path2, 'http://127.0.0.1:5000/sign/detail/'+file.sign.filename+'/'+current_user.name+'/'+file.sign.doc.name+'/'+datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S %a') ,current_user.name,0, x,y)#200, 140)
                # try:
                #     re = 'Pengesahan KKP oleh:\n{}\n{}\n{}'.format(ds1, ds2, ds3)
                #     create_sign(path2, path3, cert,key,cert,'Signature', re,current_user.name)
                # except Exception as err:
                #     flash(str(err), 'danger')
                #     return redirect(url_for('permintaan'))
            except Exception as err:
                flash(str('Penguji Kedua Belum Tanda Tangan'), 'danger')
                return redirect(url_for('permintaan'))
            with open(path2, 'rb') as doc:
                file_id_data = file.id
                file_data = doc.read()
                sign1_data = current_user.name 
                try:
                    file.sign.dosen3_sign = True
                    data = SignTable.query.filter_by(id = file_id_data).first_or_404()
                    data.sign3 = current_user.name
                    data.sign3_date = datetime.utcnow()
                    data.file = file_data
                    db.session.commit()
                    
                    if path2:
                        os.remove(path2)
                        print('delete success')
                    else:
                        print("The file does not exist")
                    if path1:
                        os.remove(path1)
                        print('delete success')
                    else:
                        print("The file does not exist")
                    flash('File Berhasil Di tanda tangan','success')
                    return redirect(url_for('permintaan'))
                except Exception as err:
                    flash(str(err), 'danger')
                    return redirect(url_for('permintaan'))
        else:
            flash('Password Salah','warning')
            return redirect(url_for('permintaan'))
    return redirect(url_for('permintaan'))

@app.route('/signature/<id>')
@login_required
@check_confirmed
@permission_required(Permission.SIGN)
def signature(id):
    data = User.query.filter_by(id=id).first_or_404()
    return render_template('/settings/signature.html', user = data )

@app.route('/uploadsign/<id>', methods=['POST','GET'])
@permission_required(Permission.SIGN)
@login_required
@check_confirmed
def upload_sign(id):
    if request.method =='POST':
        data = User.query.filter_by(id=id).first_or_404()
        sign = request.files['signature']
        try:
            fname = data.name+data.nomor+sign.filename
            data.signature = fname
            db.session.commit()
            a = os.path.join(app.config['SIGNATURE_FILE'],fname)
            sign.save(os.path.join(app.config['SIGNATURE_FILE'],fname))
            print (a)
            flash('Tanda tangan berhasil di Upload','success')
            return redirect(url_for('signature',id = current_user.id))
        except Exception as err:
            flash(str(err), 'warning')
            return redirect(url_for('signature', id = current_user.id))
    return redirect(url_for('signature', id = current_user.id))
        

############################ ADMIN ######################################
@app.route('/sertifikat/<id>', methods=['POST','GET'])
@login_required
@check_confirmed
@permission_required(Permission.SIGN)
def sertifikat(id):
    # TODO
    ser = User.query.filter_by(id=id).first_or_404()
    try:
        if ser.sertifikat is None:
            return render_template('/settings/sertifikat_null.html')
        else:
            cert = ser.sertifikat
            path_cert = os.path.join(app.config['CERTIFICATE'],cert)
            with open(path_cert, 'rb') as f:
                a = f.read()
                cert = x509.load_pem_x509_certificate(a)
            sertifikat =cert
            return render_template('/settings/sertifikat.html', cert= sertifikat)
    except Exception as e:
        return render_template('/settings/sertifikat_null.html')

@app.route('/create_sertifikat/<id>', methods=['POST','GET'])
@login_required
@check_confirmed
def create_sertifikat(id):
    if request.method == 'POST':
        password = request.form['password']
        active = request.form['active']
        ser = User.query.filter_by(id=id).first_or_404()
        certificare = str(ser.id)+ser.name+'.crt'
        key_certificate = str(ser.id)+ser.name+'key.pem'
        path_cert = os.path.join(app.config['CERTIFICATE'],certificare)
        path_key = os.path.join(app.config['CERTIFICATE'],key_certificate)
        create_cert(name=current_user.name,password=password, email=current_user.email, active=int(active), cert_name=path_cert, key_name=path_key)
        try:
            db.session.rollback()
            ser.sertifikat = certificare
            ser.key_sertifikat = key_certificate
            ser.password_sertifikat = password
            db.session.commit()
            flash('sukses buat sertifikat', 'success')
            return redirect(url_for('sertifikat', id= current_user.id))
        except Exception as e:
            flash(str(e),'danger')
            return redirect(url_for('sertifikat', id= current_user.id))
    return redirect(url_for('sertifikat', id= current_user.id))
############################ MAHASISWA ######################################
@app.route('/admin/data_mahasiswa')
@login_required
@check_confirmed
@permission_required(Permission.ADMIN)
def all_mhs():
    mhs = User.query.filter_by(role_id=1)
    return render_template('admin/data_mhs/index.html', data = mhs)

@app.route('/add/mhasiswa',methods=['POST','GET'])
@login_required
@check_confirmed
@permission_required(Permission.ADMIN)
def add_mhs():
    if request.method == 'POST':
        name = request.form['name']
        nomor = request.form['nomor']
        email = request.form['email']
        p_profile = name+nomor+email+'.jpg'
        photo = request.files['photo']
        if photo.filename == '':
            flash('No Photo Selected')
            return redirect(url_for('all_mhs'))
        # if photo:
        try:
            # path = 
            filename = name + nomor+email+'.jpg'
            photo.save(os.path.join(app.config['UPLOAD_FOLDER'],filename))
        except Exception as err:
            return str(err)
        up = User(name = name, nomor = nomor, email = email, p_profile= p_profile, password= nomor, role_id = 1)
        db.session.add(up)
        db.session.commit()
        flash('File Berhasil Diupload','success')
        return redirect(url_for('all_mhs'))

@app.route('/delete/mahasiswa/<id>')
@login_required
@check_confirmed
@permission_required(Permission.ADMIN)
def delete_mahasiswa(id):
   data = User.query.filter_by(id=id).first_or_404()
   try:
       db.session.delete(data)
       db.session.commit()
       try:
           file = data.p_profile
           path = os.path.join(app.config['UPLOAD_FOLDER'],file)
           os.remove(path)
       except Exception as err:
        #    flash('Data Tidak Ada', 'warning')
           return redirect(url_for('all_mhs'))

       flash('Data berhasil di hapus','success')
       return redirect(url_for('all_mhs'))
   except Exception as err:
       return str(err)
   return redirect(url_for('all_mhs'))

############################ DOSEN ######################################
@app.route('/admin/data_dosen')
@login_required
@check_confirmed
@permission_required(Permission.ADMIN)
def all_dosen():
    dosen = User.query.filter_by(role_id=2)
    return render_template('admin/data_dosen/index.html', data = dosen)

@app.route('/add/dosen',methods=['POST','GET'])
@login_required
@check_confirmed
@permission_required(Permission.ADMIN)
def add_dosen():
    if request.method == 'POST':
        name = request.form['name']
        nomor = request.form['nomor']
        email = request.form['email']
        p_profile = name+nomor+email+'.jpg'
        photo = request.files['photo']
        role_id = 2
        if photo.filename == '':
            flash('No Photo Selected', 'warning')
            return redirect(url_for('all_dosen'))
        # if photo:
        try:
            up = User(name = name, nomor = nomor, email = email, p_profile= p_profile, password= nomor, role_id = role_id)
            db.session.add(up)
            db.session.commit()
            ed = User.query.filter_by(nomor=nomor).first()
            ed.role_id = role_id
            db.session.commit()
        except Exception as err:
            flash(str(err),'warning')
            return redirect(url_for('all_dosen'))
        try:
            # path = 
            filename = name + nomor+email+'.jpg'
            photo.save(os.path.join(app.config['UPLOAD_FOLDER'],filename))
        except Exception as err:
            return str(err)
        flash('File Berhasil Diupload','success')
        return redirect(url_for('all_dosen'))

@app.route('/delete/dosen/<id>')
@login_required
@check_confirmed
@permission_required(Permission.ADMIN)
def delete_dosen(id):
   data = User.query.filter_by(id=id).first_or_404()
   try:
       db.session.delete(data)
       db.session.commit()
       try:
           file = data.p_profile
           path = os.path.join(app.config['UPLOAD_FOLDER'],file)
           os.remove(path)
       except Exception as err:
           flash('Data Tidak Ada', 'warning')
           return redirect(url_for('all_dosen'))

       flash('Data berhasil di hapus','success')
       return redirect(url_for('all_dosen'))
   except Exception as err:
       return str(err)
   return redirect(url_for('all_dosen'))

#######################PRODI ########################################
@app.route('/admin/data_prodi')
@login_required
@check_confirmed
@permission_required(Permission.ADMIN)
def all_prodi():
    prodi = User.query.filter_by(role_id=3)
    return render_template('admin/data_prodi/index.html', data = prodi)

@app.route('/add/prodi',methods=['POST','GET'])
@login_required
@check_confirmed
@permission_required(Permission.ADMIN)
def add_prodi():
    if request.method == 'POST':
        name = request.form['name']
        nomor = request.form['nomor']
        email = request.form['email']
        p_profile = name+nomor+email+'.jpg'
        photo = request.files['photo']
        role_id = 3
        if photo.filename == '':
            flash('No Photo Selected', 'warning')
            return redirect(url_for('all_prodi'))
        # if photo:
        try:
            up = User(name = name, nomor = nomor, email = email, p_profile= p_profile, password= nomor, role_id = role_id)
            db.session.add(up)
            db.session.commit()
            ed = User.query.filter_by(nomor=nomor).first()
            ed.role_id = role_id
            db.session.commit()
        except Exception as err:
            flash(str(err),'warning')
            return redirect(url_for('all_prodi'))
        try:
            # path = 
            filename = name + nomor+email+'.jpg'
            photo.save(os.path.join(app.config['UPLOAD_FOLDER'],filename))
        except Exception as err:
            return str(err)
        flash('File Berhasil Diupload','success')
        return redirect(url_for('all_prodi'))

####################### PRODI ########################################
####################### DEKAN ########################################
@app.route('/admin/data_dekan')
@login_required
@check_confirmed
@permission_required(Permission.ADMIN)
def all_dekan():
    prodi = User.query.filter_by(role_id=4)
    return render_template('admin/data_dekan/index.html', data = prodi)

@app.route('/add/dekan',methods=['POST','GET'])
@login_required
@check_confirmed
@permission_required(Permission.ADMIN)
def add_dekan():
    if request.method == 'POST':
        name = request.form['name']
        nomor = request.form['nomor']
        email = request.form['email']
        p_profile = name+nomor+email+'.jpg'
        photo = request.files['photo']
        role_id = 4
        if photo.filename == '':
            flash('No Photo Selected', 'warning')
            return redirect(url_for('all_dekan'))
        # if photo:
        try:
            up = User(name = name, nomor = nomor, email = email, p_profile= p_profile, password= nomor, role_id = role_id)
            db.session.add(up)
            db.session.commit()
            ed = User.query.filter_by(nomor=nomor).first()
            ed.role_id = role_id
            db.session.commit()
        except Exception as err:
            flash(str(err),'warning')
            return redirect(url_for('all_dekan'))
        try:
            # path = 
            filename = name + nomor+email+'.jpg'
            photo.save(os.path.join(app.config['UPLOAD_FOLDER'],filename))
        except Exception as err:
            return str(err)
        flash('File Berhasil Diupload','success')
        return redirect(url_for('all_dekan'))

@app.route('/profile/<id>')
@login_required
@check_confirmed
def profile(id):
    data = User.query.filter_by(id=id).first_or_404()
    return render_template('/settings/profile.html', user = data)


##################### USER #########################################
@app.route('/changepassword/<id>', methods = ['POST','GET'])
@login_required
@check_confirmed
def change_pw(id):
    if request.method == 'POST':
        user = User.query.filter_by(id=id).first_or_404()
        pw = request.form['password']
        try:   
            user.password = pw
            db.session.commit()
            flash('password berhasil diubah', 'success')
            return redirect(url_for('profile', id = id))
        except Exception as err:
            flash(str(err), 'warning')
            return redirect(url_for('profile',id = id))
    return redirect(url_for('profile',id = id))

@app.route('/changephoto/<id>', methods = ['POST','GET'])
@login_required
@check_confirmed
def change_pp(id):
    if request.method == 'POST':
        user = User.query.filter_by(id=id).first_or_404()
        file = request.files['p_profile']
        try:   
            filename = user.p_profile
            file.save(os.path.join(app.config['UPLOAD_FOLDER'],filename))
            flash('Foto berhasil diubah', 'success')
            return redirect(url_for('profile', id = id))
        except Exception as err:
            flash(str(err), 'warning')
            return redirect(url_for('profile',id = id))
    return redirect(url_for('profile',id = id))


@app.route('/notif')
def notif():
    data_1_perm = fileModel.query.filter((fileModel.dosen1_sign == False),(fileModel.dosen1== current_user.name)).count()
    data_2_perm = fileModel.query.filter((fileModel.dosen2_sign == False),(fileModel.dosen2== current_user.name)).count()
    data_3_perm = fileModel.query.filter((fileModel.dosen3_sign == False),(fileModel.dosen3== current_user.name)).count()

    data3 = SignTable.query.filter_by(sign3= None).count()
    data = data_2_perm + data_1_perm
    return jsonify({'total':data, 'prodi': data_3_perm})

@app.route('/new_notif')
def new_notif():
    peng1 = Skripsi.query.filter(and_(Skripsi.peng1 == current_user.name, Skripsi.peng1_date== None)).count()
    peng2 = Skripsi.query.filter(and_(Skripsi.peng2 == current_user.name,Skripsi.peng1_sign==True)).count()
    pem1 = Skripsi.query.filter((Skripsi.pem1 == current_user.name),(Skripsi.peng2_sign==True)).count()
    pem2 = Skripsi.query.filter((Skripsi.pem2 == current_user.name),(Skripsi.pem1_sign==True)).count()
    prodi = Skripsi.query.filter((Skripsi.prodi == current_user.name),(Skripsi.pem2_sign==True)).count()
    dekan = Skripsi.query.filter((Skripsi.dekan == current_user.name),(Skripsi.prodi_sign== True)).count()
    return jsonify({'peng1':peng1,
                    'peng2': peng2,
                    'pem1':pem1,
                    'pem2':pem2,
                    'prodi':prodi,
                    'dekan':dekan})

@app.route('/verify_stamp/')
def verify():
    jo = db.session.query(fileModel, User ).join(User). \
            filter(fileModel.dosen1 == current_user.name)
    data = jo
    return str(data)