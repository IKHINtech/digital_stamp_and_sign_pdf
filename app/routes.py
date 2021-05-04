from app import app,db, cors
from flask import render_template, request, flash, redirect, url_for, send_file, make_response, jsonify, session, send_file
from app.models.File import fileModel, SignTable
from flask_login import login_required, current_user, logout_user, login_user
import os
import base64
from datetime import timedelta, datetime
from sqlalchemy import and_
from flask_cors import CORS, cross_origin
from werkzeug.utils import secure_filename
from config import Config

from app.models.Users import User, load_user, Permission
from app.decorators import permission_required, admin_required
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
from app.PyHanko import buat_qr, create_sign, pretty, create_sign_new
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
def dashboard():
    return render_template('index.html')
##################  DOKUEMEN KONTROL  ############################
@app.route('/delete/<id>')
@login_required
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

@app.route('/detail_sign/<id>')
@login_required
def detail_sign_file(id):
    data = SignTable.query.filter_by(id=id).first_or_404()
    return render_template('/document/detail_sign.html', data = data)

def allowed_file_pdf(filename):
    return '.' in filename and \
        filename.rsplit('.', 1)[1].lower() in Config.ALLOWED_EXTENSIONS[0]

@app.route('/upload', methods=['POST', 'GET'])
@login_required
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
                file.save(os.path.join(app.config['UPLOAD_FILE'],output_file))
                #Open File
                b = open(path1, 'rb')
                up = fileModel( filename = file_name, file = b.read(), user_id = current_user.id,  dosen1 = dosen1, dosen2= dosen2, dosen3 = dosen3, page=page)
                db.session.add(up)
                db.session.commit()
                flash('File Berhasil Diupload','success')
                return redirect(url_for('diupload'))
            except Exception as e:
                return str(e)
    return render_template('/upload/index.html')


@app.route('/diupload')
@login_required
def diupload():
    data = fileModel.query.filter_by(user_id = current_user.id)
    return render_template('/diupload/index.html', a = data )

@app.route('/download_template')
@login_required
def download_template():
   res = send_file(os.path.join(app.config['TEMPLATE_FOLDER'],'template.docx'), as_attachment= True)
   return res

@app.route('/template')
def template():
    return render_template('/settings/template.html')

@app.route('/upload_template', methods = ['POST', 'GET'])
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
@login_required
def valid_main():
    return render_template('/validity/validity.html')

@app.route('/validity', methods = ['POST'])
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
            return render_template('/validity/result.html', data =l )
        except Exception as e:
            flash('dokumen tidak memiliki tanda tangan atau dokumen telah dimodifikasi', 'danger')
            return redirect(url_for('dashboard'))  
        return render_template('/validity/result.html', data = hasil, a = a)


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
    # dosen = User.query.filter_by(name=namadosen).first_or_404()
    # file = fileModel.query.fil
    return render_template('/validity/result_new.html', namafile= namafile, namadosen = namadosen,nama= nama, date = date)

@app.route('/permintaan', methods=['GET','POST'])
@login_required
@permission_required(Permission.SIGN)
def permintaan():
    a = SignTable.sign3
    data_1 = fileModel.query.filter((fileModel.dosen1_sign == False),(fileModel.dosen1== current_user.name))
    data_2 = fileModel.query.filter((fileModel.dosen2_sign == False),(fileModel.dosen2== current_user.name))
    # data_2 =db.session.query(fileModel, SignTable ).join(fileModel). \
    #         filter((fileModel.dosen2_sign == False),(fileModel.dosen2 == current_user.name)) 
    data3 = db.session.query(SignTable,fileModel ).join(SignTable). \
            filter((fileModel.dosen3_sign == False),(fileModel.dosen3 == current_user.name))
    return render_template('/permintaan/index.html', data = data_1, data1= data_2, data3 = data3)

@app.route('/stamp1/<id>', methods=['GET','POST'])
@login_required
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


@app.route('/stamp2/<id>', methods=['GET','POST'])
@permission_required(Permission.SIGN)
@login_required
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
@permission_required(Permission.SIGN)
def signature(id):
    data = User.query.filter_by(id=id).first_or_404()
    return render_template('/settings/signature.html', user = data )

@app.route('/uploadsign/<id>', methods=['POST','GET'])
@permission_required(Permission.SIGN)
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
@permission_required(Permission.ADMIN)
def all_mhs():
    mhs = User.query.filter_by(role_id=1)
    return render_template('admin/data_mhs/index.html', data = mhs)

@app.route('/add/mhasiswa',methods=['POST','GET'])
@login_required
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
           flash('Data Tidak Ada', 'warning')
           return redirect(url_for('all_mhs'))

       flash('Data berhasil di hapus','success')
       return redirect(url_for('all_mhs'))
   except Exception as err:
       return str(err)
   return redirect(url_for('all_mhs'))

############################ DOSEN ######################################
@app.route('/admin/data_dosen')
@login_required
@permission_required(Permission.ADMIN)
def all_dosen():
    dosen = User.query.filter_by(role_id=2)
    return render_template('admin/data_dosen/index.html', data = dosen)

@app.route('/add/dosen',methods=['POST','GET'])
@login_required
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
@permission_required(Permission.ADMIN)
def all_prodi():
    prodi = User.query.filter_by(role_id=3)
    return render_template('admin/data_prodi/index.html', data = prodi)

@app.route('/add/prodi',methods=['POST','GET'])
@login_required
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

#######################PRODI ########################################

@app.route('/profile/<id>')
def profile(id):
    data = User.query.filter_by(id=id).first_or_404()
    return render_template('/settings/profile.html', user = data)


##################### USER #########################################
@app.route('/changepassword/<id>', methods = ['POST','GET'])
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

@app.route('/verify_stamp/')
def verify():
    jo = db.session.query(fileModel, User ).join(User). \
            filter(fileModel.dosen1 == current_user.name)
    data = jo
    return str(data)