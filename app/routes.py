from app import app,db
from flask import render_template, request, flash, redirect, url_for, send_file, make_response, jsonify, session, send_file
from app.models.File import fileModel, SignTable
from flask_login import login_required, current_user, logout_user, login_user
import os
from datetime import timedelta, datetime
from sqlalchemy import and_

from app.models.Users import User, load_user, Permission
from app.decorators import permission_required, admin_required
# from app.errors import forbidden, page_not_found, internal_server_error


from oscrypto import keys
from certvalidator import ValidationContext
from pyhanko.pdf_utils.reader import PdfFileReader
from pyhanko.sign.validation import validate_pdf_signature
from io import BytesIO
from pyhanko.sign.fields import SigFieldSpec, append_signature_field
from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
#STAMP
from app.PyHanko import buat_qr, create_sign

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
                next = url_for('index')
            return redirect(next)
        flash('Invalid email or password.')
    return render_template('/login/login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.')
    return redirect(url_for('login'))

# @app.before_request
# def before_request():
#     session.permanent = True
#     app.permanent_session_lifetime = timedelta(minutes=1)


#################  MAIN  ############################
@app.route('/')
@login_required
def index():
   return render_template('index.html')

##################  DOKUEMEN KONTROL  ############################
@app.route('/delete/<id>')
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
def view_doc(id):
   data = fileModel.query.filter_by(id=id).first_or_404()
   pdf =BytesIO(data.file)
   name = data.filename
   return send_file(pdf,cache_timeout=0, attachment_filename='kk.pdf',as_attachment=False)

@app.route('/view_sign/<id>')
def view_doc_sign(id):
   data = SignTable.query.filter_by(id=id).first_or_404()
   pdf =BytesIO(data.file)
   return send_file(pdf,cache_timeout=0, attachment_filename='kk.pdf',as_attachment=False)

@app.route('/detail/<id>')
def detail_file(id):
    data = fileModel.query.filter_by(id=id).first_or_404()
    return render_template('/document/detail.html', data = data)

@app.route('/detail_sign/<id>')
def detail_sign_file(id):
    data = SignTable.query.filter_by(id=id).first_or_404()
    return render_template('/document/detail_sign.html', data = data)

@app.route('/upload', methods=['POST', 'GET'])
def upload_file():
    if request.method == 'POST':
        file = request.files['file']
        file_name = request.form['filename']
        dosen1 = request.form['dosen1']
        dosen2 = request.form['dosen2']
        if file.filename != '':
            try:
                #fields
                output_file = file_name +' ' + current_user.name+'.pdf'
                a = open(output_file, mode="wb")
                w = IncrementalPdfFileWriter(file)
                append_signature_field(w, SigFieldSpec(sig_field_name='Signature1'))
                w.write(a)

                #Open File
                b = open(output_file, 'rb')
                up = fileModel( filename = file_name, file = b.read(), user_id = current_user.id,  dosen1 = dosen1, dosen2= dosen2)
                db.session.add(up)
                db.session.commit()
                # if os.path.exists(output_file):
                #     os.remove(output_file)
                #     print('delete success')
                # else:
                #     print("The file does not exist")
                flash('File Berhasil Diupload','success')
                return redirect(url_for('diupload'))
            except Exception as e:
                return str(e)
    return render_template('/upload/index.html')


@app.route('/diupload')
def diupload():
    data = fileModel.query.filter_by(user_id = current_user.id)
    return render_template('/diupload/index.html', a = data )
@app.route('/download_template')
def download_template():
   res = send_file('template.docx', as_attachment= True)
   return res

#################  VALIDASI  ############################
@app.route('/validity')
def valid_main():
    return render_template('/validity/validity.html')

@app.route('/validity', methods = ['POST'])
def valid():
    cert = open('cert.pem', 'r')
    file = request.files['file']
    # with open(cert, 'r') as f2:
    if file.filename != '':
        data = cert.read()
        data = bytes(data, encoding='utf-8')
        root_cert = keys.parse_certificate(data)
        vc = ValidationContext(trust_roots=[root_cert])

        r = PdfFileReader(file)
        sig = r.embedded_signatures[0]
        status = validate_pdf_signature(sig, vc)
        hasil = status.pretty_print_details()
        return render_template('/validity/result.html', data = hasil)


#################  DOSEN AREA  ############################
@app.route('/_namadosen', methods=['GET'])
def namaDosen():
    res =User.query.filter_by(role_id = 2)
    list_dosen = [r.as_dict() for r in res]
    return jsonify(list_dosen)

@app.route('/sign/detail/<namadosen>', methods=['GET', 'POST'])
def detail_dosen(namadosen):
    dosen = User.query.filter_by(name=namadosen).first_or_404()
    return str('Document Has been Sign by'+dosen.name)

@app.route('/permintaan', methods=['GET','POST'])
@permission_required(Permission.SIGN)
def permintaan():
    a = SignTable.sign3
    data_1 = fileModel.query.filter((fileModel.dosen1_sign == False),(fileModel.dosen1== current_user.name))
    data_2 = fileModel.query.filter((fileModel.dosen2_sign == False),(fileModel.dosen2== current_user.name))
    data3 = SignTable.query.filter_by(sign3= None)
    return render_template('/permintaan/index.html', data = data_1, data1= data_2, data3 = data3)

@app.route('/stamp1/<id>', methods=['GET','POST'])
@permission_required(Permission.SIGN)
def stampOne(id):
    file = fileModel.query.filter_by(id=id).first_or_404()
    inputFile =  file.filename+ ' '+file.doc.name+'.pdf'
    output1 = file.filename+ ' '+file.doc.name+' stamp1.pdf'
    # try:
    #     valid =  open(output1 , 'r')
    #     if valid is None:
    try:
        buat_qr(inputFile,output1, 'http://127.0.0.1:5000/sign/detail/'+current_user.name ,current_user.name,0, 95, 325)
    except Exception as err:
        flash(str(err), 'danger')
        return redirect(url_for('permintaan'))
    with open(output1, 'rb') as doc:
        file_id_data = file.id
        file_data = doc.read()
        sign1_data = current_user.name 
        try:
            data = SignTable(file_id = file_id_data, file=file_data, sign1 = sign1_data, sign1_date = datetime.utcnow())
            db.session.add(data)
            file.dosen1_sign = True
            db.session.commit()
            if os.path.exists(inputFile):
                os.remove(inputFile)
                print('delete success')
            else:
                print("The file does not exist")
            flash('File Berhasil Di tanda tangan','success')
            return redirect(url_for('permintaan'))
        except Exception as err:
            flash(str(err), 'danger')
            return redirect(url_for('permintaan'))
    #     elif valid is not None:
    #         flash('bisa sign ke 2', 'info')
    #         return redirect(url_for('permintaan'))
    # except Exception as err:
    #     flash(str(err), 'danger')
    #     return redirect(url_for('permintaan'))
    return redirect(url_for('permintaan'))

@app.route('/sudah_ditandatangani', methods=['POST','GET'])
def sign_file():
    name = fileModel.query.filter(fileModel.id == SignTable.file_id)
    data = SignTable.query.filter((SignTable.sign1 == current_user.name) | (SignTable.sign2 == current_user.name)| (SignTable.sign3 == current_user.name))
    return render_template('/ditandatangani/index.html', data = data, name = name)

@app.route('/sudah_ditandatangani_dosen', methods=['POST','GET'])
def sign_file_all():
    file = fileModel.query.filter_by(user_id = current_user.id).first_or_404()
    data = SignTable.query.filter_by(file_id = file.id)
    jo = db.session.query(SignTable,fileModel ).join(fileModel). \
        filter(fileModel.user_id == current_user.id)
    return render_template('/ditandatangani/index_mhs.html', data = data, file = jo)


@app.route('/stamp2/<id>', methods=['GET','POST'])
@permission_required(Permission.SIGN)
def stampTwo(id):
    file = fileModel.query.filter_by(id=id).first_or_404()
    output1 = file.filename+ ' '+file.doc.name+' stamp1.pdf'
    output2 = file.filename+ ' '+file.doc.name+' stamp2.pdf'
    try:
        buat_qr(output1,output2, 'http://127.0.0.1:5000/sign/detail/'+current_user.name ,current_user.name,0, 330, 325)
    except Exception as err:
        flash(str('Penguji Pertama Belum Tanda Tangan'), 'danger')
        return redirect(url_for('permintaan'))
    with open(output2, 'rb') as doc:
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
            if os.path.exists(output1):
                os.remove(output1)
                print('delete success')
            else:
                print("The file does not exist")
            flash('File Berhasil Di tanda tangan','success')
            return redirect(url_for('permintaan'))
        except Exception as err:
            flash(str(err), 'danger')
            return redirect(url_for('permintaan'))
    return redirect(url_for('permintaan'))

@app.route('/stamp3/<id>', methods=['GET','POST'])
@permission_required(Permission.SIGN)
def stampThree(id):
    file = fileModel.query.filter_by(id=id).first_or_404()
    final = file.filename+ ' '+file.doc.name+'.pdf'
    output2 = file.filename+ ' '+file.doc.name+' stamp2.pdf'
    output3 = file.filename+ ' '+file.doc.name+' stamp3.pdf'

    try:
        buat_qr(output2,output3, 'http://127.0.0.1:5000/sign/detail/'+current_user.name ,current_user.name,0, 200, 140)
        try:
            create_sign(output3, final, 'pb1.crt','pb1.pem','pb1.pem','Signature1', 'Approval',current_user.name)
        except Exception as err:
            flash(str(err), 'danger')
            return redirect(url_for('permintaan'))
    except Exception as err:
        flash(str(err), 'danger')
        return redirect(url_for('permintaan'))
    with open(final, 'rb') as doc:
        file_id_data = file.id
        file_data = doc.read()
        sign1_data = current_user.name 
        try:
            data = SignTable.query.filter_by(file_id = file_id_data).first_or_404()
            data.sign3 = current_user.name
            data.sign3_date = datetime.utcnow()
            data.file = file_data
            db.session.commit()
            
            if os.path.exists(output3):
                os.remove(output3)
                print('delete success')
            else:
                print("The file does not exist")
            if os.path.exists(output2):
                os.remove(output2)
                print('delete success')
            else:
                print("The file does not exist")
            if os.path.exists(final):
                os.remove(final)
                print('delete success')
            else:
                print("The file does not exist")
            flash('File Berhasil Di tanda tangan','success')
            return redirect(url_for('permintaan'))
        except Exception as err:
            flash(str(err), 'danger')
            return redirect(url_for('permintaan'))
    return redirect(url_for('permintaan'))