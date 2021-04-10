from app import app
from flask import request
# from pyhanko_certvalidator import ValidationContext
# from pyhanko.pdf_utils.reader import PdfFileReader
# from pyhanko.sign.validation import validate_pdf_signature


@app.route('/validity')
def valid():
    cert = open('cert.pem', 'r')
    file = request.files['file']
    # with open(cert, 'r') as f2:
    data = cert.read()
    data = bytes(data, encoding='utf-8')
    root_cert = keys.parse_certificate(data)
    vc = ValidationContext(trust_roots=[root_cert])

    r = PdfFileReader(file)
    sig = r.embedded_signatures[0]
    status = validate_pdf_signature(sig, vc)
    print(status.pretty_print_details())
    return status.pretty_print_details()