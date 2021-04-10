from pyhanko.pdf_utils.reader import PdfFileReader
from pyhanko.stamp import qr_stamp_file, QRStampStyle, QRStamp
from pyhanko.pdf_utils.text import TextBoxStyle, TextBox
from pyhanko.pdf_utils.font import SimpleFontEngine
from pyhanko.sign.fields import SigFieldSpec, append_signature_field
from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
from pyhanko.sign import signers
from oscrypto import keys
from certvalidator import ValidationContext
from pyhanko.pdf_utils.reader import PdfFileReader

#FUNGSI 
def buat_qr(input_data, output_data, urls, user, page, x, y):
    tb = TextBoxStyle(font=SimpleFontEngine(name='Courier', avg_width=0.6),
                      font_size=8, leading=None,
                      text_sep=10, border_width=0,
                      vertical_center=False,)

    out = qr_stamp_file(input_data, output_data,
                        QRStampStyle(
                            border_width=0,
                            text_box_style=tb, stamp_text="Digital Signed By \n{} \n%(ts)s ".format(
                                user),
                            timestamp_format='%d-%m-%Y %H:%M:%S %Z',
                            stamp_qrsize=0.50,
                        ), page, x, y, url=urls)
    return out

def create_sign(input_file, output_file, crt_file, key_file, ca_key, field, reason, name):
    cms_signer = signers.SimpleSigner.load(
        key_file, crt_file,
        ca_chain_files=(ca_key,),
        key_passphrase=b'rahasia'
    )
    a = open(output_file, mode="wb")
    with open(input_file, 'rb') as doc:
        w = IncrementalPdfFileWriter(doc)
        out = signers.sign_pdf(
            w, signers.PdfSignatureMetadata(
                field_name=field,
                reason=reason,
                name=name,
            ),
            signer=cms_signer, output=a
        )
    return out