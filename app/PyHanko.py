from pyhanko.pdf_utils.reader import PdfFileReader
from pyhanko.stamp import qr_stamp_file, QRStampStyle, QRStamp
from pyhanko.pdf_utils.text import TextBoxStyle, TextBox
from pyhanko.pdf_utils.font import SimpleFontEngine
from pyhanko.sign.fields import SigFieldSpec, append_signature_field
from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
from pyhanko.sign import signers
from oscrypto import keys
from pyhanko.sign import fields
from certvalidator import ValidationContext
from pyhanko.pdf_utils.reader import PdfFileReader
from pyhanko.sign.fields import SigSeedSubFilter, MDPPerm
from pyhanko.pdf_utils.images import PdfImage
from PIL import Image
import os
from config import Config
from app import app
from pyhanko.sign.diff_analysis import (
    SuspiciousModification, ModificationLevel, DEFAULT_DIFF_POLICY, DiffPolicy,
    DiffResult,
)

#FUNGSI 
def buat_qr(bg, input_data, output_data, urls, user, page, x, y):
    tb = TextBoxStyle(font=SimpleFontEngine(name='Courier', avg_width=0.6),
                      font_size=8, leading=None,
                      text_sep=10, border_width=0,
                      vertical_center=False,)
    path = os.path.join(app.config['SIGNATURE_FILE'],bg)
    img = Image.open(path)

    out = qr_stamp_file(input_data, output_data,
                        QRStampStyle(
                            background= PdfImage(img, writer=None),
                            background_opacity=1,
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
                location= 'Pelita Bangsa University',
                subfilter = SigSeedSubFilter.PADES,
                use_pades_lta= True,
                timestamp_field_name = 'Field_time' ,
                docmdp_permissions= MDPPerm.NO_CHANGES,
                # embed_validation_info= True,
                # validation_context = ValidationContext(other_certs=[root_cert]), 
                md_algorithm = 'sha256'
            ),
            signer=cms_signer, output=a
        )
    return out

def create_sign_new(input_file, output_file, bg, crt_file, key_file, field:str, url:str ,reason:str, name:str, password:str,page:int, x:int, y:int):
    x1 = x+180
    y1 = y+60
    cms_signer = signers.SimpleSigner.load(
        key_file, crt_file,
        key_passphrase=bytes(password, encoding='utf-8')
    )
    path = os.path.join(app.config['SIGNATURE_FILE'],bg)
    img = Image.open(path)
    tb = TextBoxStyle(font=SimpleFontEngine(name='Courier', avg_width=0.6),
                    font_size=8, leading=None,
                    text_sep=10, border_width=0,
                    vertical_center=False,)
    a = open(output_file, mode="wb")
    with open(input_file, 'rb') as doc:
        w = IncrementalPdfFileWriter(doc)
        #x = 300
        #y = 174
        append_signature_field(w, SigFieldSpec(sig_field_name=field, on_page=page, box=(x,y,x1,y1),
                                                field_mdp_spec=fields.FieldMDPSpec(fields.FieldMDPAction.INCLUDE, 
                                                fields=['fields']), doc_mdp_update_value=fields.MDPPerm.FILL_FORMS))
        style = QRStampStyle(
            background=PdfImage(img, writer=None),
            background_opacity=1,
            border_width=0,
            text_box_style=tb, 
            stamp_text="Digital Signed By \n{} \n%(ts)s".format(name),
            timestamp_format='%d-%m-%Y %H:%M:%S %Z',
            stamp_qrsize=0.50)
        out = signers.PdfSigner(
            signers.PdfSignatureMetadata(
                field_name=field,
                reason=reason,
                name=name,
                location= 'Pelita Bangsa',
                subfilter = SigSeedSubFilter.PADES,
                use_pades_lta= True,
                timestamp_field_name = 'Field_time',
                md_algorithm = 'sha256'
            ),
            signer=cms_signer,
            stamp_style= style
        ).sign_pdf(pdf_out= w, output=a, appearance_text_params= {'url': url})
    return out


from pyhanko.sign.general import SignatureStatus
from pyhanko.sign.validation import SignatureCoverageLevel
def pretty(self):
        cert: x509.Certificate = self.signing_cert

        def _trust_anchor(status: SignatureStatus):
            if status.validation_path is not None:
                trust_anchor: x509.Certificate = status.validation_path[0]
                return trust_anchor.subject.human_friendly
            else:
                return "No path to trust anchor found."

        if self.trusted:
            trust_status = "trusted"
        elif self.revoked:
            trust_status = "revoked"
        else:
            trust_status = "untrusted"
        about_signer = (
            f"Certificate subject: \"{cert.subject.human_friendly}\"\n"
            f"Certificate SHA1 fingerprint: {cert.sha1.hex()}\n"
            f"Certificate SHA256 fingerprint: {cert.sha256.hex()}\n"
            f"Trust anchor: \"{_trust_anchor(self)}\"\n"
            f"The signer's certificate is {trust_status}."
        )

        if self.coverage == SignatureCoverageLevel.ENTIRE_FILE:
            modification_str = "The signature covers the entire file."
        else:
            modlvl_string = "Some modifications may be illegitimate"
            if self.modification_level is not None:
                if self.modification_level == ModificationLevel.LTA_UPDATES:
                    modlvl_string = \
                        "All modifications relate to signature maintenance"
                elif self.modification_level == ModificationLevel.FORM_FILLING:
                    modlvl_string = (
                        "All modifications relate to signing and form filling "
                        "operations"
                    )
            modification_str = (
                "The signature does not cover the entire file.\n"
                f"{modlvl_string}, and they appear to be "
                f"{'' if self.docmdp_ok else 'in'}compatible with the "
                "current document modification policy."
            )

        validity_info = (
            "The signature is cryptographically "
            f"{'' if self.intact and self.valid else 'un'}sound.\n"
            f"{modification_str}"
        )

        ts = self.signer_reported_dt
        tst_status = self.timestamp_validity
        about_tsa = ''
        if tst_status is not None:
            ts = tst_status.timestamp
            tsa = tst_status.signing_cert

            about_tsa = (
                "The signing time is guaranteed by a time stamping authority.\n"
                f"TSA certificate subject: \"{tsa.subject.human_friendly}\"\n"
                f"TSA certificate SHA1 fingerprint: {tsa.sha1.hex()}\n"
                f"TSA certificate SHA256 fingerprint: {tsa.sha256.hex()}\n"
                f"TSA cert trust anchor: \"{_trust_anchor(tst_status)}\"\n"
                "The TSA certificate is "
                f"{'' if tst_status.trusted else 'un'}trusted."
            )
        elif ts is not None:
            about_tsa = "The signing time is self-reported by the signer."

        if ts is not None:
            signing_time_str = ts.isoformat()
        else:
            signing_time_str = "unknown"

        timing_info = (
            f"Signing time: {signing_time_str}\n{about_tsa}"
        )

        def fmt_section(hdr, body):
            return '\n'.join(
                (hdr, '-' * len(hdr), body, '\n')
            )

        bottom_line = (
            f"The signature is judged {'' if self.bottom_line else 'IN'}VALID."
        )

        if self.seed_value_ok:
            sv_info = "There were no SV issues detected for this signature."
        else:
            sv_info = (
                "The signature did not satisfy the SV constraints on "
                "the signature field.\nError message: "
                + self.seed_value_constraint_error.failure_message
            )

        sections = [
            ("Signer info", about_signer), ("Integrity", validity_info),
            ("Signing time", timing_info),
            ("Seed value constraints", sv_info),
            ("Bottom line", bottom_line)
        ]
        return sections