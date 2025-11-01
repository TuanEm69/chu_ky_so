import sys
from datetime import datetime, timedelta, timezone
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, NoEncryption
from cryptography.hazmat.primitives.serialization.pkcs7 import PKCS7SignatureBuilder, PKCS7Options
from cryptography.x509.oid import NameOID
from pypdf import PdfReader, PdfWriter

PLACEHOLDER_SIZE = 8192  # vùng trống dành cho chữ ký


def create_self_signed_cert():
    """Sinh khóa RSA và chứng chỉ tự ký."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "PDFSigner-Student58KTPM")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(timezone.utc) - timedelta(minutes=1))
        .not_valid_after(datetime.now(timezone.utc) + timedelta(days=365))
        .sign(key, hashes.SHA256())
    )
    return key, cert


def add_placeholder(src_pdf, temp_pdf):
    """Sao chép PDF gốc và chèn vùng placeholder cho chữ ký."""
    reader = PdfReader(src_pdf)
    writer = PdfWriter()
    for p in reader.pages:
        writer.add_page(p)

    with open(temp_pdf, "wb") as f:
        writer.write(f)

    with open(temp_pdf, "ab") as f:
        f.write(b"\n% Signature placeholder\n")
        f.write(b"/ByteRange [0 ********** ********** **********]\n")
        f.write(b"\x00" * PLACEHOLDER_SIZE)

    print(f"[+] Đã thêm placeholder: {temp_pdf}")


def inject_signature(temp_pdf, signed_pdf, pkcs7_blob):
    """Chèn dữ liệu PKCS#7 vào vùng placeholder và cập nhật ByteRange."""
    pdf_bytes = open(temp_pdf, "rb").read()
    placeholder = b"\x00" * PLACEHOLDER_SIZE
    pos = pdf_bytes.find(placeholder)
    if pos == -1:
        raise RuntimeError("Không tìm thấy vùng placeholder trong PDF tạm!")

    start = pos
    end = start + PLACEHOLDER_SIZE
    byte_range = [0, start, end, len(pdf_bytes) - end]

    # Chèn chữ ký
    output = bytearray(pdf_bytes)
    output[start:start + len(pkcs7_blob)] = pkcs7_blob

    # Cập nhật ByteRange
    br_text = f"/ByteRange [{byte_range[0]} {byte_range[1]} {byte_range[2]} {byte_range[3]}]"
    br_start = pdf_bytes.find(b"/ByteRange [")
    br_end = pdf_bytes.find(b"]", br_start)
    output[br_start:br_end + 1] = br_text.encode().ljust(br_end + 1 - br_start, b" ")

    with open(signed_pdf, "wb") as f:
        f.write(output)

    print(f"[+] PDF đã ký: {signed_pdf}")
    print("ByteRange:", byte_range)


def main():
    if len(sys.argv) != 3:
        print("Cách dùng: python sign_pdf.py input.pdf signed.pdf")
        sys.exit(1)

    input_pdf, signed_pdf = sys.argv[1], sys.argv[2]
    temp_pdf = input_pdf.replace(".pdf", "_temp.pdf")

    add_placeholder(input_pdf, temp_pdf)
    key, cert = create_self_signed_cert()

    pdf_bytes = open(temp_pdf, "rb").read()
    placeholder = b"\x00" * PLACEHOLDER_SIZE
    pos = pdf_bytes.find(placeholder)
    data_to_sign = pdf_bytes[:pos] + pdf_bytes[pos + PLACEHOLDER_SIZE:]

    pkcs7 = (
        PKCS7SignatureBuilder()
        .set_data(data_to_sign)
        .add_signer(cert, key, hashes.SHA256())
        .sign(Encoding.DER, [PKCS7Options.DetachedSignature])
    )

    inject_signature(temp_pdf, signed_pdf, pkcs7)

    open("student_key.pem", "wb").write(
        key.private_bytes(Encoding.PEM, PrivateFormat.TraditionalOpenSSL, NoEncryption())
    )
    open("student_cert.pem", "wb").write(cert.public_bytes(Encoding.PEM))

    print("[+] Đã tạo student_key.pem và student_cert.pem")


if __name__ == "__main__":
    main()
