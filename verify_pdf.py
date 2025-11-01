import re
import sys
from cryptography import x509
from asn1crypto import cms


def extract_signature(pdf_bytes: bytes):
    """
    Trích xuất vùng dữ liệu được ký và blob PKCS#7 từ file PDF (do sign_pdf.py tạo).
    """
    pattern = rb"/ByteRange\s*\[\s*(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s*\]"
    found = re.search(pattern, pdf_bytes)
    if not found:
        raise RuntimeError("Không tìm thấy /ByteRange trong PDF.")
    a, b, c, d = map(int, found.groups())

    pkcs7_data = pdf_bytes[b:c].rstrip(b"\x00")
    signed_part = pdf_bytes[:b] + pdf_bytes[c:]
    return signed_part, pkcs7_data, (a, b, c, d)


def verify_pdf_signature(pdf_path: str, cert_path: str):
    """Phân tích và kiểm tra cấu trúc chữ ký PKCS#7 trong PDF."""
    with open(pdf_path, "rb") as f:
        pdf_bytes = f.read()

    signed_data_bytes, pkcs7_blob, byte_range = extract_signature(pdf_bytes)
    print(f"📑 ByteRange: {byte_range}")
    print(f"📦 Kích thước blob PKCS#7: {len(pkcs7_blob)} bytes")

    # Nạp chứng chỉ PEM
    with open(cert_path, "rb") as f:
        cert_bytes = f.read()
    cert = x509.load_pem_x509_certificate(cert_bytes)
    print(f"🔐 Thuật toán ký trong chứng chỉ: {cert.signature_algorithm_oid._name}")

    # Phân tích cấu trúc PKCS#7
    try:
        pkcs7_info = cms.ContentInfo.load(pkcs7_blob)
    except Exception as e:
        print("❌ Không đọc được dữ liệu PKCS#7:", e)
        return

    if pkcs7_info["content_type"].native != "signed_data":
        print("⚠ Không phải cấu trúc SignedData.")
        return

    signed_data = pkcs7_info["content"]
    # Truy cập đúng cú pháp thay vì .get()
    certs = signed_data["certificates"]
    signers = signed_data["signer_infos"]

    cert_count = len(certs) if certs is not None else 0
    signer_count = len(signers) if signers is not None else 0

    print(f"📜 PKCS#7 chứa {cert_count} chứng chỉ và {signer_count} signer(s).")

    if cert_count > 0 and signer_count > 0:
        print("✅ Cấu trúc chữ ký hợp lệ (có certificate & signer).")
    else:
        print("⚠ Thiếu certificate hoặc signer trong chữ ký.")

    print("\n🔍 Có thể kiểm chứng thủ công bằng OpenSSL:")
    print("   openssl cms -verify -inform DER -in signature.der "
          "-content data.bin -noverify -certfile student_cert.pem")


def main():
    if len(sys.argv) != 3:
        print("Cách dùng: python verify_pdf.py signed.pdf student_cert.pem")
        sys.exit(1)

    verify_pdf_signature(sys.argv[1], sys.argv[2])


if __name__ == "__main__":
    main()
