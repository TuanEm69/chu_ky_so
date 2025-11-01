# BÀI TẬP VỀ NHÀ – MÔN: AN TOÀN VÀ BẢO MẬT THÔNG TIN
# Nguyễn Tuấn Anh - K225480106095
 Chủ đề: Chữ ký số trong file PDF
 Giảng viên: Đỗ Duy Cốp
 Thời điểm giao: 2025-10-24 11:45
 Đối tượng áp dụng: Toàn bộ sv lớp học phần 58KTPM
 Hạn nộp: Sv upload tất cả lên github trước 2025-10-31 23:59:59--
## I. MÔ TẢ CHUNG
 Sinh viên thực hiện báo cáo và thực hành: phân tích và hiện thực việc nhúng, xác 
thực chữ ký số trong file PDF.
 Phải nêu rõ chuẩn tham chiếu (PDF 1.7 / PDF 2.0, PAdES/ETSI) và sử dụng công cụ 
thực thi (ví dụ iText7, OpenSSL, PyPDF, pdf-lib).--
## II. CÁC YÊU CẦU CỤ THỂ
 1) Cấu trúc PDF liên quan chữ ký 
 2) Thời gian ký được lưu ở đâu?
    
  2 Phần trên đã có trong file "Tìm hiểu về pdf.pdf"
    
 4) Các bước tạo và lưu chữ ký trong PDF (đã có private RSA)- Viết script/code thực hiện tuần tự:
 1. Chuẩn bị file PDF gốc.
 2. Tạo Signature field (AcroForm), reserve vùng /Contents (8192 bytes).
 3. Xác định /ByteRange (loại trừ vùng /Contents khỏi hash).
 4. Tính hash (SHA-256/512) trên vùng ByteRange.
 5. Tạo PKCS#7/CMS detached hoặc CAdES:- Include messageDigest, signingTime, contentType.- Include certificate chain.- (Tùy chọn) thêm RFC3161 timestamp token.
 6. Chèn blob DER PKCS#7 vào /Contents (hex/binary) đúng offset.
 7. Ghi incremental update.
 8. (LTV) Cập nhật DSS với Certs, OCSPs, CRLs, VRI.- Phải nêu rõ: hash alg, RSA padding, key size, vị trí lưu trong PKCS#7.- Đầu ra: mã nguồn, file PDF gốc, file PDF đã ký.
4) Các bước xác thực chữ ký trên PDF đã ký- Các bước kiểm tra:
 1. Đọc Signature dictionary: /Contents, /ByteRange.
 2. Tách PKCS#7, kiểm tra định dạng.
 3. Tính hash và so sánh messageDigest.
 4. Verify signature bằng public key trong cert.
 5. Kiểm tra chain → root trusted CA.
 6. Kiểm tra OCSP/CRL.
 7. Kiểm tra timestamp token.
 8. Kiểm tra incremental update (phát hiện sửa đổi).- Nộp kèm script verify + log kiểm thử.--

## LỆNH CHẠY CODE
Đầu tiên phải tải và cài đặt python bản 3.12.3

Chuẩn bị môi trường puthon trong vs code;

Cài thư viện: pip install cryptography pypdf asn1crypto

Ký file PDF: python sign_pdf.py original.pdf signed.pdf

Kiểm tra chữ ký: python verify_pdf.py signed.pdf student_cert.pem
