# Bài 1: Tấn công giả mạo tên miền (IDN Homograph Attack)

## 1. Bối cảnh & Hiện trường giả
* **Bối cảnh**: Một lập trình viên nhận được thông báo *"Security Alert"* yêu cầu đăng nhập lại GitHub để xác minh. Thanh địa chỉ hiển thị: `https://githúb.com/login`.
* **Hiện trường giả**: Sinh viên nộp một đoạn mã giả lập kiểm tra chuỗi URL nhưng lại bỏ qua việc kiểm tra các ký tự Unicode gây nhầm lẫn (Homograph Attack).

## 2. Bảng tổng hợp kiến thức & Giải quyết yêu cầu

| Yêu cầu đầu ra | Nội dung phân tích chi tiết |
| :--- | :--- |
| **1. Chỉ ra ký tự lạ trong URL và giải thích tại sao nó đánh lừa được người dùng** | • **Ký tự lạ**: Chữ **`ú`** (ký tự Unicode có dấu sắc, mã `U+00FA`) nằm trong cụm `githúb.com`, thay thế cho chữ **`u`** chuẩn ASCII (`U+0075`) của tên miền thật `github.com`.<br>• **Lý do đánh lừa mắt người**: Khi hiển thị trên thanh địa chỉ trình duyệt với phông chữ nhỏ, dấu sắc trên chữ `ú` rất mảnh. Kết hợp với tâm lý hoảng loạn khi thấy cảnh báo *"Security Alert"*, người dùng thường chỉ nhìn lướt tổng thể chữ `github` và biểu tượng ổ khóa `https://` mà không soi từng ký tự.<br>• **Lý do đánh lừa đoạn mã kiểm tra của sinh viên**: Nếu đoạn mã chỉ kiểm tra cú pháp URL thông thường (như kiểm tra tiền tố `https://`, đuôi `.com`, hoặc dùng biểu thức chính quy cho phép ký tự chữ Unicode) mà **không chuẩn hóa chuỗi (Unicode Normalization)** hoặc **không biên dịch sang định dạng Punycode**, chương trình vẫn đánh giá URL này là hợp lệ. |
| **2. Quy trình kiểm tra URL nhanh bằng mắt thường trước khi nhập Master Password** | • **Xác định đúng Tên miền gốc (Root Domain)**: Chỉ tập trung đọc cụm ký tự nằm ngay trước dấu gạch chéo `/` đầu tiên sau `https://` (tức là `githúb.com`).<br>• **Soi từng ký tự dễ gây nhầm lẫn**: Kiểm tra xem có chữ cái mang dấu tiếng Việt/ngoại ngữ (`ú`, `а`, `е`, `о` hệ Kirin) hoặc các cặp ký tự giả dạng nhau (số `0` thay chữ `o`, chữ `I` hoa thay chữ `l` thường, hai chữ `rn` ghép sát nhau giả làm chữ `m`) hay không.<br>• **Không tin tưởng mù quáng vào `https://`**: Giao thức HTTPS và biểu tượng ổ khóa chỉ chứng minh kết nối được mã hóa đường truyền, không chứng minh trang web đó là chính chủ (kẻ tấn công dễ dàng đăng ký chứng chỉ SSL miễn phí Let's Encrypt cho tên miền giả `githúb.com`). |
| **3. Quy trình kiểm tra URL bằng công cụ hỗ trợ trước khi nhập Master Password** | • **Sử dụng tính năng Tự động điền (Auto-fill) của Password Manager**: Các trình quản lý mật khẩu chuyên dụng (như Bitwarden, 1Password, KeePassXC) so sánh tên miền dựa trên mã máy thật (Punycode). Khi truy cập `githúb.com` (mã thật là `xn--githb-rva.com`), Password Manager nhận thấy không khớp với `github.com` nên **từ chối tự động điền mật khẩu** — đây là dấu hiệu cảnh báo giả mạo chính xác nhất.<br>• **Copy – Paste URL ra trình soạn thảo văn bản thuần (Notepad / Terminal)**: Khi sao chép địa chỉ `https://githúb.com/login` từ thanh địa chỉ và dán vào Notepad, trình duyệt sẽ tự động chuyển đổi tên miền Unicode sang chuỗi **Punycode** bắt đầu bằng `xn--` (`https://xn--githb-rva.com/login`), giúp lập trình viên phát hiện ngay lập tức. |

## 3. Minh họa kỹ thuật: Cách kiểm tra đúng trong Code (Python)

Để tránh lỗi bỏ sót ký tự Unicode giả mạo như trong hiện trường giả, đoạn mã kiểm tra URL cần kiểm tra xem tên miền có chứa ký tự ngoài bảng mã ASCII chuẩn hay không (hoặc đối chiếu Punycode với danh sách tên miền tin cậy):

```python
from urllib.parse import urlparse

TRUSTED_DOMAINS = {"github.com", " www.github.com"}

def verify_github_url(url: str) -> tuple[bool, str]:
    parsed = urlparse(url)
    hostname = parsed.hostname or ""
    
    # Chuyển tên miền sang dạng Punycode (IDNA encoding)
    punycode_host = hostname.encode("idna").decode("ascii")
    
    # Kiểm tra xem có chứa ký tự ngoài bảng ASCII (tiền tố xn--) hay không
    if not hostname.isascii() or punycode_host.startswith("xn--"):
        return False, f"CẢNH BÁO GIẢ MẠO (Homograph Attack): '{hostname}' thực chất là '{punycode_host}'"
    
    if hostname not in TRUSTED_DOMAINS:
        return False, f"Tên miền '{hostname}' không nằm trong danh sách tin cậy!"
        
    return True, "URL hợp lệ và an toàn."

# Thử nghiệm với URL giả mạo trong đề bài
is_safe, message = verify_github_url("https://githúb.com/login")
print(message)
# Kết quả: CẢNH BÁO GIẢ MẠO (Homograph Attack): 'githúb.com' thực chất là 'xn--githb-rva.com'
```
