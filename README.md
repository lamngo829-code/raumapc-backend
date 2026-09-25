# Rau Má PC — Website Quản Lý và Bán Linh Kiện PC

Đồ án cơ sở — Ngành Công nghệ thông tin, Trường Đại học Nguyễn Tất Thành
Sinh viên thực hiện: **Ngô Trường Lâm** — MSSV: **2400005472**

Hệ thống thương mại điện tử bán linh kiện máy tính, gồm 2 phần tách biệt:
- **backend/** — Node.js + Express REST API (triển khai trên Render)
- **frontend/** — HTML/CSS/JavaScript thuần, không dùng framework (triển khai trên Vercel)

---

## 1. Cấu trúc thư mục

```
Đồ_Án_Website_Quản_Lý_Và_Bán_Linh_Kiện_PC/
├── backend/                       (Node.js + Express REST API — deploy: Render)
│   ├── server.js                  (toàn bộ route, schema, middleware — 1 file duy nhất)
│   ├── __tests__/
│   │   └── orders.test.js         (18 test case tự động — Jest)
│   ├── .env                       (mẫu biến môi trường, xem bảng mục 3)
│   ├── package.json / package-lock.json
│   └── node_modules/              (cài qua npm install, không đưa lên Git)
│
└── frontend/                      (HTML/CSS/JS thuần — deploy: Vercel)
    ├── index.html                 (trang chủ)
    ├── 404.html
    ├── vercel.json                (cấu hình rewrite route cho Vercel)
    ├── admin/                     (trang quản trị — TÁCH RIÊNG, không nằm trong pages/)
    │   ├── admin.html
    │   ├── admin.css
    │   └── admin.js
    ├── pages/
    │   ├── shop/                  (25 trang: danh mục, chi tiết SP, giỏ hàng, build-pc...)
    │   ├── account/               (login, register, profile, orders)
    │   └── info/                  (18 trang: showroom, tin tức, khuyến mãi, bảo hành, B2B...)
    └── assets/
        ├── css/
        ├── js/
        └── images/
```

> **Lưu ý:** `admin/` là thư mục độc lập ngang cấp với `pages/`, KHÔNG phải thư mục con bên trong `pages/` — tách bạch rõ ràng giao diện khách hàng và giao diện quản trị ngay từ cấp thư mục.

---

## 2. Yêu cầu hệ thống (Prerequisites)

- **Node.js** phiên bản 18 trở lên (khuyến nghị 20 LTS) — tải tại https://nodejs.org
- **npm** (đi kèm sẵn khi cài Node.js)
- Một tài khoản **MongoDB Atlas** miễn phí https://cloud.mongodb.com để lấy chuỗi kết nối `MONGO_URI`
- *(Tuỳ chọn)* Tài khoản **Cloudinary**, **Google Cloud Console**, **VNPay Sandbox**, **EmailJS/Gmail** nếu muốn chạy đầy đủ toàn bộ tính năng nâng cao (upload ảnh, đăng nhập Google, thanh toán, gửi OTP)
- **Visual Studio Code** + tiện ích mở rộng **Live Server** (để chạy frontend cục bộ)

---

## 3. Bảng biến môi trường (`.env`) đầy đủ

Tạo file `backend/.env` (copy từ `.env.example`) và điền các biến sau:

| Biến môi trường | Bắt buộc? | Ý nghĩa / Cách lấy giá trị |
|---|---|---|
| `PORT` | Không | Cổng chạy server cục bộ (mặc định 3000) |
| `MONGO_URI` | **Có** | Chuỗi kết nối MongoDB Atlas — Atlas → Database → Connect → Drivers |
| `JWT_SECRET` | **Có** | Chuỗi bí mật tự đặt (bất kỳ), dùng ký/xác thực JWT |
| `ADMIN_PASS` | **Có** | Mật khẩu khởi tạo cho tài khoản Admin đầu tiên |
| `GOOGLE_CLIENT_ID` | Có (nếu dùng đăng nhập Google) | Google Cloud Console → APIs & Services → Credentials → OAuth Client ID |
| `CLOUDINARY_CLOUD_NAME` | Có (nếu upload ảnh) | Trang Dashboard của Cloudinary (cloudinary.com) |
| `CLOUDINARY_API_KEY` | Có (nếu upload ảnh) | Cùng trang Dashboard Cloudinary |
| `CLOUDINARY_API_SECRET` | Có (nếu upload ảnh) | Cùng trang Dashboard Cloudinary — **giữ bí mật, không commit lên Git** |
| `VNP_TMNCODE` | Có (nếu test thanh toán) | Mã Terminal do VNPay cấp khi đăng ký Sandbox tại sandbox.vnpayment.vn |
| `VNP_HASHSECRET` | Có (nếu test thanh toán) | Chuỗi bí mật VNPay cấp kèm TMNCODE, dùng ký HMAC-SHA512 |
| `EMAILJS_SERVICE_ID` / `EMAILJS_TEMPLATE_ID` / `EMAILJS_USER_ID` / `EMAILJS_TOKEN` | Có (nếu gửi OTP) | Tài khoản EmailJS (hoặc thay bằng Nodemailer + Gmail App Password) |
| `SENTRY_DSN` | Không | sentry.io nếu muốn bật giám sát lỗi; để trống vẫn chạy bình thường |
| `NODE_ENV` | Không | `development` khi chạy máy cá nhân, `production` khi triển khai thật |

---

## 4. Cài đặt và chạy Backend

```bash
# Bước 1 — Clone mã nguồn
git clone https://github.com/lamngo829-code/raumapc-backend.git
cd raumapc-backend

# Bước 2 — Cài đặt thư viện
npm install

# Bước 3 — Tạo file .env (copy từ .env.example rồi điền giá trị thật)
cp .env.example .env

# Bước 4 — Chạy server
npm start
# Nếu thành công, terminal hiện dòng: "Đã kết nối MongoDB!"
# và server chạy tại http://localhost:3000
```

## 5. Chạy Frontend

1. Mở thư mục `frontend/` bằng VS Code.
2. Chuột phải vào file `pages/shop/index.html` (hoặc trang muốn xem) → **"Open with Live Server"**.
3. Trong file cấu hình API của frontend (`assets/js/config.js` hoặc tương tự), trỏ biến `API_URL` về `http://localhost:3000` khi chạy cục bộ.

## 6. Chạy bộ kiểm thử tự động

```bash
cd backend
npm test
# Kết quả mong đợi: "Tests: 18 passed, 18 total"
```

> Lần chạy đầu tiên, `mongodb-memory-server` cần tải một bản MongoDB Community Server thật (~100MB) về máy — cần có Internet, mất khoảng 1–3 phút tuỳ mạng. Các lần chạy sau sẽ nhanh hơn nhiều vì đã có bản tải sẵn.

---

## 7. Một số lỗi thường gặp

| Lỗi | Nguyên nhân / Cách khắc phục |
|---|---|
| `MongooseServerSelectionError` | Sai `MONGO_URI`, hoặc chưa thêm IP máy hiện tại vào **Network Access** trên MongoDB Atlas |
| `Error: Cannot find module ...` | Quên chạy `npm install`, hoặc chạy lệnh sai thư mục (phải đứng trong `backend/`) |
| Đăng nhập Google báo lỗi | Thiếu `GOOGLE_CLIENT_ID`, hoặc domain chạy thử chưa thêm vào **Authorized JavaScript origins** trong Google Cloud Console |
| Thanh toán VNPay không redirect được | Sai `VNP_TMNCODE`/`VNP_HASHSECRET`, hoặc chưa cấu hình đúng URL return trong tài khoản Sandbox VNPay |
| `npm test` treo ở bước khởi tạo | Lần đầu chạy cần Internet để `mongodb-memory-server` tự tải MongoDB thật (~100MB) |

---

## 8. Danh sách API chính

```
Xác thực:   POST /api/register, /api/login, /api/auth/google, /api/request-otp
Sản phẩm:   GET/POST/PUT/DELETE /api/products, /api/products/:id/comments
Đơn hàng:   POST/GET /api/orders, GET /api/orders/my, /api/orders/track,
            PUT /api/orders/:id/status, DELETE /api/orders/:id
Thanh toán: POST /api/vnpay/create_url, GET /api/vnpay/ipn, /api/vnpay/verify-return
Quản trị:   GET /api/admin/revenue, /api/admin/revenue-chart, CRUD /api/coupons
Health:     GET /api/health
```

---

## 9. Liên kết

- Backend: https://github.com/lamngo829-code/raumapc-backend
- Frontend: https://github.com/lamngo829-code/raumapc-frontend
- Website demo: https://raumapc-frontend.vercel.app
- API backend demo: https://raumapc-backend-fms3.onrender.com
- Video demo: https://drive.google.com/file/d/1Kl05VQrOSC1hNZZZo5pHyv3COlpj5mjZ/view?usp=drive_link
