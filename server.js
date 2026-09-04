require('dotenv').config();
const express = require('express');
const cors = require('cors');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs'); 
const jwt = require('jsonwebtoken'); 

const app = express();
app.use(cors());
// Tăng giới hạn dung lượng tải lên cho ảnh Base64 lên 50MB
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ limit: '50mb', extended: true }));

const JWT_SECRET = process.env.JWT_SECRET;

// ==========================================
// 1. KẾT NỐI MONGODB
// ==========================================
mongoose.connect(process.env.MONGO_URI)
    .then(() => console.log('✅ Đã kết nối MongoDB!'))
    .catch(err => console.error('❌ Lỗi kết nối MongoDB:', err));

// ==========================================
// 2. KHUÔN MẪU DỮ LIỆU (ĐÃ TÁCH BIỆT ADMIN VÀ USER)
// ==========================================
// Khuôn Sản phẩm
const productSchema = new mongoose.Schema({
    name: String, price: String, img: String, warranty: String,
    specs: String, description: String, category: String, brand: String,
    comments: { type: Array, default: [] } // <-- KHO CHỨA BÌNH LUẬN
});
productSchema.index({ name: 'text' }); 
const Product = mongoose.model('Product', productSchema);

// Khuôn Đơn hàng
const orderSchema = new mongoose.Schema({
    orderId: String, date: String, username: String, account: String,
    email: String, items: Array, total: Number, status: String
});
const Order = mongoose.model('Order', orderSchema);

// Khuôn Khách hàng (User) - Nằm ở Collection "users"
const userSchema = new mongoose.Schema({
    fullName: { type: String, required: true },
    username: { type: String, unique: true, required: true },
    password: { type: String, required: true },
    phone: { type: String, required: true }, 
    email: { type: String, required: true }, 
    role: { type: String, default: 'user' },
    cart: { type: Array, default: [] },
    createdAt: { type: Date, default: Date.now } // Thêm trường lưu ngày tạo
});
const User = mongoose.model('User', userSchema);

// MỚI: Khuôn Quản trị viên (Admin) - Nằm ở Collection riêng "admins"
const adminSchema = new mongoose.Schema({
    fullName: { type: String, required: true },
    username: { type: String, unique: true, required: true },
    password: { type: String, required: true },
    role: { type: String, default: 'admin' }
});
const Admin = mongoose.model('Admin', adminSchema);

// ==========================================
// CỬA AN NINH (MIDDLEWARE)
// ==========================================
const verifyToken = (req, res, next) => {
    const token = req.headers['authorization'];
    if (!token) return res.status(403).json({ message: "Bạn chưa đăng nhập!" });
    try {
        const decoded = jwt.verify(token.split(" ")[1], JWT_SECRET);
        req.user = decoded; 
        next();
    } catch (err) { return res.status(401).json({ message: "Phiên đăng nhập hết hạn!" }); }
};

// ==========================================
// API BÍ MẬT: TẠO TÀI KHOẢN ADMIN ĐẦU TIÊN TỰ ĐỘNG
// ==========================================
app.get('/api/setup-admin', async (req, res) => {
    try {
        const existingAdmin = await Admin.findOne({ username: 'admin' });
        if (existingAdmin) return res.send("<h3>Tài khoản Admin đã tồn tại trong Database!</h3>");

        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(process.env.ADMIN_PASS, salt);

        const newAdmin = new Admin({
            fullName: "Tổng Giám Đốc Rau Má",
            username: "admin",
            password: hashedPassword,
            role: "admin"
        });
        await newAdmin.save();
        res.send("<h3>✅ Đã khởi tạo biệt thự Admin thành công!</h3><p>Tài khoản: <b>admin</b></p><p>Mật khẩu: <b>Lamngo@395508622</b></p><p>Vui lòng đăng nhập trên website!</p>");
    } catch (err) { res.status(500).send("Lỗi hệ thống: " + err.message); }
});

// --- 1. GỬI MÃ OTP ĐỂ XÁC NHẬN ĐĂNG KÝ ---
app.post('/api/request-register-otp', async (req, res) => {
    try {
        const { email, username } = req.body;
        
        const existingUser = await User.findOne({ $or: [{ email: email }, { username: username }] });
        if (existingUser) return res.status(400).json({ success: false, message: "Email hoặc Tên đăng nhập đã được sử dụng!" });

        const otpCode = Math.floor(100000 + Math.random() * 900000).toString();
        otpCache[email] = { code: otpCode, expiresAt: Date.now() + 60000 };

        const htmlContent = `
        <div style="font-family: Arial; padding: 20px; border: 1px solid #eee; border-radius: 10px;">
            <h2 style="color: #1435c3;">MÃ OTP XÁC NHẬN ĐĂNG KÝ TÀI KHOẢN</h2>
            <p>Chào bạn,</p>
            <div style="background: #f4f7fe; padding: 15px; text-align: center; border-radius: 8px; margin: 20px 0;">
                <p>Mã xác nhận 6 số để tạo tài khoản Rau Má PC của bạn là:</p>
                <h1 style="color: #d70018; letter-spacing: 5px;">${otpCode}</h1>
            </div>
            <p style="color: #d70018; font-weight: bold;">⚠️ Mã này chỉ có hiệu lực trong đúng 60 GIÂY.</p>
        </div>`;

        const emailData = {
            service_id: process.env.EMAILJS_SERVICE_ID, 
            template_id: process.env.EMAILJS_TEMPLATE_ID, 
            user_id: process.env.EMAILJS_USER_ID, 
            accessToken: process.env.EMAILJS_TOKEN,
            template_params: { to_email: email, subject: '[Rau Má PC] Mã OTP Đăng Ký Tài Khoản', message: htmlContent }
        };

        fetch('https://api.emailjs.com/api/v1.0/email/send', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(emailData) }).catch(e=>console.log(e));

        res.json({ success: true, message: "Mã OTP đăng ký đã được gửi đến Email!" });
    } catch (err) { res.status(500).json({ success: false, message: "Lỗi hệ thống!" }); }
});

// --- 2. API ĐĂNG KÝ CHÍNH THỨC (PHẢI CÓ OTP) ---
app.post('/api/register', async (req, res) => {
    try {
        const { fullName, username, password, phone, email, otp } = req.body;
        
        const cached = otpCache[email];
        if (!cached) return res.status(400).json({ success: false, message: "Vui lòng ấn gửi mã OTP trước!" });
        if (Date.now() > cached.expiresAt) return res.status(400).json({ success: false, message: "Mã OTP đã HẾT HẠN (quá 60s)! Vui lòng đăng ký lại." });
        if (cached.code !== otp) return res.status(400).json({ success: false, message: "Mã OTP không chính xác!" });

        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);

        const newUser = new User({ fullName, username, password: hashedPassword, phone, email });
        await newUser.save();
        
        delete otpCache[email]; 
        res.json({ success: true, message: "Đăng ký thành công!" });
    } catch (err) { res.status(500).json({ success: false, message: "Lỗi máy chủ!" }); }
});

// --- 3. API ĐĂNG NHẬP (BẰNG USERNAME HOẶC EMAIL ĐỀU ĐƯỢC) ---
app.post('/api/login', async (req, res) => {
    try {
        const loginId = req.body.username; 

        let user = await User.findOne({ $or: [{ username: loginId }, { email: loginId }] });
        let isRole = 'user';

        if (!user) {
            user = await Admin.findOne({ username: loginId });
            isRole = 'admin';
        }

        if (!user) return res.status(401).json({ success: false, message: "Sai tài khoản hoặc Email!" });

        const isMatch = await bcrypt.compare(req.body.password, user.password);
        if (!isMatch) return res.status(401).json({ success: false, message: "Sai mật khẩu!" });

        const token = jwt.sign({ id: user._id, username: user.username, role: isRole }, JWT_SECRET, { expiresIn: '7d' });
        
        const userData = { username: user.username, fullName: user.fullName, role: isRole };
        if (isRole === 'user') {
            userData.email = user.email; 
            userData.phone = user.phone; 
            userData.cart = user.cart;
            userData.createdAt = user.createdAt; // Gửi ngày tạo về cho giao diện web
        }

        res.json({ success: true, token, user: userData });
    } catch (err) { res.status(500).json({ success: false, message: "Lỗi máy chủ!" }); }
});


// ==========================================
// HỆ THỐNG BẢO MẬT MẬT KHẨU (MÃ OTP 60 GIÂY)
// ==========================================
const otpCache = {}; // Bộ đệm lưu mã OTP tạm thời

// 1. API Gửi mã OTP 6 số (Dùng chung)
app.post('/api/request-otp', async (req, res) => {
    try {
        const { email } = req.body;
        const user = await User.findOne({ email: email });
        if (!user) return res.status(404).json({ success: false, message: "Email không tồn tại!" });

        // Tạo mã 6 số ngẫu nhiên & Canh thời gian 60 giây
        const otpCode = Math.floor(100000 + Math.random() * 900000).toString();
        otpCache[email] = {
            code: otpCode,
            expiresAt: Date.now() + 60000 
        };

        const htmlContent = `
        <div style="font-family: Arial; padding: 20px; border: 1px solid #eee; border-radius: 10px;">
            <h2 style="color: #1435c3;">MÃ XÁC NHẬN BẢO MẬT (OTP)</h2>
            <p>Chào <strong>${user.fullName}</strong>,</p>
            <div style="background: #f4f7fe; padding: 15px; text-align: center; border-radius: 8px; margin: 20px 0;">
                <p>Mã xác nhận 6 số của bạn là:</p>
                <h1 style="color: #d70018; letter-spacing: 5px;">${otpCode}</h1>
            </div>
            <p style="color: #d70018; font-weight: bold;">⚠️ Mã này chỉ có hiệu lực trong đúng 60 GIÂY.</p>
            <p>Nếu bạn không thực hiện yêu cầu này, vui lòng bỏ qua email.</p>
        </div>`;

        const emailData = {
            service_id: process.env.EMAILJS_SERVICE_ID, 
            template_id: process.env.EMAILJS_TEMPLATE_ID, 
            user_id: process.env.EMAILJS_USER_ID, 
            accessToken: process.env.EMAILJS_TOKEN,
            template_params: { to_email: user.email, subject: '[Rau Má PC] Mã OTP Xác Nhận Bảo Mật', message: htmlContent }
        };

        fetch('https://api.emailjs.com/api/v1.0/email/send', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(emailData) }).catch(e=>console.log(e));

        res.json({ success: true, message: "Mã OTP đã được gửi đến Email. Mã sẽ hết hạn sau 60 giây!" });
    } catch (err) { res.status(500).json({ success: false, message: "Lỗi hệ thống!" }); }
});

// 2. API Đặt lại mật khẩu mới (Quên mật khẩu)
app.post('/api/forgot-password-verify', async (req, res) => {
    try {
        const { email, otp, newPassword } = req.body;
        const cached = otpCache[email];

        if (!cached) return res.status(400).json({ success: false, message: "Vui lòng ấn gửi mã OTP trước!" });
        if (Date.now() > cached.expiresAt) return res.status(400).json({ success: false, message: "Mã OTP đã HẾT HẠN (quá 60s)! Vui lòng gửi lại mã." });
        if (cached.code !== otp) return res.status(400).json({ success: false, message: "Mã OTP không chính xác!" });

        const user = await User.findOne({ email: email });
        const salt = await bcrypt.genSalt(10);
        user.password = await bcrypt.hash(newPassword, salt);
        await user.save();
        
        delete otpCache[email]; // Hủy mã OTP ngay sau khi dùng thành công
        res.json({ success: true, message: "Khôi phục mật khẩu thành công! Bạn đã có thể đăng nhập." });
    } catch (err) { res.status(500).json({ success: false, message: "Lỗi hệ thống!" }); }
});

// 3. API Đổi mật khẩu từ tài khoản (Có OTP)
app.post('/api/change-password-verify', verifyToken, async (req, res) => {
    try {
        const { oldPassword, newPassword, otp, email } = req.body;
        const cached = otpCache[email];

        if (!cached) return res.status(400).json({ success: false, message: "Vui lòng ấn gửi mã OTP trước!" });
        if (Date.now() > cached.expiresAt) return res.status(400).json({ success: false, message: "Mã OTP đã HẾT HẠN (quá 60s)! Vui lòng gửi lại mã." });
        if (cached.code !== otp) return res.status(400).json({ success: false, message: "Mã OTP không chính xác!" });

        let user = await User.findById(req.user.id);
        if (!user) user = await Admin.findById(req.user.id);

        const isMatch = await bcrypt.compare(oldPassword, user.password);
        if (!isMatch) return res.status(400).json({ success: false, message: "Mật khẩu cũ không chính xác!" });

        const salt = await bcrypt.genSalt(10);
        user.password = await bcrypt.hash(newPassword, salt);
        await user.save();

        delete otpCache[email];
        res.json({ success: true, message: "Đổi mật khẩu thành công! Vui lòng đăng nhập lại." });
    } catch (err) { res.status(500).json({ success: false, message: "Lỗi hệ thống!" }); }
});


// ==========================================
// 4. API SẢN PHẨM & TÌM KIẾM
// ==========================================
app.get('/api/products', async (req, res) => {
    try { 
        const products = await Product.find();
        
        // ĐÓNG GÓI LẠI DỮ LIỆU: Đổi _id của MongoDB thành id cho Giao diện web hiểu
        const formattedProducts = products.map(sp => ({
            id: sp._id.toString(),
            name: sp.name,
            price: sp.price,
            img: sp.img,
            warranty: sp.warranty,
            category: sp.category,
            brand: sp.brand, // Dạy máy chủ gửi brand về cho web
            specs: sp.specs,
            description: sp.description,
            comments: sp.comments // <-- BỔ SUNG DÒNG NÀY ĐỂ TRẢ VỀ BÌNH LUẬN KHI F5
        }));
        
        res.json(formattedProducts); 
    } catch (err) { 
        res.status(500).json({ message: "Lỗi Server" }); 
    }
});

// ==========================================
// CÁC API THÊM, SỬA, XÓA SẢN PHẨM TỪ ADMIN
// ==========================================
// 1. Thêm sản phẩm mới
app.post('/api/products', async (req, res) => {
    try {
        const newProduct = new Product(req.body);
        await newProduct.save();
        res.json({ message: "Thêm sản phẩm thành công!" });
    } catch (err) { 
        res.status(500).json({ message: "Lỗi lưu sản phẩm!" }); 
    }
});

// 2. Cập nhật sản phẩm
app.put('/api/products/:id', async (req, res) => {
    try {
        await Product.findByIdAndUpdate(req.params.id, req.body);
        res.json({ message: "Cập nhật thành công!" });
    } catch (err) { 
        res.status(500).json({ message: "Lỗi cập nhật!" }); 
    }
});

// 3. Xóa sản phẩm
app.delete('/api/products/:id', async (req, res) => {
    try {
        await Product.findByIdAndDelete(req.params.id);
        res.json({ message: "Xóa thành công!" });
    } catch (err) { 
        res.status(500).json({ message: "Lỗi xóa sản phẩm!" }); 
    }
});

// ==========================================
// 5. API ĐƠN HÀNG, DOANH THU & GỬI MAIL HÓA ĐƠN
// ==========================================
app.post('/api/orders', async (req, res) => {
    try {
        const newOrder = new Order(req.body);
        await newOrder.save();

        // 1. Phân tách lại Tên, SĐT, Địa chỉ từ chuỗi username để đưa vào bảng
        let cusName = newOrder.username;
        let cusPhone = "Đang cập nhật";
        let cusAddress = "Đang cập nhật";
        const match = newOrder.username.match(/(.+?)\s*\((.+?)\s*-\s*(.+)\)/);
        if (match) { 
            cusName = match[1]; 
            cusPhone = match[2]; 
            cusAddress = match[3]; 
        }

        // 2. Tạo danh sách sản phẩm y như code cũ
        let itemsHtml = "";
        newOrder.items.forEach(item => {
            let priceNum = parseInt(String(item.price).replace(/\D/g, '')) || 0;
            let qtyNum = parseInt(item.quantity) || 1;
            let itemTotal = priceNum * qtyNum;
            itemsHtml += `
            <tr>
                <td style="padding: 12px 10px 12px 0; border-bottom: 1px solid #eee; color: #555; font-size: 14px;">${item.name}</td>
                <td style="padding: 12px 10px; border-bottom: 1px solid #eee; text-align: center; color: #555; font-size: 14px;">${qtyNum}</td>
                <td style="padding: 12px 0 12px 10px; border-bottom: 1px solid #eee; text-align: right; color: #d70018; font-weight: bold; font-size: 14px;">${new Intl.NumberFormat('vi-VN').format(itemTotal)}đ</td>
            </tr>`;
        });

        let formattedTotal = new Intl.NumberFormat('vi-VN').format(newOrder.total) + ' đ';

        // 3. Khôi phục TOÀN BỘ giao diện HTML gốc của bạn
        const headerSubtitle = "Đơn hàng đang chờ duyệt";
        const statusTitle = "ĐƠN HÀNG ĐANG CHỜ DUYỆT";
        const statusMessage = "Cảm ơn bạn đã tin tưởng và mua sắm tại hệ thống Rau Má PC. Đơn hàng của bạn đã được hệ thống ghi nhận và đang chờ duyệt!";
        const color = "#2980b9"; 
        const bgColor = "#ebf5fb"; 

        const fullHtmlContent = `
        <div style="font-family: 'Segoe UI', Arial, sans-serif; max-width: 600px; margin: 0 auto; border: 1px solid #eaebec; border-radius: 12px; overflow: hidden; box-shadow: 0 8px 20px rgba(0,0,0,0.04);">
            
            <!-- HEADER -->
            <div style="background: linear-gradient(135deg, #1435c3 0%, #0a1b66 100%); padding: 30px 20px; text-align: center;">
                <table align="center" border="0" cellpadding="0" cellspacing="0" style="margin: 0 auto;">
                    <tr>
                        <td style="padding-right: 18px; vertical-align: middle;">
                            <img src="https://github.com/lamngo829-code/raumapc-backend/blob/main/logo-sticky.jpg?raw=true" alt="Logo Rau Má" style="width: 75px; height: auto; display: block; border-radius: 4px;">
                        </td>
                        <td style="vertical-align: middle; text-align: left;">
                            <h1 style="margin: 0; font-size: 28px; font-weight: bold; letter-spacing: 1.5px; color: #ffffff;">RAU MÁ PC</h1>
                            <p style="margin: 5px 0 0; font-size: 15px; color: #cbd5e1;">${headerSubtitle}</p>
                        </td>
                    </tr>
                </table>
            </div>
            
            <!-- NỘI DUNG CHÍNH -->
            <div style="padding: 40px 30px; background-color: #ffffff; color: #333333;">
                <p style="font-size: 15px; margin-top: 0; margin-bottom: 20px;">Chào <strong>${cusName}</strong>,</p>

                <!-- HỘP THÔNG BÁO PASTEL -->
                <div style="background-color: ${bgColor}; padding: 20px; border-radius: 8px; text-align: center; margin: 20px 0; border: 1px solid ${color}40;">
                    <h3 style="color: ${color}; margin: 0 0 10px 0; font-size: 16px; font-weight: bold; text-transform: uppercase;">${statusTitle}</h3>
                    <p style="color: #444; margin: 0; line-height: 1.6; font-size: 14px;">${statusMessage}</p>
                </div>

                <h3 style="color: #1435c3; border-bottom: 2px solid #f4f7fe; padding-bottom: 8px; margin-top: 30px; font-size: 15px;">Thông Tin Nhận Hàng (Mã đơn: #${newOrder.orderId})</h3>
                <table style="width: 100%; font-size: 14px; line-height: 1.8; color: #444;">
                    <tr><td style="width: 110px; font-weight: bold;">Người nhận:</td><td>${cusName}</td></tr>
                    <tr><td style="font-weight: bold;">Số điện thoại:</td><td>${cusPhone}</td></tr>
                    <tr><td style="font-weight: bold;">Địa chỉ:</td><td>${cusAddress}</td></tr>
                </table>

                <h3 style="color: #1435c3; border-bottom: 2px solid #f4f7fe; padding-bottom: 8px; margin-top: 30px; font-size: 15px;">Chi Tiết Sản Phẩm</h3>
                <table style="width: 100%; border-collapse: collapse; font-size: 14px;">
                    <thead>
                        <tr style="background-color: #f4f7fe; color: #2b3674;">
                            <th style="padding: 10px; text-align: left; border-radius: 6px 0 0 6px;">Tên sản phẩm</th>
                            <th style="padding: 10px; text-align: center;">SL</th>
                            <th style="padding: 10px; text-align: right; border-radius: 0 6px 6px 0;">Thành tiền</th>
                        </tr>
                    </thead>
                    <tbody>
                        ${itemsHtml}
                    </tbody>
                </table>

                <div style="text-align: right; margin-top: 25px; padding-top: 15px; border-top: 2px dashed #eee;">
                    <span style="font-size: 14px; color: #555;">Tổng thanh toán:</span>
                    <strong style="color: #d70018; font-size: 24px; margin-left: 10px;">${formattedTotal}</strong>
                </div>
            </div>

            <!-- FOOTER -->
            <div style="background-color: #f8f9fa; padding: 25px 20px; text-align: center; font-size: 13px; color: #777777; border-top: 1px solid #eeeeee;">
                <p style="margin: 0 0 8px 0; font-weight: bold; color: #333333; font-size: 14px;">CÔNG TY TNHH MÁY TÍNH RAU MÁ</p>
                <p style="margin: 4px 0;">Hotline: <strong style="color: #1435c3;">1900 3636</strong> | Email: cskh@raumapc.com</p>
                <p style="margin: 4px 0 0;">Địa chỉ: An Phú Đông, Quận 12, TP. Hồ Chí Minh</p>
            </div>
        </div>`;

        // 4. Gửi email ẩn danh thông qua các biến bảo mật .env
        const emailData = {
            service_id: process.env.EMAILJS_SERVICE_ID,
            template_id: process.env.EMAILJS_TEMPLATE_ID,
            user_id: process.env.EMAILJS_USER_ID,
            accessToken: process.env.EMAILJS_TOKEN,
            template_params: {
                to_email: newOrder.email,
                subject: `[Rau Má PC] Đơn hàng #${newOrder.orderId} đang chờ xác nhận`,
                message: fullHtmlContent
            }
        };

        fetch('https://api.emailjs.com/api/v1.0/email/send', {
            method: 'POST', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(emailData)
        }).catch(err => console.log("Lỗi gửi mail tự động:", err));

        res.json({ message: "Đặt hàng thành công!" });
    } catch (error) { res.status(500).json({ message: "Lỗi khi lưu đơn!" }); }
});

// API Lấy danh sách toàn bộ đơn hàng
app.get('/api/orders', async (req, res) => {
    try { res.json(await Order.find()); } catch (err) { res.status(500).json({ message: "Lỗi!" }); }
});

// API Thống kê doanh thu cho Admin
app.get('/api/admin/revenue', async (req, res) => {
    try {
        const revenue = await Order.aggregate([
            { $match: { status: "Hoàn thành" } },
            { $group: { _id: null, totalRevenue: { $sum: "$total" }, totalOrders: { $sum: 1 } } }
        ]);
        res.json(revenue[0] || { totalRevenue: 0, totalOrders: 0 });
    } catch (err) { res.status(500).json({ message: "Lỗi thống kê!" }); }
});

// ==========================================
// 6. API ĐỒNG BỘ GIỎ HÀNG CLOUD
// ==========================================
app.put('/api/users/cart', verifyToken, async (req, res) => {
    try {
        await User.findByIdAndUpdate(req.user.id, { cart: req.body.cart });
        res.json({ success: true, message: "Đã đồng bộ giỏ hàng" });
    } catch (err) { res.status(500).json({ success: false, message: "Lỗi đồng bộ" }); }
});

// ==========================================
// 7. API ĐỔI TRẠNG THÁI & GỬI EMAIL VƯỢT TƯỜNG LỬA
// ==========================================
app.put('/api/orders/:id/status', async (req, res) => {
    try {
        const order = await Order.findOneAndUpdate(
            { orderId: req.params.id }, 
            { status: req.body.status }, 
            { returnDocument: 'after' }
        );
        
        let statusTitle = ""; let statusMessage = ""; let color = ""; let bgColor = ""; let emailSubject = ""; let headerSubtitle = "";
        
        if (order.status === "Đang giao hàng") {
            emailSubject = `[Rau Má PC] Đơn hàng #${order.orderId} đang được giao đến bạn`;
            headerSubtitle = "Đơn hàng đang được giao";
            statusTitle = "ĐƠN HÀNG ĐANG ĐƯỢC GIAO";
            statusMessage = "Tuyệt vời! Đơn hàng của bạn đã được bàn giao cho đơn vị vận chuyển và đang trên đường đến với bạn. Vui lòng chú ý điện thoại để nhận hàng nhé!";
            color = "#f39c12"; bgColor = "#fdf8e4"; 
        } else if (order.status === "Hoàn thành") {
            emailSubject = `[Rau Má PC] Đơn hàng #${order.orderId} đã giao thành công`;
            headerSubtitle = "Giao hàng thành công";
            statusTitle = "GIAO HÀNG THÀNH CÔNG";
            statusMessage = "Đơn hàng của bạn đã được giao thành công. Rau Má PC rất cảm ơn bạn đã tin tưởng và ủng hộ. Chúc bạn có những trải nghiệm tuyệt vời cùng dàn máy của mình!";
            color = "#27ae60"; bgColor = "#eafaf1"; 
        } else if (order.status === "Đã hủy") {
            emailSubject = `[Rau Má PC] Đơn hàng #${order.orderId} đã bị hủy`;
            headerSubtitle = "Đơn hàng đã hủy";
            statusTitle = "ĐƠN HÀNG ĐÃ HỦY";
            statusMessage = "Đơn hàng của bạn đã bị hủy trên hệ thống. Nếu có bất kỳ thắc mắc nào hoặc muốn đặt lại hàng, hãy liên hệ ngay với Rau Má PC nhé!";
            color = "#e74c3c"; bgColor = "#fdedec"; 
        } else {
            emailSubject = `[Rau Má PC] Đơn hàng #${order.orderId} đang chờ xác nhận`;
            headerSubtitle = "Đơn hàng đang chờ duyệt";
            statusTitle = "ĐƠN HÀNG ĐANG CHỜ DUYỆT";
            statusMessage = "Cảm ơn bạn đã tin tưởng và mua sắm tại hệ thống Rau Má PC. Đơn hàng của bạn đã được hệ thống ghi nhận và đang chờ duyệt!";
            color = "#2980b9"; bgColor = "#ebf5fb"; 
        }

        let cusName = order.username;
        let cusPhone = "Đang cập nhật";
        let cusAddress = "Đang cập nhật";
        const match = order.username.match(/(.+?)\s*\((.+?)\s*-\s*(.+)\)/);
        if (match) { cusName = match[1]; cusPhone = match[2]; cusAddress = match[3]; }

        let itemsHtml = "";
        if (order.items && order.items.length > 0) {
            order.items.forEach(item => {
                let priceNum = parseInt(String(item.price).replace(/\D/g, '')) || 0;
                let qtyNum = parseInt(item.quantity) || 1;
                itemsHtml += `
                <tr>
                    <td style="padding: 12px 10px 12px 0; border-bottom: 1px solid #eee; color: #555; font-size: 14px;">${item.name}</td>
                    <td style="padding: 12px 10px; border-bottom: 1px solid #eee; text-align: center; color: #555; font-size: 14px;">${qtyNum}</td>
                    <td style="padding: 12px 0 12px 10px; border-bottom: 1px solid #eee; text-align: right; color: #d70018; font-weight: bold; font-size: 14px;">${new Intl.NumberFormat('vi-VN').format(priceNum * qtyNum)}đ</td>
                </tr>`;
            });
        }

        const htmlContent = `
        <div style="font-family: 'Segoe UI', Arial, sans-serif; max-width: 600px; margin: 0 auto; border: 1px solid #e0e0e0; overflow: hidden; box-shadow: 0 4px 15px rgba(0,0,0,0.05); border-radius: 8px;">
            <div style="background-color: #1435c3; padding: 25px 20px; text-align: center;">
                <table align="center" border="0" cellpadding="0" cellspacing="0" style="margin: 0 auto;">
                    <tr>
                        <td style="padding-right: 15px; vertical-align: middle;">
                            <img src="https://github.com/lamngo829-code/raumapc-backend/blob/main/logo-sticky.jpg?raw=true" alt="Logo" style="width: 65px; height: 65px; object-fit: cover; border-radius: 50%; box-shadow: 0 2px 10px rgba(0,0,0,0.2); display: block;">
                        </td>
                        <td style="vertical-align: middle; text-align: left;">
                            <h1 style="margin: 0; font-size: 28px; letter-spacing: 1px; color: #ffffff;">RAU MÁ PC</h1>
                            <p style="margin: 5px 0 0; font-size: 15px; opacity: 0.9; color: #ffffff;">${headerSubtitle}</p>
                        </td>
                    </tr>
                </table>
            </div>
            <div style="padding: 30px 20px; background-color: #ffffff; color: #333333;">
                <p style="font-size: 15px; margin-top: 0; margin-bottom: 20px;">Chào <strong>${cusName}</strong>,</p>
                <div style="background-color: ${bgColor}; padding: 20px; border-radius: 8px; text-align: center; margin: 20px 0; border: 1px solid ${color}40;">
                    <h3 style="color: ${color}; margin: 0 0 10px 0; font-size: 16px; font-weight: bold; text-transform: uppercase;">${statusTitle}</h3>
                    <p style="color: #444; margin: 0; line-height: 1.6; font-size: 14px;">${statusMessage}</p>
                </div>
                <h3 style="color: #1435c3; border-bottom: 2px solid #f4f7fe; padding-bottom: 8px; margin-top: 30px; font-size: 15px;">Thông Tin Nhận Hàng (Mã đơn: #${order.orderId})</h3>
                <table style="width: 100%; font-size: 14px; line-height: 1.8; color: #444;">
                    <tr><td style="width: 110px; font-weight: bold;">Người nhận:</td><td>${cusName}</td></tr>
                    <tr><td style="font-weight: bold;">Số điện thoại:</td><td>${cusPhone}</td></tr>
                    <tr><td style="font-weight: bold;">Địa chỉ:</td><td>${cusAddress}</td></tr>
                </table>
                <h3 style="color: #1435c3; border-bottom: 2px solid #f4f7fe; padding-bottom: 8px; margin-top: 30px; font-size: 15px;">Chi Tiết Sản Phẩm</h3>
                <table style="width: 100%; border-collapse: collapse; font-size: 14px;">
                    <thead><tr style="background-color: #f4f7fe; color: #2b3674;"><th style="padding: 10px; text-align: left; border-radius: 6px 0 0 6px;">Tên sản phẩm</th><th style="padding: 10px; text-align: center;">SL</th><th style="padding: 10px; text-align: right; border-radius: 0 6px 6px 0;">Thành tiền</th></tr></thead>
                    <tbody>${itemsHtml}</tbody>
                </table>
                <div style="text-align: right; margin-top: 25px; padding-top: 15px; border-top: 2px dashed #eee;">
                    <span style="font-size: 14px; color: #555;">Tổng thanh toán:</span>
                    <strong style="color: #d70018; font-size: 22px; margin-left: 10px;">${new Intl.NumberFormat('vi-VN').format(order.total)} đ</strong>
                </div>
            </div>
            <div style="background-color: #f9f9f9; padding: 20px; text-align: center; font-size: 12px; color: #777777; border-top: 1px solid #eeeeee;">
                <p style="margin: 0; font-weight: bold; color: #333; font-size: 13px;">CÔNG TY TNHH MÁY TÍNH RAU MÁ</p>
                <p style="margin: 6px 0 0;">Hotline: 1900 3636 | Email: <a href="mailto:cskh@raumapc.com" style="color: #1435c3; text-decoration: none;">cskh@raumapc.com</a></p>
                <p style="margin: 6px 0 0;">Địa chỉ: An Phú Đông, Quận 12, TP. Hồ Chí Minh</p>
            </div>
        </div>`;

        const emailData = {
            service_id: process.env.EMAILJS_SERVICE_ID,
            template_id: process.env.EMAILJS_TEMPLATE_ID, 
            user_id: process.env.EMAILJS_USER_ID,
            accessToken: process.env.EMAILJS_TOKEN, 
            template_params: {
                to_email: order.email,
                subject: emailSubject, 
                message: htmlContent
            }
        };

        fetch('https://api.emailjs.com/api/v1.0/email/send', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(emailData)
        }).catch(err => console.log(err));

        res.json({ message: "Cập nhật và gửi thông báo cho khách thành công!" });
    } catch (err) { res.status(500).json({ message: "Lỗi hệ thống!" }); }
});

// ==========================================
// 9. API THÊM BÌNH LUẬN VÀO SẢN PHẨM
// ==========================================
app.post('/api/products/:id/comments', async (req, res) => {
    try {
        const { userName, content, rating, img } = req.body;
        const product = await Product.findById(req.params.id);
        if (!product) return res.status(404).json({ success: false, message: "Sản phẩm không tồn tại!" });

        const newComment = {
            id: Date.now().toString(),
            userName: userName || "Khách",
            content: content,
            rating: rating || 5,
            img: img || null,
            date: new Date().toLocaleDateString('vi-VN') + ' ' + new Date().toLocaleTimeString('vi-VN', {hour: '2-digit', minute:'2-digit'})
        };

        product.comments.push(newComment);
        await product.save();
        res.json({ success: true, message: "Đã gửi bình luận!", comments: product.comments });
    } catch (err) { res.status(500).json({ success: false, message: "Lỗi máy chủ!" }); }
});

app.listen(process.env.PORT || 3000, () => console.log(`✅ Máy chủ đang chạy ở chuẩn bảo mật Doanh Nghiệp`));


// ==========================================
// 8. API CẬP NHẬT THÔNG TIN LIÊN HỆ & EMAIL (CÓ XÁC THỰC OTP)
// ==========================================

// --- GỬI MÃ OTP XÁC NHẬN ĐỔI EMAIL MỚI ---
app.post('/api/request-email-update-otp', verifyToken, async (req, res) => {
    try {
        const { newEmail } = req.body;
        
        // Kiểm tra xem email mới đã có người dùng chưa
        const existingEmail = await User.findOne({ email: newEmail });
        if (existingEmail) return res.status(400).json({ success: false, message: "Email này đã được đăng ký bởi tài khoản khác!" });

        // Tạo mã 6 số & Hẹn giờ 60 giây
        const otpCode = Math.floor(100000 + Math.random() * 900000).toString();
        otpCache[newEmail] = { code: otpCode, expiresAt: Date.now() + 60000 };

        const htmlContent = `
        <div style="font-family: Arial; padding: 20px; border: 1px solid #eee; border-radius: 10px;">
            <h2 style="color: #1435c3;">XÁC NHẬN THAY ĐỔI EMAIL TÀI KHOẢN</h2>
            <p>Chào bạn,</p>
            <div style="background: #f4f7fe; padding: 15px; text-align: center; border-radius: 8px; margin: 20px 0;">
                <p>Mã xác nhận 6 số để cập nhật Email mới cho tài khoản Rau Má PC là:</p>
                <h1 style="color: #d70018; letter-spacing: 5px;">${otpCode}</h1>
            </div>
            <p style="color: #d70018; font-weight: bold;">⚠️ Mã này chỉ có hiệu lực trong đúng 60 GIÂY.</p>
        </div>`;

        const emailData = {
            service_id: process.env.EMAILJS_SERVICE_ID, 
            template_id: process.env.EMAILJS_TEMPLATE_ID, 
            user_id: process.env.EMAILJS_USER_ID, 
            accessToken: process.env.EMAILJS_TOKEN,
            template_params: { to_email: newEmail, subject: '[Rau Má PC] Xác Nhận Thay Đổi Email', message: htmlContent }
        };

        fetch('https://api.emailjs.com/api/v1.0/email/send', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(emailData) }).catch(e=>console.log(e));

        res.json({ success: true, message: "Mã OTP đã được gửi đến Email mới!" });
    } catch (err) { res.status(500).json({ success: false, message: "Lỗi hệ thống!" }); }
});

// --- CẬP NHẬT THÔNG TIN LIÊN HỆ & EMAIL (XÁC THỰC OTP) ---
app.post('/api/users/me/update', verifyToken, async (req, res) => {
    try {
        const { phone, email, otp } = req.body;
        
        let user = await User.findById(req.user.id);
        if (!user) return res.status(404).json({ success: false, message: "Không tìm thấy người dùng."});

        // Nếu người dùng thay đổi Email, cần kiểm tra OTP
        if (email && email !== user.email) {
             const cached = otpCache[email];
            if (!cached) return res.status(400).json({ success: false, message: "Vui lòng ấn gửi mã OTP để xác nhận Email mới!" });
            if (Date.now() > cached.expiresAt) return res.status(400).json({ success: false, message: "Mã OTP đã HẾT HẠN (quá 60s)! Vui lòng gửi lại mã." });
            if (cached.code !== otp) return res.status(400).json({ success: false, message: "Mã OTP xác nhận Email không chính xác!" });
            
            user.email = email;
            delete otpCache[email]; // Xóa OTP sau khi dùng
        }

        // Cập nhật SĐT nếu có
        if (phone) user.phone = phone;

        await user.save();
        res.json({ success: true, message: "Cập nhật thông tin thành công!", user: { username: user.username, fullName: user.fullName, role: user.role, email: user.email, phone: user.phone, cart: user.cart, createdAt: user.createdAt } });

    } catch (err) { res.status(500).json({ success: false, message: "Lỗi máy chủ!" }); }
});


// ==========================================
// 8. API XÓA TÀI KHOẢN VĨNH VIỄN
// ==========================================
app.delete('/api/users/me', verifyToken, async (req, res) => {
    try {
        if (req.user.role === 'admin') {
            await Admin.findByIdAndDelete(req.user.id);
        } else {
            await User.findByIdAndDelete(req.user.id);
        }
        res.json({ success: true, message: "Tài khoản của bạn đã được xóa vĩnh viễn!" });
    } catch (err) { 
        res.status(500).json({ success: false, message: "Lỗi hệ thống khi xóa tài khoản!" }); 
    }
});