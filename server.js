require('dotenv').config();
const geoip = require('geoip-lite');
const express = require('express');
const cors = require('cors');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs'); 
const jwt = require('jsonwebtoken');

const app = express();

app.set('trust proxy', 1);

const allowedOrigins = ['https://raumapc-frontend.vercel.app', 'http://127.0.0.1:5500', 'http://localhost:5500'];
app.use(cors({
    origin: function (origin, callback) {
        if (!origin || allowedOrigins.includes(origin)) {
            callback(null, true);
        } else {
            callback(new Error('Tên miền không hợp lệ (CORS block)'));
        }
    },
    credentials: true
}));

// HẠ GIỚI HẠN DỮ LIỆU XUỐNG 5MB ĐỂ CHỐNG SPAM SẬP MÁY CHỦ
app.use(express.json({ limit: '5mb' }));
app.use(express.urlencoded({ limit: '5mb', extended: true }));

const rateLimit = require('express-rate-limit');

// Khiên 1: Giới hạn toàn hệ thống (Max 300 yêu cầu / 15 phút cho mỗi IP)
const globalLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, 
    max: 300,
    message: { success: false, message: "Hệ thống đang quá tải từ thiết bị của bạn. Vui lòng thử lại sau 15 phút!" }
});
app.use(globalLimiter);

// Khiên 2: Khóa chặt cổng Đăng nhập & Gửi OTP (Max 5 lần / 5 phút)
const authLimiter = rateLimit({
    windowMs: 5 * 60 * 1000,
    max: 5, 
    message: { success: false, message: "Phát hiện dấu hiệu Spam! Vui lòng thao tác chậm lại hoặc thử lại sau 5 phút." }
});

// ==========================================
// KHIÊN 3: CHẶN IP NƯỚC NGOÀI (GEO-BLOCKING)
// ==========================================
const geoBlocker = (req, res, next) => {
    let ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress;
    if (ip) {
        ip = ip.split(',')[0].trim();
        const geo = geoip.lookup(ip);
        if (geo && geo.country !== 'VN' && ip !== '::1' && ip !== '127.0.0.1') {
            console.log(`🚨 Chặn truy cập từ quốc gia: ${geo.country} (IP: ${ip})`);
            return res.status(403).json({
                success: false,
                message: "Hệ thống Rau Má PC hiện tại chỉ hỗ trợ truy cập và đặt hàng từ lãnh thổ Việt Nam."
            });
        }
    }
    next();
};
app.use(geoBlocker);

// Áp dụng Khiên 2 cho các API nhạy cảm
app.use('/api/login', authLimiter);
app.use('/api/request-otp', authLimiter);
app.use('/api/request-register-otp', authLimiter);

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
    productId: String, 
    name: String, price: String, img: String, warranty: String,
    specs: String, description: String, category: String, brand: String,
    views: { type: Number, default: 0 },
    comments: { type: Array, default: [] },
    gallery: { type: Array, default: [] }
});
productSchema.index({ name: 'text' }); 
const Product = mongoose.model('Product', productSchema);

// Khuôn Đơn hàng
const orderSchema = new mongoose.Schema({
    orderId: String, date: String, username: String, account: String,
    email: String, items: Array, total: Number, status: String
});
const Order = mongoose.model('Order', orderSchema);

// Khuôn Khách hàng (User)
const userSchema = new mongoose.Schema({
    fullName: { type: String, required: true },
    username: { type: String, unique: true, required: true },
    password: { type: String, required: true },
    phone: { type: String, required: true }, 
    email: { type: String, required: true, index: true }, 
    role: { type: String, default: 'user' },
    cart: { type: Array, default: [] },
    avatar: { type: String, default: '' },
    createdAt: { type: Date, default: Date.now } 
});
const User = mongoose.model('User', userSchema);

// Khuôn Quản trị viên (Admin)
const adminSchema = new mongoose.Schema({
    fullName: { type: String, required: true },
    username: { type: String, unique: true, required: true },
    password: { type: String, required: true },
    role: { type: String, default: 'admin' }
});
const Admin = mongoose.model('Admin', adminSchema);

// Khuôn Cài Đặt Website (Settings) - DÙNG CHO CÀI ĐẶT TRANG CHỦ
const settingSchema = new mongoose.Schema({
    key: { type: String, unique: true },
    data: Object
});
const Setting = mongoose.model('Setting', settingSchema);

// ==========================================
// CỬA AN NINH (MIDDLEWARE)
// ==========================================
const verifyToken = async (req, res, next) => {
    const token = req.headers['authorization'];
    if (!token) return res.status(403).json({ message: "Bạn chưa đăng nhập!" });
    try {
        const decoded = jwt.verify(token.split(" ")[1], JWT_SECRET);
        
        let user = await User.findById(decoded.id);
        if (!user) user = await Admin.findById(decoded.id);
        
        if (!user) {
            return res.status(401).json({ message: "Tài khoản đã bị xóa khỏi hệ thống!", accountDeleted: true });
        }

        req.user = decoded; 
        next();
    } catch (err) { return res.status(401).json({ message: "Phiên đăng nhập hết hạn!" }); }
};

app.get('/api/auth/verify', verifyToken, (req, res) => {
    res.json({ success: true });
});

// ==========================================
// TẠO ADMIN 
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

app.post('/api/admin/create', verifyToken, async (req, res) => {
    try {
        if (req.user.role !== 'admin') {
            return res.status(403).json({ success: false, message: "Cảnh báo: Chỉ Admin mới có quyền tạo Admin khác!" });
        }

        const { fullName, username, password } = req.body;
        if (!fullName || !username || !password) return res.status(400).json({ success: false, message: "Vui lòng cung cấp đủ Tên, Tài khoản và Mật khẩu!" });

        const existingAdmin = await Admin.findOne({ username });
        if (existingAdmin) return res.status(400).json({ success: false, message: "Tài khoản Admin này đã tồn tại!" });

        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);

        const newAdmin = new Admin({ fullName: fullName, username: username, password: hashedPassword, role: "admin" });
        await newAdmin.save();
        res.json({ success: true, message: `Đã tạo thành công Admin: ${fullName} (${username})` });
    } catch (err) { res.status(500).json({ success: false, message: "Lỗi hệ thống: " + err.message }); }
});

// ==========================================
// XÁC THỰC OTP & ĐĂNG NHẬP
// ==========================================
const otpCache = {};

app.post('/api/request-register-otp', async (req, res) => {
    try {
        const { email, username } = req.body;
        const existingUser = await User.findOne({ $or: [{ email: email }, { username: username }] });
        if (existingUser) return res.status(400).json({ success: false, message: "Email hoặc Tên đăng nhập đã được sử dụng!" });

        const otpCode = Math.floor(100000 + Math.random() * 900000).toString();
        otpCache[email] = { code: otpCode, expiresAt: Date.now() + 60000 };

        const htmlContent = `<div style="font-family: Arial; padding: 20px; border: 1px solid #eee; border-radius: 10px;"><h2 style="color: #1435c3;">MÃ OTP XÁC NHẬN ĐĂNG KÝ</h2><p>Mã của bạn là: <b style="color: #d70018;">${otpCode}</b></p></div>`;
        const emailData = { service_id: process.env.EMAILJS_SERVICE_ID, template_id: process.env.EMAILJS_TEMPLATE_ID, user_id: process.env.EMAILJS_USER_ID, accessToken: process.env.EMAILJS_TOKEN, template_params: { to_email: email, subject: '[Rau Má PC] Mã OTP Đăng Ký Tài Khoản', message: htmlContent } };
        fetch('https://api.emailjs.com/api/v1.0/email/send', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(emailData) }).catch(e=>console.log(e));

        res.json({ success: true, message: "Mã OTP đăng ký đã được gửi đến Email!" });
    } catch (err) { res.status(500).json({ success: false, message: "Lỗi hệ thống!" }); }
});

app.post('/api/register', async (req, res) => {
    try {
        const { fullName, username, password, phone, email, otp } = req.body;
        const cached = otpCache[email];
        if (!cached) return res.status(400).json({ success: false, message: "Vui lòng ấn gửi mã OTP trước!" });
        if (Date.now() > cached.expiresAt) return res.status(400).json({ success: false, message: "Mã OTP đã HẾT HẠN!" });
        if (cached.code !== otp) return res.status(400).json({ success: false, message: "Mã OTP không chính xác!" });

        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);

        const newUser = new User({ fullName, username, password: hashedPassword, phone, email });
        await newUser.save();
        delete otpCache[email]; 
        res.json({ success: true, message: "Đăng ký thành công!" });
    } catch (err) { res.status(500).json({ success: false, message: "Lỗi máy chủ!" }); }
});

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

        if (isRole === 'admin') {
            const token = jwt.sign({ id: user._id, username: user.username, role: isRole }, JWT_SECRET, { expiresIn: '7d' });
            return res.json({ success: true, token, user: { username: user.username, fullName: user.fullName, role: isRole, avatar: user.avatar }, requireOtp: false });
        }

        const otpCode = Math.floor(100000 + Math.random() * 900000).toString();
        otpCache[user.email] = { code: otpCode, expiresAt: Date.now() + 60000 };

        const htmlContent = `<div style="font-family: Arial; padding: 20px; border: 1px solid #eee; border-radius: 10px;"><h2 style="color: #1435c3;">MÃ OTP ĐĂNG NHẬP BẢO MẬT</h2><p>Mã của bạn là: <b style="color: #d70018;">${otpCode}</b></p></div>`;
        const emailData = { service_id: process.env.EMAILJS_SERVICE_ID, template_id: process.env.EMAILJS_TEMPLATE_ID, user_id: process.env.EMAILJS_USER_ID, accessToken: process.env.EMAILJS_TOKEN, template_params: { to_email: user.email, subject: '[Rau Má PC] Mã OTP Đăng Nhập', message: htmlContent } };
        fetch('https://api.emailjs.com/api/v1.0/email/send', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(emailData) }).catch(e=>console.log(e));

        res.json({ success: true, requireOtp: true, email: user.email, message: "Mã OTP đã được gửi đến email." });
    } catch (err) { res.status(500).json({ success: false, message: "Lỗi máy chủ!" }); }
});

app.post('/api/login-verify', async (req, res) => {
    try {
        const { email, otp } = req.body;
        const cached = otpCache[email];
        if (!cached) return res.status(400).json({ success: false, message: "Phiên đăng nhập không hợp lệ!" });
        if (Date.now() > cached.expiresAt) return res.status(400).json({ success: false, message: "Mã OTP đã HẾT HẠN!" });
        if (cached.code !== otp) return res.status(400).json({ success: false, message: "Mã OTP không chính xác!" });

        const user = await User.findOne({ email: email });
        const token = jwt.sign({ id: user._id, username: user.username, role: 'user' }, JWT_SECRET, { expiresIn: '7d' });
        const userData = { username: user.username, fullName: user.fullName, role: 'user', email: user.email, phone: user.phone, cart: user.cart, avatar: user.avatar, createdAt: user.createdAt };

        delete otpCache[email]; 
        res.json({ success: true, token, user: userData });
    } catch (err) { res.status(500).json({ success: false, message: "Lỗi máy chủ!" }); }
});

app.post('/api/request-otp', async (req, res) => {
    try {
        const { email } = req.body;
        const user = await User.findOne({ email: email });
        if (!user) return res.status(404).json({ success: false, message: "Email không tồn tại!" });

        const otpCode = Math.floor(100000 + Math.random() * 900000).toString();
        otpCache[email] = { code: otpCode, expiresAt: Date.now() + 60000 };

        const htmlContent = `<div style="font-family: Arial; padding: 20px;"><h2 style="color: #1435c3;">MÃ XÁC NHẬN BẢO MẬT (OTP)</h2><p>Mã của bạn là: <b style="color: #d70018;">${otpCode}</b></p></div>`;
        const emailData = { service_id: process.env.EMAILJS_SERVICE_ID, template_id: process.env.EMAILJS_TEMPLATE_ID, user_id: process.env.EMAILJS_USER_ID, accessToken: process.env.EMAILJS_TOKEN, template_params: { to_email: user.email, subject: '[Rau Má PC] Mã OTP Xác Nhận Bảo Mật', message: htmlContent } };
        fetch('https://api.emailjs.com/api/v1.0/email/send', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(emailData) }).catch(e=>console.log(e));

        res.json({ success: true, message: "Mã OTP đã gửi qua Email!" });
    } catch (err) { res.status(500).json({ success: false, message: "Lỗi hệ thống!" }); }
});

app.post('/api/forgot-password-verify', async (req, res) => {
    try {
        const { email, otp, newPassword } = req.body;
        const cached = otpCache[email];
        if (!cached || Date.now() > cached.expiresAt || cached.code !== otp) return res.status(400).json({ success: false, message: "Mã OTP không hợp lệ hoặc đã hết hạn!" });

        const user = await User.findOne({ email: email });
        const salt = await bcrypt.genSalt(10);
        user.password = await bcrypt.hash(newPassword, salt);
        await user.save();
        
        delete otpCache[email]; 
        res.json({ success: true, message: "Khôi phục mật khẩu thành công!" });
    } catch (err) { res.status(500).json({ success: false, message: "Lỗi hệ thống!" }); }
});

app.post('/api/change-password-verify', verifyToken, async (req, res) => {
    try {
        const { oldPassword, newPassword, otp, email } = req.body;
        const cached = otpCache[email];
        if (!cached || Date.now() > cached.expiresAt || cached.code !== otp) return res.status(400).json({ success: false, message: "Mã OTP không hợp lệ!" });

        let user = await User.findById(req.user.id) || await Admin.findById(req.user.id);
        const isMatch = await bcrypt.compare(oldPassword, user.password);
        if (!isMatch) return res.status(400).json({ success: false, message: "Mật khẩu cũ không chính xác!" });

        const salt = await bcrypt.genSalt(10);
        user.password = await bcrypt.hash(newPassword, salt);
        await user.save();

        delete otpCache[email];
        res.json({ success: true, message: "Đổi mật khẩu thành công!" });
    } catch (err) { res.status(500).json({ success: false, message: "Lỗi hệ thống!" }); }
});

// ==========================================
// API SẢN PHẨM & TÌM KIẾM
// ==========================================
app.get('/api/products', async (req, res) => {
    try { 
        const products = await Product.find();
        const formattedProducts = products.map(sp => ({
            id: sp._id.toString(),
            productId: sp.productId || sp._id.toString().slice(-6).toUpperCase(), 
            name: sp.name, price: sp.price, img: sp.img, warranty: sp.warranty,
            category: sp.category, brand: sp.brand, specs: sp.specs, description: sp.description,
            views: sp.views || 0, comments: sp.comments, gallery: sp.gallery || []
        }));
        res.json(formattedProducts); 
    } catch (err) { res.status(500).json({ message: "Lỗi Server" }); }
});

app.get('/api/products/detail/:id', async (req, res) => {
    try {
        const key = req.params.id;
        let sp = mongoose.Types.ObjectId.isValid(key) ? await Product.findById(key) : null;
        if (!sp) sp = await Product.findOne({ productId: key });
        if (!sp) return res.status(404).json({ message: "Không tìm thấy sản phẩm!" });

        res.json({
            id: sp._id.toString(), productId: sp.productId || sp._id.toString().slice(-6).toUpperCase(),
            name: sp.name, price: sp.price, img: sp.img, warranty: sp.warranty,
            category: sp.category, brand: sp.brand, specs: sp.specs, description: sp.description,
            comments: sp.comments, gallery: sp.gallery || []
        });
    } catch (err) { res.status(500).json({ message: "Lỗi Server" }); }
});

// --- HÀM TẠO ID TỰ ĐỘNG THÔNG MINH (PHIÊN BẢN CẬP NHẬT) ---
async function generateAutoId(categoryString) {
    const cat1 = categoryString ? categoryString.split(',')[0].trim().toLowerCase() : '';
    let prefix = 'SP';

    if (['cpu', 'intel', 'amd'].includes(cat1)) prefix = 'CPU';
    else if (['vga', 'vga-nvidia', 'vga-amd'].includes(cat1)) prefix = 'VGA';
    else if (cat1 === 'main') prefix = 'M';
    else if (cat1 === 'monitor') prefix = 'MH';
    else if (cat1 === 'ram') prefix = 'RAM';
    else if (cat1 === 'storage') prefix = 'SSD';
    else if (cat1 === 'psu') prefix = 'PSU';
    else if (['cooling', 'thermal-paste'].includes(cat1)) prefix = 'TN';
    else if (cat1 === 'case') prefix = 'V';
    else if (cat1.includes('win-') || cat1.includes('office-') || ['licensed-software', 'other-software'].includes(cat1)) prefix = 'PM';
    else if (['wireless-mouse', 'mouse'].includes(cat1)) prefix = 'MOU';
    else if (['wireless-keyboard', 'keyboard'].includes(cat1)) prefix = 'KB';

    try {
        const latestProduct = await Product.findOne({ productId: new RegExp('^' + prefix + '\\d+$') })
            .sort({ productId: -1 })
            .collation({ locale: "en_US", numericOrdering: true }); 

        let nextNumber = 1;
        if (latestProduct && latestProduct.productId) {
            const currentNumStr = latestProduct.productId.replace(prefix, '');
            const currentNum = parseInt(currentNumStr, 10);
            if (!isNaN(currentNum)) nextNumber = currentNum + 1;
        }
        return prefix + String(nextNumber).padStart(7, '0');
    } catch (error) {
        return prefix + String(Math.floor(Math.random() * 10000000)).padStart(7, '0'); 
    }
}

app.post('/api/products', async (req, res) => {
    try {
        if (!req.body.productId || req.body.productId.trim() === '') {
            req.body.productId = await generateAutoId(req.body.category);
        }
        const newProduct = new Product(req.body);
        await newProduct.save();
        res.json({ message: "Thêm sản phẩm thành công!" });
    } catch (err) { res.status(500).json({ message: "Lỗi lưu sản phẩm!" }); }
});

app.put('/api/products/:id', async (req, res) => {
    try {
        if (!req.body.productId || req.body.productId.trim() === '') {
            req.body.productId = await generateAutoId(req.body.category);
        }
        await Product.findByIdAndUpdate(req.params.id, req.body);
        res.json({ message: "Cập nhật thành công!" });
    } catch (err) { res.status(500).json({ message: "Lỗi cập nhật!" }); }
});

app.delete('/api/products/:id', async (req, res) => {
    try {
        await Product.findByIdAndDelete(req.params.id);
        res.json({ message: "Xóa thành công!" });
    } catch (err) { res.status(500).json({ message: "Lỗi xóa sản phẩm!" }); }
});

app.put('/api/products/:id/view', async (req, res) => {
    try {
        const key = req.params.id;
        let query = mongoose.Types.ObjectId.isValid(key) ? { _id: key } : { productId: key };
        const sp = await Product.findOneAndUpdate(query, { $inc: { views: 1 } }, { returnDocument: 'after' });
        if (sp) res.json({ success: true, views: sp.views });
        else res.status(404).json({ success: false });
    } catch (err) { res.status(500).json({ success: false }); }
});

// ==========================================
// API ĐƠN HÀNG, DOANH THU & GỬI MAIL HÓA ĐƠN
// ==========================================
app.post('/api/orders', async (req, res) => {
    try {
        const newOrder = new Order(req.body);
        await newOrder.save();

        let cusName = newOrder.username;
        let cusPhone = "Đang cập nhật";
        let cusAddress = "Đang cập nhật";
        const match = newOrder.username.match(/(.+?)\s*\((.+?)\s*-\s*(.+)\)/);
        if (match) { cusName = match[1]; cusPhone = match[2]; cusAddress = match[3]; }

        let itemsHtml = "";
        newOrder.items.forEach(item => {
            let priceNum = parseInt(String(item.price).replace(/\D/g, '')) || 0;
            let qtyNum = parseInt(item.quantity) || 1;
            let itemTotal = priceNum * qtyNum;
            itemsHtml += `<tr><td style="padding: 12px 10px 12px 0; border-bottom: 1px solid #eee;">${item.name}</td><td style="padding: 12px 10px; border-bottom: 1px solid #eee; text-align: center;">${qtyNum}</td><td style="padding: 12px 0 12px 10px; border-bottom: 1px solid #eee; text-align: right; color: #d70018; font-weight: bold;">${new Intl.NumberFormat('vi-VN').format(itemTotal)}đ</td></tr>`;
        });

        let formattedTotal = new Intl.NumberFormat('vi-VN').format(newOrder.total) + ' đ';

        const fullHtmlContent = `
        <div style="font-family: Arial; max-width: 600px; margin: 0 auto; border: 1px solid #eaebec; border-radius: 12px;">
            <div style="background: linear-gradient(135deg, #1435c3 0%, #0a1b66 100%); padding: 30px; text-align: center; color: white;">
                <h1 style="margin: 0;">RAU MÁ PC</h1><p>Đơn hàng đang chờ duyệt</p>
            </div>
            <div style="padding: 30px;">
                <p>Chào <strong>${cusName}</strong>, cảm ơn bạn đã đặt hàng.</p>
                <h3 style="color: #1435c3; border-bottom: 2px solid #f4f7fe; padding-bottom: 8px;">Mã đơn: #${newOrder.orderId}</h3>
                <p><b>Điện thoại:</b> ${cusPhone}</p>
                <p><b>Địa chỉ:</b> ${cusAddress}</p>
                <table style="width: 100%; border-collapse: collapse;"><tbody>${itemsHtml}</tbody></table>
                <h2 style="text-align: right; color: #d70018;">Tổng: ${formattedTotal}</h2>
            </div>
        </div>`;

        const emailData = { service_id: process.env.EMAILJS_SERVICE_ID, template_id: process.env.EMAILJS_TEMPLATE_ID, user_id: process.env.EMAILJS_USER_ID, accessToken: process.env.EMAILJS_TOKEN, template_params: { to_email: newOrder.email, subject: `[Rau Má PC] Đơn hàng #${newOrder.orderId} chờ xác nhận`, message: fullHtmlContent } };
        const adminEmailData = { service_id: process.env.EMAILJS_SERVICE_ID, template_id: process.env.EMAILJS_TEMPLATE_ID, user_id: process.env.EMAILJS_USER_ID, accessToken: process.env.EMAILJS_TOKEN, template_params: { to_email: "lamngo829@gmail.com", subject: `🚨 CÓ ĐƠN MỚI #${newOrder.orderId}`, message: fullHtmlContent } };

        fetch('https://api.emailjs.com/api/v1.0/email/send', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(adminEmailData) }).catch(e=>console.log(e));
        fetch('https://api.emailjs.com/api/v1.0/email/send', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(emailData) }).catch(e=>console.log(e));

        const userCheck = await User.findOne({ username: newOrder.account });
        if (userCheck) { userCheck.cart = []; await userCheck.save(); }

        res.json({ message: "Đặt hàng thành công!" });
    } catch (error) { res.status(500).json({ message: "Lỗi khi lưu đơn!" }); }
});

app.get('/api/orders', async (req, res) => {
    try { res.json(await Order.find()); } catch (err) { res.status(500).json({ message: "Lỗi!" }); }
});

app.get('/api/admin/revenue', async (req, res) => {
    try {
        const revenue = await Order.aggregate([ { $match: { status: "Hoàn thành" } }, { $group: { _id: null, totalRevenue: {$sum: "$total" }, totalOrders: { $sum: 1 } } } ]);
        res.json(revenue[0] || { totalRevenue: 0, totalOrders: 0 });
    } catch (err) { res.status(500).json({ message: "Lỗi thống kê!" }); }
});

app.put('/api/users/cart', verifyToken, async (req, res) => {
    try {
        await User.findByIdAndUpdate(req.user.id, { cart: req.body.cart });
        res.json({ success: true, message: "Đã đồng bộ giỏ hàng" });
    } catch (err) { res.status(500).json({ success: false, message: "Lỗi đồng bộ" }); }
});

app.put('/api/orders/:id/status', async (req, res) => {
    try {
        const order = await Order.findOneAndUpdate({ orderId: req.params.id }, { status: req.body.status }, { returnDocument: 'after' });
        res.json({ message: "Cập nhật thành công!" });
    } catch (err) { res.status(500).json({ message: "Lỗi hệ thống!" }); }
});

app.delete('/api/orders/:id', async (req, res) => {
    try {
        await Order.findOneAndDelete({ orderId: req.params.id });
        res.json({ success: true, message: "Đã xóa đơn hàng!" });
    } catch (err) { res.status(500).json({ success: false, message: "Lỗi xóa đơn hàng!" }); }
});

app.post('/api/products/:id/comments', async (req, res) => {
    try {
        const { userName, userAvatar, content, rating, img } = req.body;
        const product = await Product.findById(req.params.id);
        if (!product) return res.status(404).json({ success: false, message: "Sản phẩm không tồn tại!" });

        const newComment = { id: Date.now().toString(), userName: userName || "Khách", userAvatar: userAvatar || "", content: content, rating: rating || 5, img: img || null, date: new Date().toLocaleDateString('vi-VN') + ' ' + new Date().toLocaleTimeString('vi-VN', {hour: '2-digit', minute:'2-digit'}) };
        product.comments.push(newComment);
        await product.save();
        res.json({ success: true, message: "Đã gửi bình luận!", comments: product.comments });
    } catch (err) { res.status(500).json({ success: false, message: "Lỗi máy chủ!" }); }
});

app.post('/api/request-email-update-otp', verifyToken, async (req, res) => {
    try {
        const { newEmail } = req.body;
        const existingEmail = await User.findOne({ email: newEmail });
        if (existingEmail) return res.status(400).json({ success: false, message: "Email này đã được đăng ký bởi tài khoản khác!" });

        const otpCode = Math.floor(100000 + Math.random() * 900000).toString();
        otpCache[newEmail] = { code: otpCode, expiresAt: Date.now() + 60000 };

        const htmlContent = `<div style="padding: 20px;"><h2>XÁC NHẬN ĐỔI EMAIL</h2><p>Mã của bạn: <b>${otpCode}</b></p></div>`;
        const emailData = { service_id: process.env.EMAILJS_SERVICE_ID, template_id: process.env.EMAILJS_TEMPLATE_ID, user_id: process.env.EMAILJS_USER_ID, accessToken: process.env.EMAILJS_TOKEN, template_params: { to_email: newEmail, subject: '[Rau Má PC] Đổi Email', message: htmlContent } };
        fetch('https://api.emailjs.com/api/v1.0/email/send', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(emailData) }).catch(e=>console.log(e));

        res.json({ success: true, message: "Đã gửi mã OTP!" });
    } catch (err) { res.status(500).json({ success: false }); }
});

app.post('/api/users/me/update', verifyToken, async (req, res) => {
    try {
        const { phone, email, otp, avatar } = req.body;
        let user = await User.findById(req.user.id);
        if (!user) return res.status(404).json({ success: false, message: "Không tìm thấy người dùng."});

        if (email && email !== user.email) {
             const cached = otpCache[email];
            if (!cached || Date.now() > cached.expiresAt || cached.code !== otp) return res.status(400).json({ success: false, message: "Mã OTP không hợp lệ!" });
            user.email = email;
            delete otpCache[email]; 
        }

        if (phone) user.phone = phone;
        if (avatar) user.avatar = avatar;

        await user.save();
        res.json({ success: true, message: "Cập nhật thành công!", user: { username: user.username, fullName: user.fullName, role: user.role, email: user.email, phone: user.phone, cart: user.cart, avatar: user.avatar, createdAt: user.createdAt } });
    } catch (err) { res.status(500).json({ success: false, message: "Lỗi máy chủ!" }); }
});

app.delete('/api/users/me', verifyToken, async (req, res) => {
    try {
        if (req.user.role === 'admin') await Admin.findByIdAndDelete(req.user.id);
        else await User.findByIdAndDelete(req.user.id);
        res.json({ success: true, message: "Đã xóa tài khoản!" });
    } catch (err) { res.status(500).json({ success: false }); }
});

// ==========================================
// API LƯU VÀ TẢI CẤU HÌNH TRANG CHỦ GLOBAL (LƯU LÊN CLOUD MONGODB)
// ==========================================
app.get('/api/settings/home', async (req, res) => {
    try {
        const homeSettings = await Setting.findOne({ key: 'homeConfig' });
        res.json(homeSettings ? homeSettings.data : {});
    } catch (err) { res.status(500).json({}); }
});

app.put('/api/settings/home', verifyToken, async (req, res) => {
    if (req.user.role !== 'admin') return res.status(403).json({ success: false, message: "Từ chối quyền truy cập!" });
    try {
        await Setting.findOneAndUpdate(
            { key: 'homeConfig' },
            { data: req.body },
            { upsert: true, new: true } // Nếu chưa có thì tạo mới, có rồi thì ghi đè
        );
        res.json({ success: true, message: "Đã đồng bộ trang chủ lên Cloud!" });
    } catch (err) { res.status(500).json({ success: false }); }
});

// Endpoint giữ Server thức
app.get('/api/health', (req, res) => { res.json({ status: 'ok', time: new Date().toISOString() }); });

app.listen(process.env.PORT || 3000, () => console.log(`✅ Máy chủ đang chạy ở chuẩn bảo mật Doanh Nghiệp`));