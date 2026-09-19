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

app.use(express.json({ limit: '5mb' }));
app.use(express.urlencoded({ limit: '5mb', extended: true }));

const rateLimit = require('express-rate-limit');
const globalLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 300, message: { success: false, message: "Hệ thống đang quá tải từ thiết bị của bạn. Vui lòng thử lại sau 15 phút!" } });
app.use(globalLimiter);

const authLimiter = rateLimit({ windowMs: 5 * 60 * 1000, max: 5, message: { success: false, message: "Phát hiện dấu hiệu Spam! Vui lòng thao tác chậm lại hoặc thử lại sau 5 phút." } });

const geoBlocker = (req, res, next) => {
    let ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress;
    if (ip) {
        ip = ip.split(',')[0].trim();
        const geo = geoip.lookup(ip);
        if (geo && geo.country !== 'VN' && ip !== '::1' && ip !== '127.0.0.1') {
            return res.status(403).json({ success: false, message: "Hệ thống Rau Má PC hiện tại chỉ hỗ trợ truy cập và đặt hàng từ lãnh thổ Việt Nam." });
        }
    }
    next();
};
app.use(geoBlocker);
app.use('/api/login', authLimiter);
app.use('/api/request-otp', authLimiter);
app.use('/api/request-register-otp', authLimiter);

const JWT_SECRET = process.env.JWT_SECRET;

mongoose.connect(process.env.MONGO_URI)
    .then(() => console.log('✅ Đã kết nối MongoDB!'))
    .catch(err => console.error('❌ Lỗi kết nối MongoDB:', err));

// ==========================================
// KHUÔN MẪU DỮ LIỆU
// ==========================================
const productSchema = new mongoose.Schema({
    productId: String, name: String, price: String, img: String, warranty: String,
    status: { type: String, default: 'Còn hàng' }, 
    stock: { type: Number, default: 10 }, 
    specs: String, description: String, category: String, brand: String,
    views: { type: Number, default: 0 }, comments: { type: Array, default: [] }, gallery: { type: Array, default: [] }
});
productSchema.index({ name: 'text' }); 
const Product = mongoose.model('Product', productSchema);

const orderSchema = new mongoose.Schema({ orderId: String, date: String, username: String, account: String, email: String, items: Array, total: Number, status: String, paymentMethod: String });
const Order = mongoose.model('Order', orderSchema);

// ĐÃ THÊM: isLocked (Trạng thái khóa) và loginHistory (Nhật ký đăng nhập)
const userSchema = new mongoose.Schema({ 
    fullName: { type: String, required: true }, 
    username: { type: String, unique: true, required: true }, 
    password: { type: String, required: true }, 
    phone: { type: String, required: true }, 
    email: { type: String, required: true, index: true }, 
    role: { type: String, default: 'user' }, 
    cart: { type: Array, default: [] }, 
    avatar: { type: String, default: '' },
    isLocked: { type: Boolean, default: false },
    loginHistory: { type: Array, default: [] },
    createdAt: { type: Date, default: Date.now } 
});
const User = mongoose.model('User', userSchema);

const adminSchema = new mongoose.Schema({ fullName: { type: String, required: true }, username: { type: String, unique: true, required: true }, password: { type: String, required: true }, role: { type: String, default: 'admin' } });
const Admin = mongoose.model('Admin', adminSchema);

const settingSchema = new mongoose.Schema({ key: { type: String, unique: true }, data: Object });
const Setting = mongoose.model('Setting', settingSchema);

const couponSchema = new mongoose.Schema({ code: { type: String, required: true, unique: true }, discountPercent: { type: Number, required: true }, isActive: { type: Boolean, default: true }, createdAt: { type: Date, default: Date.now } });
const Coupon = mongoose.model('Coupon', couponSchema);

// BỘ LỌC BẢO VỆ (ĐÁ VĂNG USER NẾU BỊ KHÓA)
const verifyToken = async (req, res, next) => {
    const token = req.headers['authorization'];
    if (!token) return res.status(403).json({ message: "Bạn chưa đăng nhập!" });
    try {
        const decoded = jwt.verify(token.split(" ")[1], JWT_SECRET);
        let user = await User.findById(decoded.id) || await Admin.findById(decoded.id);
        if (!user) return res.status(401).json({ message: "Tài khoản đã bị xóa khỏi hệ thống!", accountDeleted: true });
        
        // NẾU ADMIN ĐÃ KHÓA, ÉP BUỘC LOGOUT NGAY LẬP TỨC DÙ CÒN TOKEN
        if (user.isLocked) return res.status(401).json({ message: "Tài khoản của bạn đã bị khóa do vi phạm!", accountDeleted: true });
        
        req.user = decoded; next();
    } catch (err) { return res.status(401).json({ message: "Phiên đăng nhập hết hạn!" }); }
};

app.get('/api/auth/verify', verifyToken, (req, res) => { res.json({ success: true }); });

app.get('/api/setup-admin', async (req, res) => {
    try {
        const existingAdmin = await Admin.findOne({ username: 'admin' });
        if (existingAdmin) return res.send("<h3>Tài khoản Admin đã tồn tại!</h3>");
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(process.env.ADMIN_PASS, salt);
        const newAdmin = new Admin({ fullName: "Tổng Giám Đốc Rau Má", username: "admin", password: hashedPassword, role: "admin" });
        await newAdmin.save();
        res.send("<h3>✅ Đã khởi tạo biệt thự Admin thành công!</h3>");
    } catch (err) { res.status(500).send("Lỗi hệ thống: " + err.message); }
});

app.post('/api/admin/create', verifyToken, async (req, res) => {
    try {
        if (req.user.role !== 'admin') return res.status(403).json({ success: false, message: "Cảnh báo: Chỉ Admin mới có quyền tạo Admin khác!" });
        const { fullName, username, password } = req.body;
        if (!fullName || !username || !password) return res.status(400).json({ success: false, message: "Vui lòng cung cấp đủ thông tin!" });
        const existingAdmin = await Admin.findOne({ username });
        if (existingAdmin) return res.status(400).json({ success: false, message: "Tài khoản Admin này đã tồn tại!" });
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);
        const newAdmin = new Admin({ fullName: fullName, username: username, password: hashedPassword, role: "admin" });
        await newAdmin.save();
        res.json({ success: true, message: `Đã tạo thành công Admin: ${fullName} (${username})` });
    } catch (err) { res.status(500).json({ success: false, message: "Lỗi hệ thống!" }); }
});

const otpCache = {};
app.post('/api/request-register-otp', async (req, res) => {
    try {
        const { email, username } = req.body;
        const existingUser = await User.findOne({ $or: [{ email: email }, { username: username }] });
        if (existingUser) return res.status(400).json({ success: false, message: "Email hoặc Tên đăng nhập đã được sử dụng!" });
        const otpCode = Math.floor(100000 + Math.random() * 900000).toString();
        otpCache[email] = { code: otpCode, expiresAt: Date.now() + 60000 };
        const htmlContent = `<div style="font-family: Arial; padding: 20px;"><h2 style="color: #1435c3;">MÃ OTP XÁC NHẬN ĐĂNG KÝ</h2><p>Mã của bạn là: <b style="color: #d70018;">${otpCode}</b></p></div>`;
        const emailData = { service_id: process.env.EMAILJS_SERVICE_ID, template_id: process.env.EMAILJS_TEMPLATE_ID, user_id: process.env.EMAILJS_USER_ID, accessToken: process.env.EMAILJS_TOKEN, template_params: { to_email: email, subject: '[Rau Má PC] Mã OTP Đăng Ký Tài Khoản', message: htmlContent } };
        fetch('https://api.emailjs.com/api/v1.0/email/send', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(emailData) }).catch(e=>console.log(e));
        res.json({ success: true, message: "Mã OTP đăng ký đã được gửi đến Email!" });
    } catch (err) { res.status(500).json({ success: false, message: "Lỗi hệ thống!" }); }
});

app.post('/api/register', async (req, res) => {
    try {
        const { fullName, username, password, phone, email, otp } = req.body;
        const cached = otpCache[email];
        if (!cached || Date.now() > cached.expiresAt || cached.code !== otp) return res.status(400).json({ success: false, message: "Mã OTP không hợp lệ hoặc đã hết hạn!" });
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
        if (!user) { user = await Admin.findOne({ username: loginId }); isRole = 'admin'; }
        if (!user) return res.status(401).json({ success: false, message: "Sai tài khoản hoặc Email!" });
        
        // CHẶN NGAY TỪ CỬA NẾU BỊ KHÓA
        if (user.isLocked) return res.status(403).json({ success: false, message: "Tài khoản của bạn đã bị Admin khóa do vi phạm chính sách!" });

        const isMatch = await bcrypt.compare(req.body.password, user.password);
        if (!isMatch) return res.status(401).json({ success: false, message: "Sai mật khẩu!" });

        if (isRole === 'admin') {
            const token = jwt.sign({ id: user._id, username: user.username, role: isRole }, JWT_SECRET, { expiresIn: '7d' });
            return res.json({ success: true, token, user: { username: user.username, fullName: user.fullName, role: isRole, avatar: user.avatar }, requireOtp: false });
        }

        const otpCode = Math.floor(100000 + Math.random() * 900000).toString();
        otpCache[user.email] = { code: otpCode, expiresAt: Date.now() + 60000 };
        const htmlContent = `<div style="font-family: Arial; padding: 20px;"><h2 style="color: #1435c3;">MÃ OTP ĐĂNG NHẬP BẢO MẬT</h2><p>Mã của bạn là: <b style="color: #d70018;">${otpCode}</b></p></div>`;
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
        
        // GHI NHẬN LỊCH SỬ ĐĂNG NHẬP SAU KHI VƯỢT QUA OTP
        const now = new Date().toLocaleString('vi-VN', { hour12: false });
        user.loginHistory.push(now);
        await user.save();

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

// API ĐỔI MẬT KHẨU TỪ TRONG TRANG PROFILE (TỰ ĐỘNG MÃ HÓA BCRYPT)
app.post('/api/users/change-password', verifyToken, async (req, res) => {
    try {
        const { oldPassword, newPassword } = req.body;
        let user = await User.findById(req.user.id) || await Admin.findById(req.user.id);
        if (!user) return res.status(404).json({ success: false, message: "Không tìm thấy người dùng." });
        
        // So khớp mật khẩu cũ
        const isMatch = await bcrypt.compare(oldPassword, user.password);
        if (!isMatch) return res.status(400).json({ success: false, message: "Mật khẩu hiện tại không chính xác!" });
        
        // Mã hóa mật khẩu mới siêu cấp bảo mật
        const salt = await bcrypt.genSalt(10);
        user.password = await bcrypt.hash(newPassword, salt);
        await user.save();
        
        res.json({ success: true, message: "Đổi mật khẩu thành công! Mật khẩu mới đã được mã hóa an toàn." });
    } catch (err) { res.status(500).json({ success: false, message: "Lỗi hệ thống!" }); }
});

app.get('/api/products', async (req, res) => {
    try { 
        const products = await Product.find();
        const formattedProducts = products.map(sp => ({
            id: sp._id.toString(), productId: sp.productId || sp._id.toString().slice(-6).toUpperCase(), 
            name: sp.name, price: sp.price, img: sp.img, warranty: sp.warranty, status: sp.status || 'Còn hàng', 
            stock: sp.stock !== undefined ? sp.stock : 10, category: sp.category, brand: sp.brand, specs: sp.specs, description: sp.description,
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
            name: sp.name, price: sp.price, img: sp.img, warranty: sp.warranty, status: sp.status || 'Còn hàng',
            stock: sp.stock !== undefined ? sp.stock : 10, category: sp.category, brand: sp.brand, specs: sp.specs, description: sp.description, comments: sp.comments, gallery: sp.gallery || []
        });
    } catch (err) { res.status(500).json({ message: "Lỗi Server" }); }
});

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
        const latestProduct = await Product.findOne({ productId: new RegExp('^' + prefix + '\\d+$') }).sort({ productId: -1 }).collation({ locale: "en_US", numericOrdering: true }); 
        let nextNumber = 1;
        if (latestProduct && latestProduct.productId) {
            const currentNumStr = latestProduct.productId.replace(prefix, '');
            const currentNum = parseInt(currentNumStr, 10);
            if (!isNaN(currentNum)) nextNumber = currentNum + 1;
        }
        return prefix + String(nextNumber).padStart(7, '0');
    } catch (error) { return prefix + String(Math.floor(Math.random() * 10000000)).padStart(7, '0'); }
}

app.post('/api/products', async (req, res) => {
    try {
        if (!req.body.productId || req.body.productId.trim() === '') req.body.productId = await generateAutoId(req.body.category);
        const newProduct = new Product(req.body);
        await newProduct.save();
        res.json({ message: "Thêm sản phẩm thành công!" });
    } catch (err) { res.status(500).json({ message: "Lỗi lưu sản phẩm!" }); }
});

app.put('/api/products/:id', async (req, res) => {
    try {
        if (!req.body.productId || req.body.productId.trim() === '') req.body.productId = await generateAutoId(req.body.category);
        if (req.body.stock !== undefined && parseInt(req.body.stock) <= 0) { req.body.stock = 0; req.body.status = 'Hết hàng'; }
        await Product.findByIdAndUpdate(req.params.id, req.body);
        res.json({ message: "Cập nhật thành công!" });
    } catch (err) { res.status(500).json({ message: "Lỗi cập nhật!" }); }
});

app.delete('/api/products/:id', async (req, res) => {
    try { await Product.findByIdAndDelete(req.params.id); res.json({ message: "Xóa thành công!" }); } catch (err) { res.status(500).json({ message: "Lỗi xóa!" }); }
});

app.put('/api/products/:id/view', async (req, res) => {
    try {
        const key = req.params.id; let query = mongoose.Types.ObjectId.isValid(key) ? { _id: key } : { productId: key };
        const sp = await Product.findOneAndUpdate(query, { $inc: { views: 1 } }, { returnDocument: 'after' });
        if (sp) res.json({ success: true, views: sp.views }); else res.status(404).json({ success: false });
    } catch (err) { res.status(500).json({ success: false }); }
});

app.post('/api/orders', async (req, res) => {
    try {
        const newOrder = new Order(req.body);
        await newOrder.save();

        if (newOrder.items && newOrder.items.length > 0) {
            for (let item of newOrder.items) {
                let qtyNum = parseInt(item.quantity) || 1; let realId = item.id || item._id; 
                if (realId && mongoose.Types.ObjectId.isValid(realId)) {
                    let product = await Product.findById(realId);
                    if (product) {
                        product.stock = (product.stock !== undefined ? product.stock : 10) - qtyNum;
                        if (product.stock <= 0) { product.stock = 0; product.status = 'Hết hàng'; }
                        await product.save();
                    }
                }
            }
        }

        let cusName = newOrder.username; let cusPhone = "Đang cập nhật"; let cusAddress = "Đang cập nhật";
        const match = newOrder.username.match(/(.+?)\s*\((.+?)\s*-\s*(.+)\)/);
        if (match) { cusName = match[1]; cusPhone = match[2]; cusAddress = match[3]; }

        let itemsHtml = "";
        newOrder.items.forEach(item => {
            let priceNum = parseInt(String(item.price).replace(/\D/g, '')) || 0;
            let qtyNum = parseInt(item.quantity) || 1; let itemTotal = priceNum * qtyNum;
            itemsHtml += `<tr><td style="padding: 12px 10px 12px 0; border-bottom: 1px solid #eee;">${item.name}</td><td style="padding: 12px 10px; border-bottom: 1px solid #eee; text-align: center;">${qtyNum}</td><td style="padding: 12px 0 12px 10px; border-bottom: 1px solid #eee; text-align: right; color: #d70018; font-weight: bold;">${new Intl.NumberFormat('vi-VN').format(itemTotal)}đ</td></tr>`;
        });
        let formattedTotal = new Intl.NumberFormat('vi-VN').format(newOrder.total) + ' đ';

        const fullHtmlContent = `
        <div style="font-family: Arial; max-width: 600px; margin: 0 auto; border: 1px solid #eaebec; border-radius: 12px;">
            <div style="background: linear-gradient(135deg, #1435c3 0%, #0a1b66 100%); padding: 30px; text-align: center; color: white;">
                <h1 style="margin: 0;">RAU MÁ PC</h1><p>Đơn hàng của bạn đã được ghi nhận</p>
            </div>
            <div style="padding: 30px;">
                <p>Chào <strong>${cusName}</strong>, cảm ơn bạn đã đặt hàng.</p>
                <h3 style="color: #1435c3; border-bottom: 2px solid #f4f7fe; padding-bottom: 8px;">Mã đơn: #${newOrder.orderId}</h3>
                <p><b>Hình thức:</b> ${newOrder.paymentMethod || 'Thanh toán COD'}</p>
                <p><b>Điện thoại:</b> ${cusPhone}</p><p><b>Địa chỉ:</b> ${cusAddress}</p>
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

app.get('/api/orders', async (req, res) => { try { res.json(await Order.find()); } catch (err) { res.status(500).json({ message: "Lỗi!" }); } });

// ==========================================
// API THỐNG KÊ DOANH THU (TUẦN/THÁNG/NĂM)
// ==========================================
app.get('/api/admin/revenue', async (req, res) => {
    try {
        const orders = await Order.find({ status: "Hoàn thành" });
        let totalRevenue = 0, totalOrders = 0;
        let weekRev = 0, monthRev = 0, yearRev = 0;

        const now = new Date();
        const today = new Date(now.getFullYear(), now.getMonth(), now.getDate());
        
        // Xác định mốc thời gian: Đầu tuần (Thứ 2), Đầu tháng, Đầu năm
        const dayOfWeek = now.getDay() || 7; 
        const startOfWeek = new Date(today);
        startOfWeek.setDate(today.getDate() - dayOfWeek + 1);

        const startOfMonth = new Date(now.getFullYear(), now.getMonth(), 1);
        const startOfYear = new Date(now.getFullYear(), 0, 1);

        orders.forEach(o => {
            totalRevenue += o.total || 0;
            totalOrders++;
            
            // Bóc tách ngày tháng từ chuỗi (Ví dụ: "16:45:00 19/09/2026" -> 19, 09, 2026)
            let dateStr = o.date || "";
            let dMatch = dateStr.match(/(\d{1,2})[\/\-](\d{1,2})[\/\-](\d{4})/);
            if(dMatch) {
                let oDate = new Date(dMatch[3], dMatch[2]-1, dMatch[1]);
                if(oDate >= startOfWeek) weekRev += o.total || 0;
                if(oDate >= startOfMonth) monthRev += o.total || 0;
                if(oDate >= startOfYear) yearRev += o.total || 0;
            }
        });

        res.json({ totalRevenue, totalOrders, weekRev, monthRev, yearRev });
    } catch (err) { res.status(500).json({ message: "Lỗi thống kê!" }); }
});

// ==========================================
// API VẼ BIỂU ĐỒ DOANH THU THEO NGÀY (CẢI TIẾN)
// ==========================================
app.get('/api/admin/revenue-chart', verifyToken, async (req, res) => {
    if (req.user.role !== 'admin') return res.status(403).json({ message: "Từ chối quyền truy cập!" });
    try {
        const orders = await Order.find({ status: "Hoàn thành" });
        const chartData = {};
        
        orders.forEach(order => {
            let dateStr = order.date || "";
            let dMatch = dateStr.match(/(\d{1,2})[\/\-](\d{1,2})[\/\-](\d{4})/);
            // Chuẩn hóa định dạng ngày để vẽ biểu đồ cho đẹp
            let datePart = dMatch ? `${dMatch[1]}/${dMatch[2]}/${dMatch[3]}` : 'Chưa rõ';
            
            if (!chartData[datePart]) chartData[datePart] = 0;
            chartData[datePart] += order.total;
        });
        
        res.json({ labels: Object.keys(chartData), data: Object.values(chartData) });
    } catch (err) { res.status(500).json({ message: "Lỗi vẽ biểu đồ!" }); }
});

app.put('/api/users/cart', verifyToken, async (req, res) => {
    try { await User.findByIdAndUpdate(req.user.id, { cart: req.body.cart }); res.json({ success: true, message: "Đã đồng bộ giỏ hàng" }); } catch (err) { res.status(500).json({ success: false, message: "Lỗi đồng bộ" }); }
});

app.put('/api/orders/:id/status', async (req, res) => {
    try { await Order.findOneAndUpdate({ orderId: req.params.id }, { status: req.body.status }); res.json({ message: "Cập nhật thành công!" }); } catch (err) { res.status(500).json({ message: "Lỗi hệ thống!" }); }
});

app.delete('/api/orders/:id', async (req, res) => {
    try { await Order.findOneAndDelete({ orderId: req.params.id }); res.json({ success: true, message: "Đã xóa đơn hàng!" }); } catch (err) { res.status(500).json({ success: false, message: "Lỗi xóa đơn hàng!" }); }
});

app.post('/api/products/:id/comments', async (req, res) => {
    try {
        const { userName, userAvatar, content, rating, img } = req.body;
        const product = await Product.findById(req.params.id);
        if (!product) return res.status(404).json({ success: false, message: "Sản phẩm không tồn tại!" });

        const newComment = { id: Date.now().toString(), userName: userName || "Khách", userAvatar: userAvatar || "", content: content, rating: rating || 5, img: img || null, date: new Date().toLocaleDateString('vi-VN') + ' ' + new Date().toLocaleTimeString('vi-VN', {hour: '2-digit', minute:'2-digit'}) };
        product.comments.push(newComment); await product.save();
        res.json({ success: true, message: "Đã gửi bình luận!", comments: product.comments });
    } catch (err) { res.status(500).json({ success: false, message: "Lỗi máy chủ!" }); }
});

app.post('/api/users/me/update', verifyToken, async (req, res) => {
    try {
        const { phone, email, otp, avatar } = req.body;
        let user = await User.findById(req.user.id);
        if (!user) return res.status(404).json({ success: false, message: "Không tìm thấy người dùng."});

        if (email && email !== user.email) {
             const cached = otpCache[email];
            if (!cached || Date.now() > cached.expiresAt || cached.code !== otp) return res.status(400).json({ success: false, message: "Mã OTP không hợp lệ!" });
            user.email = email; delete otpCache[email]; 
        }
        if (phone) user.phone = phone; if (avatar) user.avatar = avatar;
        await user.save();
        res.json({ success: true, message: "Cập nhật thành công!", user: { username: user.username, fullName: user.fullName, role: user.role, email: user.email, phone: user.phone, cart: user.cart, avatar: user.avatar, createdAt: user.createdAt } });
    } catch (err) { res.status(500).json({ success: false, message: "Lỗi máy chủ!" }); }
});

app.delete('/api/users/me', verifyToken, async (req, res) => {
    try { if (req.user.role === 'admin') await Admin.findByIdAndDelete(req.user.id); else await User.findByIdAndDelete(req.user.id); res.json({ success: true, message: "Đã xóa tài khoản!" }); } catch (err) { res.status(500).json({ success: false }); }
});

app.get('/api/settings/home', async (req, res) => { try { const homeSettings = await Setting.findOne({ key: 'homeConfig' }); res.json(homeSettings ? homeSettings.data : {}); } catch (err) { res.status(500).json({}); } });
app.put('/api/settings/home', verifyToken, async (req, res) => {
    if (req.user.role !== 'admin') return res.status(403).json({ success: false, message: "Từ chối!" });
    try { await Setting.findOneAndUpdate({ key: 'homeConfig' }, { data: req.body }, { upsert: true, new: true }); res.json({ success: true, message: "Đã đồng bộ!" }); } catch (err) { res.status(500).json({ success: false }); }
});

app.get('/api/admin/coupons', verifyToken, async (req, res) => {
    if (req.user.role !== 'admin') return res.status(403).json({ message: "Từ chối truy cập!" });
    try { res.json(await Coupon.find().sort({ createdAt: -1 })); } catch (err) { res.status(500).json({ message: "Lỗi hệ thống!" }); }
});

app.post('/api/admin/coupons', verifyToken, async (req, res) => {
    if (req.user.role !== 'admin') return res.status(403).json({ message: "Từ chối truy cập!" });
    try {
        req.body.code = req.body.code.toUpperCase();
        const existing = await Coupon.findOne({ code: req.body.code });
        if (existing) return res.status(400).json({ success: false, message: "Mã giảm giá này đã tồn tại!" });
        const newCoupon = new Coupon(req.body); await newCoupon.save();
        res.json({ success: true, message: "Thêm Voucher thành công!" });
    } catch (err) { res.status(500).json({ success: false, message: "Lỗi lưu Voucher!" }); }
});

app.delete('/api/admin/coupons/:id', verifyToken, async (req, res) => {
    if (req.user.role !== 'admin') return res.status(403).json({ message: "Từ chối truy cập!" });
    try { await Coupon.findByIdAndDelete(req.params.id); res.json({ success: true, message: "Đã xóa Voucher!" }); } catch (err) { res.status(500).json({ success: false, message: "Lỗi xóa Voucher!" }); }
});

app.post('/api/coupons/apply', async (req, res) => {
    try {
        const { code } = req.body;
        const coupon = await Coupon.findOne({ code: code.toUpperCase(), isActive: true });
        if (!coupon) return res.status(404).json({ success: false, message: "Mã giảm giá không hợp lệ hoặc đã bị khóa!" });
        res.json({ success: true, discountPercent: coupon.discountPercent, message: `Áp dụng thành công! Đơn hàng được giảm ${coupon.discountPercent}%` });
    } catch (err) { res.status(500).json({ success: false, message: "Lỗi hệ thống!" }); }
});

// ==========================================
// API QUẢN TRỊ KHÁCH HÀNG (THÊM TÍNH NĂNG KHÓA TÀI KHOẢN)
// ==========================================
app.get('/api/admin/users', verifyToken, async (req, res) => {
    if (req.user.role !== 'admin') return res.status(403).json({ message: "Từ chối truy cập!" });
    try { 
        const users = await User.find({ role: 'user' }).select('-password').sort({ createdAt: -1 });
        res.json(users); 
    } catch (err) { res.status(500).json({ message: "Lỗi hệ thống!" }); }
});

// API Toggle Khóa/Mở Khóa tài khoản
app.put('/api/admin/users/:id/lock', verifyToken, async (req, res) => {
    if (req.user.role !== 'admin') return res.status(403).json({ message: "Từ chối truy cập!" });
    try {
        let user = await User.findById(req.params.id);
        if (!user) return res.status(404).json({ success: false, message: "Không tìm thấy user!" });
        
        user.isLocked = !user.isLocked; // Đảo ngược trạng thái khóa
        await user.save();
        res.json({ success: true, message: user.isLocked ? "Đã khóa tài khoản thành công!" : "Đã mở khóa tài khoản!" });
    } catch (err) { res.status(500).json({ success: false, message: "Lỗi thực thi!" }); }
});

app.delete('/api/admin/users/:id', verifyToken, async (req, res) => {
    if (req.user.role !== 'admin') return res.status(403).json({ message: "Từ chối truy cập!" });
    try { 
        await User.findByIdAndDelete(req.params.id); 
        res.json({ success: true, message: "Đã xóa vĩnh viễn tài khoản!" }); 
    } catch (err) { res.status(500).json({ success: false, message: "Lỗi xóa tài khoản!" }); }
});

// API Đổi Mật Khẩu Khách Hàng Bởi Admin (Bypass mật khẩu cũ, tự động mã hóa bcrypt)
app.put('/api/admin/users/:id/change-password', verifyToken, async (req, res) => {
    if (req.user.role !== 'admin') return res.status(403).json({ message: "Từ chối truy cập!" });
    
    try {
        const { newPassword } = req.body;
        if (!newPassword || newPassword.length < 6) {
            return res.status(400).json({ success: false, message: "Mật khẩu mới phải từ 6 ký tự trở lên!" });
        }
        
        let user = await User.findById(req.params.id);
        if (!user) return res.status(404).json({ success: false, message: "Không tìm thấy tài khoản khách hàng này!" });
        
        // Mã hóa mật khẩu mới bằng thuật toán bcrypt
        const salt = await bcrypt.genSalt(10);
        user.password = await bcrypt.hash(newPassword, salt);
        await user.save();
        
        res.json({ success: true, message: `Đã đổi mật khẩu cho khách hàng [${user.username}] thành công!` });
    } catch (err) { 
        res.status(500).json({ success: false, message: "Lỗi hệ thống máy chủ!" }); 
    }
});

// ==========================================
// API ĐỔI MẬT KHẨU ADMIN (CHỈ CẦN NHẬP MẬT KHẨU MỚI)
// ==========================================
app.post('/api/admin/change-password', verifyToken, async (req, res) => {
    // 1. Chặn đứng nếu không phải Admin
    if (req.user.role !== 'admin') return res.status(403).json({ message: "Từ chối truy cập!" });
    
    try {
        const { newPassword } = req.body;
        if (!newPassword || newPassword.length < 6) {
            return res.status(400).json({ success: false, message: "Mật khẩu mới phải từ 6 ký tự trở lên!" });
        }
        
        let admin = await Admin.findById(req.user.id);
        if (!admin) return res.status(404).json({ success: false, message: "Không tìm thấy tài khoản Admin!" });
        
        // 2. Mã hóa mật khẩu mới bằng bcrypt trước khi lưu
        const salt = await bcrypt.genSalt(10);
        admin.password = await bcrypt.hash(newPassword, salt);
        await admin.save();
        
        res.json({ success: true, message: "Đã đổi mật khẩu Admin thành công!" });
    } catch (err) { 
        res.status(500).json({ success: false, message: "Lỗi hệ thống máy chủ!" }); 
    }
});

app.get('/api/health', (req, res) => { res.json({ status: 'ok', time: new Date().toISOString() }); });
app.listen(process.env.PORT || 3000, () => console.log(`✅ Máy chủ đang chạy ở chuẩn bảo mật Doanh Nghiệp`));