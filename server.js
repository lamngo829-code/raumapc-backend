require('dotenv').config();

// Theo dõi lỗi production (tùy chọn) - chỉ bật khi đã cấu hình SENTRY_DSN trong biến môi trường.
// Nếu chưa có tài khoản Sentry (sentry.io, có gói miễn phí) thì bỏ qua, code vẫn chạy bình thường.
let Sentry = null;
if (process.env.SENTRY_DSN) {
    Sentry = require('@sentry/node');
    Sentry.init({ dsn: process.env.SENTRY_DSN, tracesSampleRate: 0.1, environment: process.env.NODE_ENV || 'production' });
    process.on('uncaughtException', (err) => Sentry.captureException(err));
    process.on('unhandledRejection', (err) => Sentry.captureException(err));
}

const geoip = require('geoip-lite');
const express = require('express');
const cors = require('cors');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const querystring = require('querystring');

const cloudinary = require('cloudinary').v2;

const { OAuth2Client } = require('google-auth-library');
const googleClient = new OAuth2Client(process.env.GOOGLE_CLIENT_ID);

cloudinary.config({
    cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
    api_key: process.env.CLOUDINARY_API_KEY,
    api_secret: process.env.CLOUDINARY_API_SECRET
});

async function uploadBase64ToCloud(base64String, folderName) {
    // 1. Nếu không có gì hoặc đã là link có sẵn (http) thì trả về nguyên vẹn
    if (!base64String || typeof base64String !== 'string' || !base64String.startsWith('data:image')) {
        return base64String || "";
    }

    try {
        const result = await cloudinary.uploader.upload(base64String, {
            folder: folderName,
            fetch_format: 'auto',
            quality: 'auto'
        });

        // 2. Ép kiểu đảm bảo luôn luôn trả về một chuỗi URL hợp lệ
        if (result && result.secure_url) {
            return String(result.secure_url);
        }
        return "";
    } catch (error) {
        console.error("Lỗi upload Cloudinary:", error);
        return ""; // Trả về chuỗi rỗng nếu lỗi, tránh sập Database
    }
}

// Hàm hỗ trợ "Tiêu hủy" ảnh cũ trên Cloudinary
async function deleteCloudinaryImage(imageUrl) {
    if (!imageUrl || !imageUrl.includes('res.cloudinary.com')) return;
    try {
        // Tách lấy public_id từ đường link URL
        const parts = imageUrl.split('/upload/');
        if (parts.length === 2) {
            const pathWithoutVersion = parts[1].replace(/^v\d+\//, ''); // Bỏ mã phiên bản (vd: v1234567/)
            const publicId = pathWithoutVersion.substring(0, pathWithoutVersion.lastIndexOf('.')); // Bỏ đuôi file (.jpg, .png)

            if (publicId) {
                await cloudinary.uploader.destroy(publicId);
                console.log("🗑 Đã xóa ảnh cũ trên mây:", publicId);
            }
        }
    } catch (error) {
        console.error("Lỗi xóa ảnh Cloudinary:", error);
    }
}

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

// ==========================================
// HỆ THỐNG CACHE (BỘ NHỚ ĐỆM RAM)
// ==========================================
const NodeCache = require("node-cache");
// Lưu cache trong 5 phút (300 giây). Tự động xóa cache cũ sau 5 phút.
const myCache = new NodeCache({ stdTTL: 300, checkperiod: 320 });

// Lính gác Cache: Bắt giữ các yêu cầu GET
const cacheMiddleware = (req, res, next) => {
    // Chỉ Cache các API lấy dữ liệu (GET)
    if (req.method !== 'GET') return next();

    // Dùng chính đường dẫn URL làm chìa khóa (VD: /api/products?limit=50)
    const key = req.originalUrl;
    const cachedResponse = myCache.get(key);

    if (cachedResponse) {
        // NẾU TRONG RAM ĐÃ CÓ: Trả về luôn, không cần hỏi MongoDB
        return res.json(cachedResponse);
    } else {
        // NẾU CHƯA CÓ: Lưu tạm hàm res.json gốc lại
        res.originalJson = res.json;
        // Viết lại hàm res.json để khi API gọi trả dữ liệu, nó sẽ tiện tay lưu luôn vào RAM
        res.json = (body) => {
            myCache.set(key, body);
            res.originalJson(body);
        };
        next();
    }
};

// Hàm "Kích hoạt nổ" để xóa sạch Cache khi có biến động dữ liệu
const clearCache = () => {
    myCache.flushAll();
    console.log('🧹 Đã dọn dẹp toàn bộ Cache!');
};

app.use(express.json({ limit: '2mb' }));
app.use(express.urlencoded({ limit: '2mb', extended: true }));

const rateLimit = require('express-rate-limit');
const globalLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 300, message: { success: false, message: "Hệ thống đang quá tải từ thiết bị của bạn. Vui lòng thử lại sau 15 phút!" } });
app.use(globalLimiter);

// BẢO MẬT BRUTE-FORCE: Siết chặt giới hạn Spam cho mọi API liên quan đến xác thực
const authLimiter = rateLimit({ windowMs: 5 * 60 * 1000, max: 5, message: { success: false, message: "Phát hiện dấu hiệu dò mật khẩu/OTP! Vui lòng thao tác chậm lại hoặc thử lại sau 5 phút." } });

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

// KÍCH HOẠT LÁ CHẮN BRUTE-FORCE CHO TOÀN BỘ API QUAN TRỌNG
app.use('/api/login', authLimiter);
app.use('/api/login-verify', authLimiter);
app.use('/api/register', authLimiter);
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
    productId: String, name: String, price: Number, img: String, warranty: String,
    importPrice: { type: Number, default: 0 },
    status: { type: String, default: 'Còn hàng' },
    stock: { type: Number, default: 10 },
    specs: String, description: String, category: String, brand: String,
    views: { type: Number, default: 0 }, comments: { type: Array, default: [] }, gallery: { type: Array, default: [] }
});
productSchema.index({ name: 'text' });
const Product = mongoose.model('Product', productSchema);

const orderSchema = new mongoose.Schema({ 
    orderId: String, date: String, username: String, account: String, 
    email: String, items: Array, total: Number, status: String, paymentMethod: String,
    createdAt: { type: Date, default: Date.now },
    totalImportPrice: { type: Number, default: 0 },
});
const Order = mongoose.model('Order', orderSchema);

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

// Lưu mã OTP vào MongoDB thay vì RAM để không bị mất khi server restart (Render free tier tự
// "ngủ" và khởi động lại khi rảnh). expiresAt có index TTL - MongoDB tự xóa document đã hết hạn.
const otpSchema = new mongoose.Schema({
    email: { type: String, required: true, unique: true },
    code: { type: String, required: true },
    expiresAt: { type: Date, required: true, index: { expires: 0 } }
});
const Otp = mongoose.model('Otp', otpSchema);

async function saveOtp(email, code) {
    await Otp.findOneAndUpdate(
        { email },
        { code, expiresAt: new Date(Date.now() + 60000) },
        { upsert: true }
    );
}

// Kiểm tra mã OTP có đúng và còn hạn không - KHÔNG tự xóa (nơi gọi tự xóa sau khi dùng xong,
// vì có chỗ cần kiểm tra OTP xong rồi mới thao tác DB tiếp, xóa quá sớm sẽ mất OTP giữa chừng)
async function checkOtp(email, code) {
    const record = await Otp.findOne({ email });
    if (!record) return false;
    if (Date.now() > record.expiresAt.getTime()) return false;
    return record.code === String(code);
}

async function clearOtp(email) {
    await Otp.deleteOne({ email });
}

const verifyToken = async (req, res, next) => {
    const token = req.headers['authorization'];
    if (!token) return res.status(403).json({ message: "Bạn chưa đăng nhập!" });
    try {
        const decoded = jwt.verify(token.split(" ")[1], JWT_SECRET);
        let user = await User.findById(decoded.id) || await Admin.findById(decoded.id);
        if (!user) return res.status(401).json({ message: "Tài khoản đã bị xóa khỏi hệ thống!", accountDeleted: true });
        if (user.isLocked) return res.status(401).json({ message: "Tài khoản của bạn đã bị khóa do vi phạm!", accountDeleted: true });
        req.user = decoded; next();
    } catch (err) { return res.status(401).json({ message: "Phiên đăng nhập hết hạn!" }); }
};

// KIỂM TRA BẢO MẬT VÀ TRẢ VỀ GIỎ HÀNG MỚI NHẤT TỪ CLOUD
app.get('/api/auth/verify', verifyToken, async (req, res) => {
    try {
        let user = await User.findById(req.user.id) || await Admin.findById(req.user.id);
        res.json({
            success: true,
            // Trả về giỏ hàng mới nhất lưu trong Database
            cart: user ? user.cart : []
        });
    } catch (err) {
        res.json({ success: true });
    }
});

app.get('/api/setup-admin', async (req, res) => {
    try {
        // Bảo mật: bắt buộc phải biết ADMIN_PASS thì mới được phép khởi tạo Admin
        // (route này không thể dùng verifyToken vì lúc gọi chưa hề có tài khoản Admin nào)
        if (!process.env.ADMIN_PASS || req.query.key !== process.env.ADMIN_PASS) {
            return res.status(403).send("<h3>Từ chối truy cập!</h3>");
        }
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
        const existingAdmin = await Admin.findOne({ username: String(username) });
        if (existingAdmin) return res.status(400).json({ success: false, message: "Tài khoản Admin này đã tồn tại!" });
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);
        const newAdmin = new Admin({ fullName, username, password: hashedPassword, role: "admin" });
        await newAdmin.save();
        res.json({ success: true, message: `Đã tạo thành công Admin: ${fullName} (${username})` });
    } catch (err) { res.status(500).json({ success: false, message: "Lỗi hệ thống!" }); }
});

app.post('/api/request-register-otp', async (req, res) => {
    try {
        const email = String(req.body.email);
        const username = String(req.body.username);

        const existingUser = await User.findOne({ $or: [{ email: email }, { username: username }] });
        if (existingUser) return res.status(400).json({ success: false, message: "Email hoặc Tên đăng nhập đã được sử dụng!" });

        const otpCode = crypto.randomInt(100000, 1000000).toString();
        await saveOtp(email, otpCode);

        const htmlContent = `
        <div style="font-family: 'Segoe UI', Arial, sans-serif; max-width: 500px; margin: 0 auto; border: 1px solid #eaebec; border-radius: 12px; overflow: hidden; box-shadow: 0 4px 15px rgba(0,0,0,0.05);">
            <div style="background: linear-gradient(135deg, #1435c3 0%, #0a1b66 100%); padding: 25px; text-align: center;">
                <img src="https://github.com/lamngo829-code/raumapc-frontend/blob/main/assets/images/icons/logo-sticky.jpg?raw=true" alt="Logo" style="width: 60px; height: 60px; border-radius: 50%; box-shadow: 0 2px 5px rgba(0,0,0,0.2); display: inline-block;">
                <h2 style="color: white; margin: 10px 0 0; font-size: 24px; letter-spacing: 1px;">RAU MÁ PC</h2>
            </div>
            <div style="padding: 30px; background: #ffffff;">
                <h3 style="color: #1e293b; font-size: 18px; margin-top: 0; text-align: center;">MÃ OTP ĐĂNG KÝ TÀI KHOẢN</h3>
                <p style="color: #475569; font-size: 15px; line-height: 1.6; text-align: center;">Xin chào bạn,</p>
                <p style="color: #475569; font-size: 15px; line-height: 1.6; text-align: center;">Bạn vừa yêu cầu mã xác nhận để đăng ký tài khoản. Dưới đây là mã OTP của bạn:</p>
                <div style="background: #f8fafc; border: 2px dashed #1435c3; border-radius: 8px; padding: 20px; text-align: center; margin: 25px 0;">
                    <h1 style="margin: 0; color: #d70018; font-size: 38px; letter-spacing: 8px;">${otpCode}</h1>
                </div>
                <p style="color: #dc2626; font-size: 14px; text-align: center; font-weight: bold; margin-bottom: 5px;">⚠️ Mã này chỉ có hiệu lực trong đúng 60 giây.</p>
                <p style="color: #64748b; font-size: 13px; text-align: center; margin-top: 0;">Tuyệt đối không chia sẻ mã này cho bất kỳ ai để bảo vệ an toàn.</p>
            </div>
            <div style="background: #f1f5f9; padding: 20px; text-align: center; border-top: 1px solid #eaebec;">
                <p style="margin: 0; color: #94a3b8; font-size: 12px;">© 2026 Rau Má PC. All rights reserved.</p>
            </div>
        </div>`;
        const emailData = { service_id: process.env.EMAILJS_SERVICE_ID, template_id: process.env.EMAILJS_TEMPLATE_ID, user_id: process.env.EMAILJS_USER_ID, accessToken: process.env.EMAILJS_TOKEN, template_params: { to_email: email, subject: '[Rau Má PC] Mã OTP Đăng Ký Tài Khoản', message: htmlContent } };
        fetch('https://api.emailjs.com/api/v1.0/email/send', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(emailData) }).catch(e => console.log(e));
        res.json({ success: true, message: "Mã OTP đăng ký đã được gửi đến Email!" });
    } catch (err) { res.status(500).json({ success: false, message: "Lỗi hệ thống!" }); }
});

app.post('/api/register', async (req, res) => {
    try {
        const { fullName, username, password, phone, email, otp } = req.body;
        const safeEmail = String(email);
        if (!(await checkOtp(safeEmail, otp))) return res.status(400).json({ success: false, message: "Mã OTP không hợp lệ hoặc đã hết hạn!" });
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);
        const newUser = new User({ fullName, username, password: hashedPassword, phone, email: safeEmail });
        await newUser.save();
        await clearOtp(safeEmail);
        res.json({ success: true, message: "Đăng ký thành công!" });
    } catch (err) { res.status(500).json({ success: false, message: "Lỗi máy chủ!" }); }
});

app.post('/api/login', async (req, res) => {
    try {
        const loginId = String(req.body.username);

        let user = await User.findOne({ $or: [{ username: loginId }, { email: loginId }] });
        let isRole = 'user';
        if (!user) { user = await Admin.findOne({ username: loginId }); isRole = 'admin'; }
        if (!user) return res.status(401).json({ success: false, message: "Sai tài khoản hoặc Email!" });

        if (user.isLocked) return res.status(403).json({ success: false, message: "Tài khoản của bạn đã bị Admin khóa do vi phạm chính sách!" });

        const isMatch = await bcrypt.compare(String(req.body.password), user.password);
        if (!isMatch) return res.status(401).json({ success: false, message: "Sai mật khẩu!" });

        if (isRole === 'admin') {
            const token = jwt.sign({ id: user._id, username: user.username, role: isRole }, JWT_SECRET, { expiresIn: '7d' });
            return res.json({ success: true, token, user: { username: user.username, fullName: user.fullName, role: isRole, avatar: user.avatar }, requireOtp: false });
        }

        const otpCode = crypto.randomInt(100000, 1000000).toString();
        await saveOtp(user.email, otpCode);

        const htmlContent = `
        <div style="font-family: 'Segoe UI', Arial, sans-serif; max-width: 500px; margin: 0 auto; border: 1px solid #eaebec; border-radius: 12px; overflow: hidden; box-shadow: 0 4px 15px rgba(0,0,0,0.05);">
            <div style="background: linear-gradient(135deg, #1435c3 0%, #0a1b66 100%); padding: 25px; text-align: center;">
                <img src="https://github.com/lamngo829-code/raumapc-frontend/blob/main/assets/images/icons/logo-sticky.jpg?raw=true" alt="Logo" style="width: 60px; height: 60px; border-radius: 50%; box-shadow: 0 2px 5px rgba(0,0,0,0.2); display: inline-block;">
                <h2 style="color: white; margin: 10px 0 0; font-size: 24px; letter-spacing: 1px;">RAU MÁ PC</h2>
            </div>
            <div style="padding: 30px; background: #ffffff;">
                <h3 style="color: #1e293b; font-size: 18px; margin-top: 0; text-align: center;">MÃ OTP ĐĂNG NHẬP BẢO MẬT</h3>
                <p style="color: #475569; font-size: 15px; line-height: 1.6; text-align: center;">Chào <strong>${user.fullName}</strong>,</p>
                <p style="color: #475569; font-size: 15px; line-height: 1.6; text-align: center;">Hệ thống vừa ghi nhận một yêu cầu đăng nhập vào tài khoản của bạn. Dưới đây là mã OTP:</p>
                <div style="background: #f8fafc; border: 2px dashed #1435c3; border-radius: 8px; padding: 20px; text-align: center; margin: 25px 0;">
                    <h1 style="margin: 0; color: #d70018; font-size: 38px; letter-spacing: 8px;">${otpCode}</h1>
                </div>
                <p style="color: #dc2626; font-size: 14px; text-align: center; font-weight: bold; margin-bottom: 5px;">⚠️ Mã này chỉ có hiệu lực trong đúng 60 giây.</p>
                <p style="color: #64748b; font-size: 13px; text-align: center; margin-top: 0;">Tuyệt đối không chia sẻ mã này cho bất kỳ ai để bảo vệ an toàn.</p>
            </div>
            <div style="background: #f1f5f9; padding: 20px; text-align: center; border-top: 1px solid #eaebec;">
                <p style="margin: 0; color: #94a3b8; font-size: 12px;">© 2026 Rau Má PC. All rights reserved.</p>
            </div>
        </div>`;
        const emailData = { service_id: process.env.EMAILJS_SERVICE_ID, template_id: process.env.EMAILJS_TEMPLATE_ID, user_id: process.env.EMAILJS_USER_ID, accessToken: process.env.EMAILJS_TOKEN, template_params: { to_email: user.email, subject: '[Rau Má PC] Mã OTP Đăng Nhập', message: htmlContent } };
        fetch('https://api.emailjs.com/api/v1.0/email/send', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(emailData) }).catch(e => console.log(e));
        res.json({ success: true, requireOtp: true, email: user.email, message: "Mã OTP đã được gửi đến email." });
    } catch (err) { res.status(500).json({ success: false, message: "Lỗi máy chủ!" }); }
});

app.get('/api/config/google', (req, res) => {
    res.json({ clientId: process.env.GOOGLE_CLIENT_ID });
});

// ==========================================
// API: ĐĂNG NHẬP / ĐĂNG KÝ BẰNG GOOGLE OAUTH
// ==========================================
app.post('/api/auth/google', async (req, res) => {
    try {
        const { credential } = req.body;

        // 1. Nhờ thư viện Google kiểm tra xem mã Token mà Frontend gửi lên có phải đồ thật không
        const ticket = await googleClient.verifyIdToken({
            idToken: credential,
            audience: process.env.GOOGLE_CLIENT_ID,
        });

        const payload = ticket.getPayload();
        const { email, name, picture } = payload; // Rút trích thông tin từ Google

        // 2. Kiểm tra xem Email này đã từng đăng ký ở Rau Má PC chưa
        let user = await User.findOne({ email: email });

        if (!user) {
            // NẾU LÀ NGƯỜI MỚI TOANH: Tự động tạo tài khoản luôn mà không cần hỏi thêm
            const salt = await bcrypt.genSalt(10);
            // Tạo một mật khẩu ngẫu nhiên siêu khó (vì họ sẽ đăng nhập bằng Google)
            const randomPassword = await bcrypt.hash(crypto.randomBytes(16).toString('hex'), salt);

            // Tự động tạo Username dựa trên tên Email
            let baseUsername = email.split('@')[0].replace(/[^a-zA-Z0-9]/g, '').toLowerCase();
            let uniqueUsername = baseUsername;
            let counter = 1;
            while (await User.findOne({ username: uniqueUsername })) {
                uniqueUsername = baseUsername + counter;
                counter++;
            }

            user = new User({
                fullName: name,
                username: uniqueUsername,
                password: randomPassword,
                phone: "Chưa cập nhật",
                email: email,
                avatar: picture // Lấy luôn ảnh đại diện từ Google
            });
            await user.save();
        }

        if (user.isLocked) return res.status(403).json({ success: false, message: "Tài khoản của bạn đã bị khóa do vi phạm chính sách!" });

        // 3. Đăng nhập thành công, tạo Token và gửi về Frontend
        const now = new Date().toLocaleString('vi-VN', { hour12: false });
        user.loginHistory.push(now);
        await user.save();

        const token = jwt.sign({ id: user._id, username: user.username, role: 'user' }, process.env.JWT_SECRET, { expiresIn: '7d' });
        const userData = { username: user.username, fullName: user.fullName, role: 'user', email: user.email, phone: user.phone, cart: user.cart, avatar: user.avatar, createdAt: user.createdAt };

        res.json({ success: true, token, user: userData, message: "Đăng nhập Google thành công!" });

    } catch (error) {
        console.error("Lỗi Google Auth:", error);
        res.status(401).json({ success: false, message: "Xác thực Google thất bại hoặc hết hạn!" });
    }
});

app.post('/api/login-verify', async (req, res) => {
    try {
        const safeEmail = String(req.body.email);
        const safeOtp = String(req.body.otp);

        if (!(await checkOtp(safeEmail, safeOtp))) return res.status(400).json({ success: false, message: "Mã OTP không hợp lệ hoặc đã hết hạn!" });

        const user = await User.findOne({ email: safeEmail });
        const now = new Date().toLocaleString('vi-VN', { hour12: false });
        user.loginHistory.push(now);
        await user.save();

        const token = jwt.sign({ id: user._id, username: user.username, role: 'user' }, JWT_SECRET, { expiresIn: '7d' });
        const userData = { username: user.username, fullName: user.fullName, role: 'user', email: user.email, phone: user.phone, cart: user.cart, avatar: user.avatar, createdAt: user.createdAt };
        await clearOtp(safeEmail);
        res.json({ success: true, token, user: userData });
    } catch (err) { res.status(500).json({ success: false, message: "Lỗi máy chủ!" }); }
});

app.post('/api/request-otp', async (req, res) => {
    try {
        const email = String(req.body.email);
        const user = await User.findOne({ email: email });
        if (!user) return res.status(404).json({ success: false, message: "Email không tồn tại!" });

        const otpCode = crypto.randomInt(100000, 1000000).toString();
        await saveOtp(email, otpCode);

        const htmlContent = `
        <div style="font-family: 'Segoe UI', Arial, sans-serif; max-width: 500px; margin: 0 auto; border: 1px solid #eaebec; border-radius: 12px; overflow: hidden; box-shadow: 0 4px 15px rgba(0,0,0,0.05);">
            <div style="background: linear-gradient(135deg, #1435c3 0%, #0a1b66 100%); padding: 25px; text-align: center;">
                <img src="https://github.com/lamngo829-code/raumapc-frontend/blob/main/assets/images/icons/logo-sticky.jpg?raw=true" alt="Logo" style="width: 60px; height: 60px; border-radius: 50%; box-shadow: 0 2px 5px rgba(0,0,0,0.2); display: inline-block;">
                <h2 style="color: white; margin: 10px 0 0; font-size: 24px; letter-spacing: 1px;">RAU MÁ PC</h2>
            </div>
            <div style="padding: 30px; background: #ffffff;">
                <h3 style="color: #1e293b; font-size: 18px; margin-top: 0; text-align: center;">MÃ XÁC NHẬN BẢO MẬT (OTP)</h3>
                <p style="color: #475569; font-size: 15px; line-height: 1.6; text-align: center;">Chào <strong>${user.fullName}</strong>,</p>
                <p style="color: #475569; font-size: 15px; line-height: 1.6; text-align: center;">Hệ thống nhận được yêu cầu thay đổi bảo mật cho tài khoản của bạn. Dưới đây là mã xác nhận:</p>
                <div style="background: #f8fafc; border: 2px dashed #1435c3; border-radius: 8px; padding: 20px; text-align: center; margin: 25px 0;">
                    <h1 style="margin: 0; color: #d70018; font-size: 38px; letter-spacing: 8px;">${otpCode}</h1>
                </div>
                <p style="color: #dc2626; font-size: 14px; text-align: center; font-weight: bold; margin-bottom: 5px;">⚠️ Mã này chỉ có hiệu lực trong đúng 60 giây.</p>
                <p style="color: #64748b; font-size: 13px; text-align: center; margin-top: 0;">Nếu bạn không yêu cầu mã này, vui lòng đổi mật khẩu ngay lập tức.</p>
            </div>
            <div style="background: #f1f5f9; padding: 20px; text-align: center; border-top: 1px solid #eaebec;">
                <p style="margin: 0; color: #94a3b8; font-size: 12px;">© 2026 Rau Má PC. All rights reserved.</p>
            </div>
        </div>`;
        const emailData = { service_id: process.env.EMAILJS_SERVICE_ID, template_id: process.env.EMAILJS_TEMPLATE_ID, user_id: process.env.EMAILJS_USER_ID, accessToken: process.env.EMAILJS_TOKEN, template_params: { to_email: user.email, subject: '[Rau Má PC] Mã OTP Xác Nhận Bảo Mật', message: htmlContent } };
        fetch('https://api.emailjs.com/api/v1.0/email/send', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(emailData) }).catch(e => console.log(e));
        res.json({ success: true, message: "Mã OTP đã gửi qua Email!" });
    } catch (err) { res.status(500).json({ success: false, message: "Lỗi hệ thống!" }); }
});

app.post('/api/forgot-password-verify', async (req, res) => {
    try {
        const { email, otp, newPassword } = req.body;
        const safeEmail = String(email);
        if (!(await checkOtp(safeEmail, otp))) return res.status(400).json({ success: false, message: "Mã OTP không hợp lệ hoặc đã hết hạn!" });

        const user = await User.findOne({ email: safeEmail });
        const salt = await bcrypt.genSalt(10);
        user.password = await bcrypt.hash(newPassword, salt);
        await user.save();
        await clearOtp(safeEmail);
        res.json({ success: true, message: "Khôi phục mật khẩu thành công!" });
    } catch (err) { res.status(500).json({ success: false, message: "Lỗi hệ thống!" }); }
});

app.post('/api/users/change-password', verifyToken, async (req, res) => {
    try {
        const { oldPassword, newPassword } = req.body;
        let user = await User.findById(req.user.id) || await Admin.findById(req.user.id);
        if (!user) return res.status(404).json({ success: false, message: "Không tìm thấy người dùng." });

        const isMatch = await bcrypt.compare(String(oldPassword), user.password);
        if (!isMatch) return res.status(400).json({ success: false, message: "Mật khẩu hiện tại không chính xác!" });

        const salt = await bcrypt.genSalt(10);
        user.password = await bcrypt.hash(newPassword, salt);
        await user.save();
        res.json({ success: true, message: "Đổi mật khẩu thành công! Mật khẩu mới đã được mã hóa an toàn." });
    } catch (err) { res.status(500).json({ success: false, message: "Lỗi hệ thống!" }); }
});

// ==========================================
// API LẤY DANH SÁCH SẢN PHẨM (CÓ BỘ LỌC NÂNG CAO & PHÂN TRANG)
// ==========================================
app.get('/api/products', cacheMiddleware, async (req, res) => {
    try {
        // 1. NHẬN CÁC THAM SỐ TỪ URL (Query Parameters)
        const page = parseInt(req.query.page) || 1;       // Trang hiện tại (Mặc định: 1)
        let limit = parseInt(req.query.limit) || 12;       // Số SP trên mỗi trang (Mặc định: 12)
        if (limit > 2000) limit = 2000;                    // Chặn giá trị limit quá lớn gây quá tải DB
        if (limit < 1) limit = 12;
        const skip = (page - 1) * limit;                  // Tính số lượng SP cần bỏ qua

        // 2. KHỞI TẠO BỘ LỌC (Query Object)
        let filter = {};

        // Lọc theo từ khóa tìm kiếm (Text Search tương đối, không phân biệt hoa thường)
        if (req.query.search) {
            // Tìm trong tên sản phẩm HOẶC mã sản phẩm
            filter.$or = [
                { name: { $regex: req.query.search, $options: 'i' } },
                { productId: { $regex: req.query.search, $options: 'i' } }
            ];
        }

        // Lọc theo danh mục (Hỗ trợ lọc nhiều danh mục cùng lúc, vd: ?category=cpu,vga)
        if (req.query.category) {
            const categories = req.query.category.split(',').map(c => new RegExp(c.trim(), 'i'));
            filter.category = { $in: categories };
        }

        // Lọc theo hãng sản xuất (Brand)
        if (req.query.brand) {
            filter.brand = new RegExp(`^${req.query.brand.trim()}$`, 'i');
        }

        // Lọc theo trạng thái (VD: Chỉ hiện hàng "Còn hàng")
        if (req.query.status) {
            filter.status = req.query.status;
        }

        // =====================================
        // LỌC KHOẢNG GIÁ SIÊU TỐC TRONG MONGODB
        // =====================================
        if (req.query.minPrice !== undefined || req.query.maxPrice !== undefined) {
            filter.price = {};
            if (req.query.minPrice) filter.price.$gte = parseInt(req.query.minPrice); // Lớn hơn hoặc bằng
            if (req.query.maxPrice) filter.price.$lte = parseInt(req.query.maxPrice); // Nhỏ hơn hoặc bằng
        }

        // 3. KHỞI TẠO TÙY CHỌN SẮP XẾP (Sort)
        let sortOption = {};
        if (req.query.sort) {
            if (req.query.sort === 'newest') sortOption._id = -1;       // Mới nhất
            else if (req.query.sort === 'views') sortOption.views = -1; // Xem nhiều nhất
        } else {
            sortOption._id = -1; // Mặc định luôn xếp mới nhất lên đầu
        }

        // 4. THỰC THI TRUY VẤN VÀO MONGODB
        // Đếm tổng số sản phẩm thỏa mãn bộ lọc (để Frontend làm nút phân trang 1 2 3...)
        const totalProducts = await Product.countDocuments(filter);

        // Lấy đúng số lượng sản phẩm của trang hiện tại
        const products = await Product.find(filter)
            .sort(sortOption)
            .skip(skip)
            .limit(limit);

        // 5. FORMAT LẠI DỮ LIỆU ĐỂ TRẢ VỀ FRONTEND (Giữ nguyên cấu trúc cũ của bạn)
        const formattedProducts = products.map(sp => ({
            id: sp._id.toString(),
            productId: sp.productId || sp._id.toString().slice(-6).toUpperCase(),
            name: sp.name,
            price: sp.price,
            importPrice: sp.importPrice || 0,
            img: sp.img,
            warranty: sp.warranty,
            status: sp.status || 'Còn hàng',
            stock: sp.stock !== undefined ? sp.stock : 10,
            category: sp.category,
            brand: sp.brand,
            specs: sp.specs,
            description: sp.description,
            views: sp.views || 0,
            comments: sp.comments,
            gallery: sp.gallery || []
        }));

        // 6. TRẢ KẾT QUẢ VỀ KÈM THÔNG TIN PHÂN TRANG
        res.json({
            success: true,
            data: formattedProducts,
            pagination: {
                totalItems: totalProducts,
                currentPage: page,
                limit: limit,
                totalPages: Math.ceil(totalProducts / limit) // Tổng số trang
            }
        });

    } catch (err) {
        res.status(500).json({ success: false, message: "Lỗi Server khi lọc sản phẩm!" });
    }
});

app.get('/api/products/detail/:id', cacheMiddleware, async (req, res) => {
    try {
        const key = req.params.id;
        let sp = mongoose.Types.ObjectId.isValid(key) ? await Product.findById(key) : null;
        if (!sp) sp = await Product.findOne({ productId: key });
        if (!sp) return res.status(404).json({ message: "Không tìm thấy sản phẩm!" });
        res.json({
            id: sp._id.toString(), productId: sp.productId || sp._id.toString().slice(-6).toUpperCase(),
            name: sp.name, price: sp.price, importPrice: sp.importPrice || 0, img: sp.img, warranty: sp.warranty, status: sp.status || 'Còn hàng',
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

// Tìm sản phẩm theo _id MongoDB (từ trang chi tiết/danh mục) hoặc productId dạng chữ
// (VD: "VGA0000001", từ ô Tìm kiếm) - id lưu trong đơn hàng có thể là 1 trong 2 dạng
async function findProductByAnyId(realId) {
    if (!realId) return null;
    let product = mongoose.Types.ObjectId.isValid(realId) ? await Product.findById(realId) : null;
    if (!product) product = await Product.findOne({ productId: realId });
    return product;
}

const LOW_STOCK_THRESHOLD = 5; // Đồng bộ với ngưỡng "Sắp hết hàng" đang dùng trong trang Admin

// Gửi email cảnh báo cho chủ shop khi 1 sản phẩm vừa tụt xuống dưới ngưỡng tồn kho thấp
function sendLowStockAlert(product) {
    const htmlContent = `
    <div style="font-family: 'Segoe UI', Arial, sans-serif; max-width: 500px; margin: 0 auto; border: 1px solid #eaebec; border-radius: 12px; overflow: hidden;">
        <div style="background: #dc2626; padding: 20px; text-align: center;">
            <h2 style="color: white; margin: 0;">⚠️ CẢNH BÁO SẮP HẾT HÀNG</h2>
        </div>
        <div style="padding: 25px; background: #ffffff;">
            <p style="font-size: 15px; color: #333;">Sản phẩm sau đang sắp hết hàng trong kho:</p>
            <table style="width: 100%; font-size: 14px; line-height: 1.8;">
                <tr><td style="font-weight:bold; width: 120px;">Tên SP:</td><td>${product.name}</td></tr>
                <tr><td style="font-weight:bold;">Mã SP:</td><td>${product.productId}</td></tr>
                <tr><td style="font-weight:bold;">Tồn kho còn:</td><td style="color:#dc2626; font-weight:bold;">${product.stock}</td></tr>
            </table>
            <p style="font-size: 13px; color: #64748b; margin-top: 20px;">Vui lòng vào trang Admin để nhập thêm hàng.</p>
        </div>
    </div>`;
    const emailData = {
        service_id: process.env.EMAILJS_SERVICE_ID,
        template_id: process.env.EMAILJS_TEMPLATE_ID,
        user_id: process.env.EMAILJS_USER_ID,
        accessToken: process.env.EMAILJS_TOKEN,
        template_params: { to_email: "lamngo829@gmail.com", subject: `⚠️ SẮP HẾT HÀNG: ${product.name}`, message: htmlContent }
    };
    fetch('https://api.emailjs.com/api/v1.0/email/send', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(emailData) }).catch(e => console.log(e));
}

// Điều chỉnh tồn kho theo danh sách items của đơn hàng.
// direction = -1 để trừ kho (đặt hàng mới / mở hủy đơn đã hủy), +1 để hoàn kho (hủy đơn)
async function adjustProductStock(items, direction) {
    if (!items || items.length === 0) return;
    for (let item of items) {
        let qtyNum = parseInt(item.quantity) || 1;
        let product = await findProductByAnyId(item.id || item._id);
        if (!product) continue;

        const stockBefore = product.stock !== undefined ? product.stock : 10;
        product.stock = stockBefore + (direction * qtyNum);
        if (product.stock <= 0) {
            product.stock = 0;
            product.status = 'Hết hàng';
        } else if (product.status === 'Hết hàng') {
            product.status = 'Còn hàng';
        }
        await product.save();

        // Chỉ gửi cảnh báo đúng lúc tồn kho VỪA vượt xuống dưới ngưỡng (tránh spam email mỗi đơn hàng)
        if (direction < 0 && stockBefore >= LOW_STOCK_THRESHOLD && product.stock < LOW_STOCK_THRESHOLD) {
            sendLowStockAlert(product);
        }
    }
}

// TẠO SẢN PHẨM MỚI
app.post('/api/products', async (req, res) => {
    try {
        // 1. Quét và đẩy Ảnh chính lên mây
        if (req.body.img) {
            req.body.img = await uploadBase64ToCloud(req.body.img, 'raumapc/products');
        }

        // 2. Quét và đẩy toàn bộ Ảnh phụ (Gallery) lên mây song song
        if (req.body.gallery && Array.isArray(req.body.gallery)) {
            const uploadedGallery = await Promise.all(
                req.body.gallery.map(imgStr => uploadBase64ToCloud(imgStr, 'raumapc/gallery'))
            );
            req.body.gallery = uploadedGallery.filter(url => url !== "");
        }

        // 3. Tiến hành lưu Database với các link ảnh siêu nhẹ
        if (!req.body.productId || req.body.productId.trim() === '') {
            req.body.productId = await generateAutoId(req.body.category);
        }

        const newProduct = new Product(req.body);
        await newProduct.save();
        clearCache(); // Gọi lệnh quét dọn
        res.json({ message: "Thêm sản phẩm thành công!" });
    } catch (err) {
        res.status(500).json({ message: "Lỗi lưu sản phẩm!" });
    }
});

// CẬP NHẬT SẢN PHẨM (SỬA & DỌN ẢNH CŨ)
app.put('/api/products/:id', async (req, res) => {
    try {
        const existingProduct = await Product.findById(req.params.id);
        if (!existingProduct) return res.status(404).json({ message: "Không tìm thấy sản phẩm!" });

        // 1. Nếu có thay đổi ảnh Chính
        if (req.body.img && req.body.img.startsWith('data:image')) {
            await deleteCloudinaryImage(existingProduct.img); // Xóa ảnh chính cũ
            req.body.img = await uploadBase64ToCloud(req.body.img, 'raumapc/products');
        } else {
            req.body.img = existingProduct.img; // Nếu không đổi thì giữ nguyên
        }

        // 2. Xử lý và Dọn dẹp ảnh Phụ (Gallery)
        if (req.body.gallery && Array.isArray(req.body.gallery)) {
            // Lọc ra các link ảnh cũ mà admin quyết định giữ lại
            const retainedUrls = req.body.gallery.filter(item => item.startsWith('http'));

            // Tìm các link ảnh đã bị admin bấm nút Xóa (có trong DB cũ nhưng không có trong danh sách giữ lại)
            const deletedUrls = (existingProduct.gallery || []).filter(oldUrl => !retainedUrls.includes(oldUrl));

            // Đem những ảnh bị loại bỏ đi tiêu hủy trên Cloudinary
            for (let oldUrl of deletedUrls) {
                await deleteCloudinaryImage(oldUrl);
            }

            // Tải lên các ảnh phụ mới (Base64)
            const uploadedGallery = await Promise.all(
                req.body.gallery.map(async (item) => {
                    if (item.startsWith('http')) return item; // Bỏ qua ảnh cũ đã giữ lại
                    return await uploadBase64ToCloud(item, 'raumapc/gallery');
                })
            );
            req.body.gallery = uploadedGallery.filter(url => url !== "");
        }

        if (!req.body.productId || req.body.productId.trim() === '') {
            req.body.productId = await generateAutoId(req.body.category);
        }
        if (req.body.stock !== undefined && parseInt(req.body.stock) <= 0) {
            req.body.stock = 0;
            req.body.status = 'Hết hàng';
        }

        await Product.findByIdAndUpdate(req.params.id, req.body);
        clearCache();
        res.json({ message: "Cập nhật thành công!" });
    } catch (err) {
        res.status(500).json({ message: "Lỗi cập nhật!" });
    }
});

app.delete('/api/products/:id', async (req, res) => {
    try {
        const product = await Product.findById(req.params.id);
        if (product) {
            // Tiêu hủy ảnh chính
            await deleteCloudinaryImage(product.img);

            // Tiêu hủy toàn bộ ảnh phụ
            if (product.gallery && product.gallery.length > 0) {
                for (let url of product.gallery) {
                    await deleteCloudinaryImage(url);
                }
            }
            await Product.findByIdAndDelete(req.params.id);
        }
        clearCache();
        res.json({ message: "Xóa thành công!" });
    } catch (err) {
        res.status(500).json({ message: "Lỗi xóa!" });
    }
});

app.put('/api/products/:id/view', async (req, res) => {
    try {
        const key = req.params.id; let query = mongoose.Types.ObjectId.isValid(key) ? { _id: key } : { productId: key };
        const sp = await Product.findOneAndUpdate(query, { $inc: { views: 1 } }, { returnDocument: 'after' });
        if (sp) res.json({ success: true, views: sp.views }); else res.status(404).json({ success: false });
    } catch (err) { res.status(500).json({ success: false }); }
});

// ==========================================
// API TÍCH HỢP THANH TOÁN VNPAY (TỰ ĐỘNG HÓA CHUẨN 100%)
// ==========================================

// Kiểm tra chữ ký vnp_SecureHash mà VNPay gửi kèm (dùng chung cho cả IPN server-to-server
// và lệnh xác nhận từ trình duyệt sau khi VNPay chuyển hướng về) - CHỈ tin dữ liệu nếu chữ ký khớp
function verifyVnpaySignature(rawParams) {
    let vnp_Params = { ...rawParams };
    let secureHash = vnp_Params['vnp_SecureHash'];
    delete vnp_Params['vnp_SecureHash'];
    delete vnp_Params['vnp_SecureHashType'];
    vnp_Params = sortObject(vnp_Params);

    let secretKey = process.env.VNP_HASHSECRET;
    if (!secretKey) return { valid: false };

    let signData = "";
    let first = true;
    for (let key in vnp_Params) {
        if (vnp_Params.hasOwnProperty(key)) {
            if (!first) signData += '&';
            signData += key + '=' + vnp_Params[key];
            first = false;
        }
    }

    let hmac = crypto.createHmac("sha512", secretKey);
    let signed = hmac.update(Buffer.from(signData, 'utf-8')).digest("hex");
    return { valid: secureHash === signed };
}

// Áp dụng kết quả thanh toán VNPay đã được xác thực chữ ký vào đơn hàng tương ứng
// (dùng chung cho IPN và lệnh xác nhận từ trình duyệt)
async function applyVnpayResult(orderId, rspCode) {
    let order = await Order.findOne({ orderId: orderId });
    if (!order || order.status !== 'Đang chờ thanh toán') return order;

    if (rspCode === '00') {
        order.status = 'Đã thanh toán (Chờ giao)';
        await order.save();
    } else {
        order.status = 'Đã hủy';
        await order.save();
        await adjustProductStock(order.items, 1); // Hoàn lại tồn kho đã trừ lúc đặt hàng
    }
    clearCache();
    return order;
}

// 1. Gửi thông tin đơn hàng sang VNPay để tạo Link thanh toán
app.post('/api/vnpay/create_url', async (req, res) => {
    try {
        // CHỐNG LỖI 1: Bắt IP chuẩn, nếu IP nội bộ thì giả lập một IP công cộng của mạng Viettel để vượt qua tường lửa VNPay
        let ipAddr = req.headers['x-forwarded-for'] || req.socket.remoteAddress;
        if (typeof ipAddr === 'string') ipAddr = ipAddr.split(',')[0].trim();
        if (!ipAddr || ipAddr === '::1' || ipAddr === '127.0.0.1') ipAddr = '113.190.233.15'; 

        let tmnCode = process.env.VNP_TMNCODE;
        let secretKey = process.env.VNP_HASHSECRET;
        if (!tmnCode || !secretKey) {
            console.error("Thiếu biến môi trường VNP_TMNCODE hoặc VNP_HASHSECRET!");
            return res.status(500).json({ success: false, message: "Cổng thanh toán VNPay chưa được cấu hình!" });
        }
        let vnpUrl = "https://sandbox.vnpayment.vn/paymentv2/vpcpay.html";
        let returnUrl = req.body.returnUrl || "https://raumapc-frontend.vercel.app/pages/info/tracking.html";

        // Chuẩn hóa thời gian VN
        let date = new Date();
        let utc = date.getTime() + (date.getTimezoneOffset() * 60000);
        let vnTime = new Date(utc + (3600000 * 7));

        const pad2 = (n) => (n < 10 ? '0' : '') + n;
        let createDate = vnTime.getFullYear().toString() + pad2(vnTime.getMonth() + 1) + pad2(vnTime.getDate()) + pad2(vnTime.getHours()) + pad2(vnTime.getMinutes()) + pad2(vnTime.getSeconds());

        vnTime.setMinutes(vnTime.getMinutes() + 15);
        let expireDate = vnTime.getFullYear().toString() + pad2(vnTime.getMonth() + 1) + pad2(vnTime.getDate()) + pad2(vnTime.getHours()) + pad2(vnTime.getMinutes()) + pad2(vnTime.getSeconds());

        let orderId = req.body.orderId;
        let amount = req.body.amount;

        let vnp_Params = {};
        vnp_Params['vnp_Version'] = '2.1.0';
        vnp_Params['vnp_Command'] = 'pay';
        vnp_Params['vnp_TmnCode'] = tmnCode;
        vnp_Params['vnp_Locale'] = 'vn';
        vnp_Params['vnp_CurrCode'] = 'VND';
        vnp_Params['vnp_TxnRef'] = String(orderId).replace(/[^a-zA-Z0-9]/g, '');
        vnp_Params['vnp_OrderInfo'] = 'Thanh toan don hang ' + String(orderId).replace(/[^a-zA-Z0-9]/g, '');
        vnp_Params['vnp_OrderType'] = 'other';
        vnp_Params['vnp_Amount'] = Math.round(Number(amount) * 100);
        vnp_Params['vnp_ReturnUrl'] = returnUrl;
        vnp_Params['vnp_IpAddr'] = ipAddr;
        vnp_Params['vnp_CreateDate'] = createDate;
        vnp_Params['vnp_ExpireDate'] = expireDate;

        vnp_Params = sortObject(vnp_Params);

        // CHỐNG LỖI 2: Tự tay ghép chuỗi thủ công, KHÔNG DÙNG querystring.stringify để tránh lỗi định dạng
        let signData = "";
        let first = true;
        for (let key in vnp_Params) {
            if (vnp_Params.hasOwnProperty(key)) {
                if (!first) signData += '&';
                signData += key + '=' + vnp_Params[key];
                first = false;
            }
        }

        let hmac = crypto.createHmac("sha512", secretKey);
        let signed = hmac.update(Buffer.from(signData, 'utf-8')).digest("hex"); 
        
        // Nối URL trực tiếp
        vnpUrl += '?' + signData + '&vnp_SecureHash=' + signed;

        res.json({ success: true, url: vnpUrl });
    } catch (err) {
        console.error("Lỗi VNPay:", err);
        res.status(500).json({ success: false, message: "Lỗi tạo link VNPay" });
    }
});

// 2. IPN (Bắt tín hiệu ngầm từ VNPay báo về để tự động duyệt đơn - server-to-server, luôn đáng tin nhất)
app.get('/api/vnpay/ipn', async (req, res) => {
    try {
        const { valid } = verifyVnpaySignature(req.query);
        if (!valid) return res.status(200).json({ RspCode: '97', Message: 'Mã xác thực không hợp lệ' });

        await applyVnpayResult(req.query['vnp_TxnRef'], req.query['vnp_ResponseCode']);
        // Luôn phải trả về 00 cho VNPay để xác nhận đã nhận tín hiệu (kể cả khi giao dịch thất bại)
        res.status(200).json({ RspCode: '00', Message: 'Xác nhận thành công' });
    } catch (err) {
        res.status(500).json({ RspCode: '99', Message: 'Lỗi máy chủ' });
    }
});

// 3. Xác nhận từ trình duyệt khi VNPay chuyển hướng khách về trang tracking.html.
// KHÔNG được tin trực tiếp status mà client tự gửi lên - phải xác thực chữ ký vnp_SecureHash
// y hệt IPN thì mới cập nhật đơn hàng, để tránh bị giả mạo "đã thanh toán" qua URL.
app.get('/api/vnpay/verify-return', async (req, res) => {
    try {
        const { valid } = verifyVnpaySignature(req.query);
        if (!valid) return res.status(400).json({ success: false, message: "Chữ ký xác thực không hợp lệ!" });

        const order = await applyVnpayResult(req.query['vnp_TxnRef'], req.query['vnp_ResponseCode']);
        if (!order) return res.status(404).json({ success: false, message: "Không tìm thấy đơn hàng!" });

        res.json({ success: true, status: order.status });
    } catch (err) {
        res.status(500).json({ success: false, message: "Lỗi máy chủ!" });
    }
});

// ==========================================
// API ĐƠN HÀNG
// ==========================================
app.post('/api/orders', verifyToken, async (req, res) => {
    try {
        // Ép đơn hàng phải gắn đúng tài khoản của chính người đang đăng nhập,
        // tránh trường hợp giả mạo tạo đơn dưới tên tài khoản người khác
        req.body.account = req.user.username;

        const newOrder = new Order(req.body);
        let totalImportPrice = 0; // Biến tính tổng giá vốn

        if (newOrder.items && newOrder.items.length > 0) {
            for (let item of newOrder.items) {
                let qtyNum = parseInt(item.quantity) || 1;
                let product = await findProductByAnyId(item.id || item._id);
                if (product) {
                    // CỘNG DỒN GIÁ VỐN CHO ĐƠN HÀNG (dựa trên importPrice trước khi trừ kho)
                    let itemImportPrice = product.importPrice || 0;
                    totalImportPrice += (itemImportPrice * qtyNum);
                }
            }
            // Trừ tồn kho
            await adjustProductStock(newOrder.items, -1);
        }

        // Gán tổng giá vốn vào đơn hàng
        newOrder.totalImportPrice = totalImportPrice;

        await newOrder.save();

        let cusName = newOrder.username; let cusPhone = "Đang cập nhật"; let cusAddress = "Đang cập nhật";
        const match = newOrder.username.match(/(.+?)\s*\((.+?)\s*-\s*(.+)\)/);
        if (match) { cusName = match[1]; cusPhone = match[2]; cusAddress = match[3]; }

        let itemsHtml = "";
        newOrder.items.forEach(item => {
            let priceNum = parseInt(String(item.price).replace(/\D/g, '')) || 0;
            let qtyNum = parseInt(item.quantity) || 1; let itemTotal = priceNum * qtyNum;
            itemsHtml += `
            <tr>
                <td style="padding: 12px 10px 12px 0; border-bottom: 1px solid #eee; color: #555; font-size: 14px;">${item.name}</td>
                <td style="padding: 12px 10px; border-bottom: 1px solid #eee; text-align: center; color: #555; font-size: 14px;">${qtyNum}</td>
                <td style="padding: 12px 0 12px 10px; border-bottom: 1px solid #eee; text-align: right; color: #d70018; font-weight: bold; font-size: 14px;">${new Intl.NumberFormat('vi-VN').format(itemTotal)}đ</td>
            </tr>`;
        });
        let formattedTotal = new Intl.NumberFormat('vi-VN').format(newOrder.total) + ' đ';

        const headerSubtitle = "Đơn hàng đang chờ duyệt";
        const statusTitle = "ĐƠN HÀNG ĐANG CHỜ DUYỆT";
        const statusMessage = "Cảm ơn bạn đã tin tưởng và mua sắm tại hệ thống Rau Má PC. Đơn hàng của bạn đã được hệ thống ghi nhận và đang chờ duyệt!";
        const color = "#2980b9";
        const bgColor = "#ebf5fb";

        const fullHtmlContent = `
        <div style="font-family: 'Segoe UI', Arial, sans-serif; max-width: 600px; margin: 0 auto; border: 1px solid #eaebec; border-radius: 12px; overflow: hidden; box-shadow: 0 8px 20px rgba(0,0,0,0.04);">
            <div style="background: linear-gradient(135deg, #1435c3 0%, #0a1b66 100%); padding: 30px 20px; text-align: center;">
                <table align="center" border="0" cellpadding="0" cellspacing="0" style="margin: 0 auto;">
                    <tr>
                        <td style="padding-right: 18px; vertical-align: middle;">
                            <img src="https://github.com/lamngo829-code/raumapc-frontend/blob/main/assets/images/icons/logo-sticky.jpg?raw=true" alt="Logo Rau Má" style="width: 75px; height: auto; display: block; border-radius: 4px;">
                        </td>
                        <td style="vertical-align: middle; text-align: left;">
                            <h1 style="margin: 0; font-size: 28px; font-weight: bold; letter-spacing: 1.5px; color: #ffffff;">RAU MÁ PC</h1>
                            <p style="margin: 5px 0 0; font-size: 15px; color: #cbd5e1;">${headerSubtitle}</p>
                        </td>
                    </tr>
                </table>
            </div>
            <div style="padding: 40px 30px; background-color: #ffffff; color: #333333;">
                <p style="font-size: 15px; margin-top: 0; margin-bottom: 20px;">Chào <strong>${cusName}</strong>,</p>
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
                    <tbody>${itemsHtml}</tbody>
                </table>
                <div style="text-align: right; margin-top: 25px; padding-top: 15px; border-top: 2px dashed #eee;">
                    <span style="font-size: 14px; color: #555;">Tổng thanh toán:</span>
                    <strong style="color: #d70018; font-size: 24px; margin-left: 10px;">${formattedTotal}</strong>
                </div>
            </div>
            <div style="background-color: #f8f9fa; padding: 25px 20px; text-align: center; font-size: 13px; color: #777777; border-top: 1px solid #eeeeee;">
                <p style="margin: 0 0 8px 0; font-weight: bold; color: #333333; font-size: 14px;">CÔNG TY TNHH MÁY TÍNH RAU MÁ</p>
                <p style="margin: 4px 0;">Hotline: <strong style="color: #1435c3;">1900 3636</strong> | Email: cskh@raumapc.com</p>
                <p style="margin: 4px 0 0;">Địa chỉ: An Phú Đông, Quận 12, TP. Hồ Chí Minh</p>
            </div>
        </div>`;

        const emailData = {
            service_id: process.env.EMAILJS_SERVICE_ID,
            template_id: process.env.EMAILJS_TEMPLATE_ID,
            user_id: process.env.EMAILJS_USER_ID,
            accessToken: process.env.EMAILJS_TOKEN,
            template_params: { to_email: newOrder.email, subject: `[Rau Má PC] Đơn hàng #${newOrder.orderId} đang chờ xác nhận`, message: fullHtmlContent }
        };
        const adminEmailData = {
            service_id: process.env.EMAILJS_SERVICE_ID,
            template_id: process.env.EMAILJS_TEMPLATE_ID,
            user_id: process.env.EMAILJS_USER_ID,
            accessToken: process.env.EMAILJS_TOKEN,
            template_params: { to_email: "lamngo829@gmail.com", subject: `🚨 CÓ ĐƠN MỚI #${newOrder.orderId}`, message: fullHtmlContent }
        };
        fetch('https://api.emailjs.com/api/v1.0/email/send', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(adminEmailData) }).catch(e => console.log(e));
        fetch('https://api.emailjs.com/api/v1.0/email/send', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(emailData) }).catch(e => console.log(e));

        const userCheck = await User.findOne({ username: newOrder.account });
        if (userCheck) { userCheck.cart = []; await userCheck.save(); }
        clearCache();
        res.json({ message: "Đặt hàng thành công!" });
    } catch (error) { res.status(500).json({ message: "Lỗi khi lưu đơn!" }); }
});

// Toàn bộ đơn hàng của MỌI khách - chỉ Admin được xem (chứa tên, SĐT, địa chỉ khách hàng)
app.get('/api/orders', verifyToken, async (req, res) => {
    if (req.user.role !== 'admin') return res.status(403).json({ message: "Từ chối truy cập!" });
    try {
        // Thêm sort({ createdAt: -1 }) để luôn lấy đơn mới nhất, tránh lỗi lưu cache
        const orders = await Order.find().sort({ createdAt: -1 });
        res.json(orders);
    } catch (err) {
        res.status(500).json({ message: "Lỗi hệ thống!" });
    }
});

// Chỉ đơn hàng của CHÍNH khách đang đăng nhập - dùng cho trang "Đơn hàng của tôi"
app.get('/api/orders/my', verifyToken, async (req, res) => {
    try {
        const orders = await Order.find({ account: req.user.username }).sort({ createdAt: -1 });
        res.json(orders);
    } catch (err) {
        res.status(500).json({ message: "Lỗi hệ thống!" });
    }
});

// ==========================================
// API TRA CỨU ĐƠN HÀNG CHO KHÁCH VÃNG LAI
// ==========================================
app.post('/api/orders/track', async (req, res) => {
    try {
        const { orderId, phone } = req.body;
        if (!orderId || !phone) return res.status(400).json({ success: false, message: "Vui lòng nhập đủ thông tin!" });

        // Tìm đơn hàng theo Mã (bỏ qua khoảng trắng và viết hoa)
        const order = await Order.findOne({ orderId: orderId.trim().toUpperCase() });
        if (!order) return res.status(404).json({ success: false, message: "Không tìm thấy đơn hàng này trên hệ thống!" });

        // Xác thực bảo mật: Số điện thoại phải khớp với dữ liệu đã lưu
        if (!order.username.includes(phone.trim())) {
            return res.status(403).json({ success: false, message: "Số điện thoại không khớp với đơn hàng này!" });
        }

        res.json({ success: true, order: order });
    } catch (err) {
        res.status(500).json({ success: false, message: "Lỗi hệ thống máy chủ!" });
    }
});

// ==========================================
// API THỐNG KÊ DOANH THU 
// ==========================================
app.get('/api/admin/revenue', verifyToken, async (req, res) => {
    if (req.user.role !== 'admin') return res.status(403).json({ message: "Từ chối truy cập!" });
    try {
        const orders = await Order.find({ status: "Hoàn thành" });
        let totalRevenue = 0, totalOrders = 0, totalProfit = 0; // Thêm totalProfit
        let weekRev = 0, monthRev = 0, yearRev = 0;
        let weekProfit = 0, monthProfit = 0, yearProfit = 0;

        const now = new Date();
        const today = new Date(now.getFullYear(), now.getMonth(), now.getDate());

        const dayOfWeek = now.getDay() || 7;
        const startOfWeek = new Date(today);
        startOfWeek.setDate(today.getDate() - dayOfWeek + 1);

        const startOfMonth = new Date(now.getFullYear(), now.getMonth(), 1);
        const startOfYear = new Date(now.getFullYear(), 0, 1);

        orders.forEach(o => {
            let rev = o.total || 0;
            let importCost = o.totalImportPrice || 0;
            let profit = rev - importCost;

            totalRevenue += rev;
            totalProfit += profit;
            totalOrders++;

            let dateStr = o.date || "";
            let dMatch = dateStr.match(/(\d{1,2})[\/\-](\d{1,2})[\/\-](\d{4})/);
            if (dMatch) {
                let oDate = new Date(dMatch[3], dMatch[2] - 1, dMatch[1]);
                if (oDate >= startOfWeek) { weekRev += rev; weekProfit += profit; }
                if (oDate >= startOfMonth) { monthRev += rev; monthProfit += profit; }
                if (oDate >= startOfYear) { yearRev += rev; yearProfit += profit; }
            }
        });

        res.json({ totalRevenue, totalProfit, totalOrders, weekRev, monthRev, yearRev, weekProfit, monthProfit, yearProfit });
    } catch (err) { res.status(500).json({ message: "Lỗi thống kê!" }); }
});

app.get('/api/admin/revenue-chart', verifyToken, async (req, res) => {
    if (req.user.role !== 'admin') return res.status(403).json({ message: "Từ chối quyền truy cập!" });
    try {
        // Chỉ lấy các đơn hàng đã Hoàn thành
        const orders = await Order.find({ status: "Hoàn thành" });

        let daily = {}, weekly = {}, monthly = {}, yearly = {};

        // Hàm tính số thứ tự tuần trong năm
        function getWeekNumber(d) {
            d = new Date(Date.UTC(d.getFullYear(), d.getMonth(), d.getDate()));
            d.setUTCDate(d.getUTCDate() + 4 - (d.getUTCDay() || 7));
            let yearStart = new Date(Date.UTC(d.getUTCFullYear(), 0, 1));
            return Math.ceil((((d - yearStart) / 86400000) + 1) / 7);
        }

        orders.forEach(order => {
            let dateStr = order.date || ""; // Đọc chuỗi ngày cũ (VD: "24/09/2026")
            let dMatch = dateStr.match(/(\d{1,2})[\/\-](\d{1,2})[\/\-](\d{4})/);
            
            if (dMatch) {
                let d = parseInt(dMatch[1]), m = parseInt(dMatch[2]), y = parseInt(dMatch[3]);
                let dateObj = new Date(y, m - 1, d);

                // Tạo nhãn (Labels)
                let dayKey = `${String(d).padStart(2, '0')}/${String(m).padStart(2, '0')}`;
                let weekKey = `Tuần ${getWeekNumber(dateObj)}`;
                let monthKey = `Tháng ${m}/${y}`;
                let yearKey = `Năm ${y}`;

                let val = order.total || 0;
                daily[dayKey] = (daily[dayKey] || 0) + val;
                weekly[weekKey] = (weekly[weekKey] || 0) + val;
                monthly[monthKey] = (monthly[monthKey] || 0) + val;
                yearly[yearKey] = (yearly[yearKey] || 0) + val;
            }
        });

        res.json({
            daily: { labels: Object.keys(daily), data: Object.values(daily) },
            weekly: { labels: Object.keys(weekly), data: Object.values(weekly) },
            monthly: { labels: Object.keys(monthly), data: Object.values(monthly) },
            yearly: { labels: Object.keys(yearly), data: Object.values(yearly) }
        });
    } catch (err) { 
        console.error(err);
        res.status(500).json({ message: "Lỗi vẽ biểu đồ!" }); 
    }
});

app.put('/api/users/cart', verifyToken, async (req, res) => {
    try { await User.findByIdAndUpdate(req.user.id, { cart: req.body.cart }); res.json({ success: true, message: "Đã đồng bộ giỏ hàng" }); } catch (err) { res.status(500).json({ success: false, message: "Lỗi đồng bộ" }); }
});

app.put('/api/orders/:id/status', verifyToken, async (req, res) => {
    if (req.user.role !== 'admin') return res.status(403).json({ message: "Từ chối truy cập!" });
    try {
        const oldOrder = await Order.findOne({ orderId: req.params.id });
        if (!oldOrder) return res.status(404).json({ message: "Không tìm thấy đơn hàng!" });
        const oldStatus = oldOrder.status;
        const newStatus = req.body.status;

        const order = await Order.findOneAndUpdate(
            { orderId: req.params.id },
            { status: newStatus },
            { returnDocument: 'after' }
        );

        // Hoàn lại tồn kho khi đơn chuyển SANG "Đã hủy", trừ lại kho nếu đơn được mở hủy (chuyển RA KHỎI "Đã hủy")
        if (oldStatus !== 'Đã hủy' && newStatus === 'Đã hủy') {
            await adjustProductStock(order.items, 1);
            clearCache();
        } else if (oldStatus === 'Đã hủy' && newStatus !== 'Đã hủy') {
            await adjustProductStock(order.items, -1);
            clearCache();
        }

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
                            <img src="https://github.com/lamngo829-code/raumapc-frontend/blob/main/assets/images/icons/logo-sticky.jpg?raw=true" alt="Logo" style="width: 65px; height: 65px; object-fit: cover; border-radius: 50%; box-shadow: 0 2px 10px rgba(0,0,0,0.2); display: block;">
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

app.delete('/api/orders/:id', verifyToken, async (req, res) => {
    if (req.user.role !== 'admin') return res.status(403).json({ success: false, message: "Từ chối truy cập!" });
    try { await Order.findOneAndDelete({ orderId: req.params.id }); res.json({ success: true, message: "Đã xóa đơn hàng!" }); } catch (err) { res.status(500).json({ success: false, message: "Lỗi xóa đơn hàng!" }); }
});

app.post('/api/products/:id/comments', async (req, res) => {
    try {
        let { userName, userAvatar, content, rating, img } = req.body;
        const product = await Product.findById(req.params.id);
        if (!product) return res.status(404).json({ success: false, message: "Sản phẩm không tồn tại!" });

        // CHẶN ẢNH ĐÍNH KÈM BÌNH LUẬN VÀ ĐẨY LÊN CLOUDINARY (THƯ MỤC REVIEWS)
        if (img) {
            img = await uploadBase64ToCloud(img, 'raumapc/reviews');
        }

        // ==========================================
        // BẢO MẬT: LỌC NỘI DUNG CHỐNG TẤN CÔNG XSS (DATA SANITIZATION)
        // ==========================================
        let safeContent = content ? String(content)
            .replace(/&/g, "&amp;")
            .replace(/</g, "&lt;")
            .replace(/>/g, "&gt;")
            .replace(/"/g, "&quot;")
            .replace(/'/g, "&#039;") : "";

        let safeName = userName ? String(userName)
            .replace(/</g, "&lt;").replace(/>/g, "&gt;") : "Khách";

        const newComment = {
            id: Date.now().toString(),
            userName: safeName,
            userAvatar: userAvatar || "",
            content: safeContent, // Lưu nội dung đã được làm sạch
            rating: rating || 5,
            img: img || null,
            date: new Date().toLocaleDateString('vi-VN') + ' ' + new Date().toLocaleTimeString('vi-VN', { hour: '2-digit', minute: '2-digit' })
        };

        product.comments.push(newComment);
        await product.save();
        clearCache();
        res.json({ success: true, message: "Đã gửi bình luận!", comments: product.comments });
    } catch (err) {
        res.status(500).json({ success: false, message: "Lỗi máy chủ!" });
    }
});

app.post('/api/users/me/update', verifyToken, async (req, res) => {
    try {
        const { phone, email, otp, avatar } = req.body;
        let user = await User.findById(req.user.id);
        if (!user) return res.status(404).json({ success: false, message: "Không tìm thấy người dùng." });

        if (email && email !== user.email) {
            if (!(await checkOtp(email, otp))) return res.status(400).json({ success: false, message: "Mã OTP không hợp lệ!" });
            user.email = email; await clearOtp(email);
        }

        if (phone) user.phone = phone;

        if (avatar && avatar !== user.avatar && avatar.startsWith('data:image')) {
            // Xóa avatar cũ trên Cloudinary (nếu có)
            await deleteCloudinaryImage(user.avatar);
            // Tải avatar mới lên
            user.avatar = await uploadBase64ToCloud(avatar, 'raumapc/avatars');
        }

        // ĐÃ XÓA SẠCH ĐOẠN CODE BỊ LỖI (if data.success...) KHỎI ĐÂY

        await user.save();

        // Trả kết quả về cho Frontend xử lý tiếp
        res.json({
            success: true,
            message: "Cập nhật thành công!",
            user: {
                username: user.username,
                fullName: user.fullName,
                role: user.role,
                email: user.email,
                phone: user.phone,
                cart: user.cart,
                avatar: user.avatar,
                createdAt: user.createdAt
            }
        });
    } catch (err) {
        res.status(500).json({ success: false, message: "Lỗi máy chủ!" });
    }
});

app.delete('/api/users/me', verifyToken, async (req, res) => {
    try { if (req.user.role === 'admin') await Admin.findByIdAndDelete(req.user.id); else await User.findByIdAndDelete(req.user.id); res.json({ success: true, message: "Đã xóa tài khoản!" }); } catch (err) { res.status(500).json({ success: false }); }
});

app.get('/api/settings/home', cacheMiddleware, async (req, res) => { try { const homeSettings = await Setting.findOne({ key: 'homeConfig' }); res.json(homeSettings ? homeSettings.data : {}); } catch (err) { res.status(500).json({}); } });
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
// API QUẢN TRỊ KHÁCH HÀNG
// ==========================================
app.get('/api/admin/users', verifyToken, async (req, res) => {
    if (req.user.role !== 'admin') return res.status(403).json({ message: "Từ chối truy cập!" });
    try {
        const users = await User.find({ role: 'user' }).select('-password').sort({ createdAt: -1 });
        res.json(users);
    } catch (err) { res.status(500).json({ message: "Lỗi hệ thống!" }); }
});

app.put('/api/admin/users/:id/lock', verifyToken, async (req, res) => {
    if (req.user.role !== 'admin') return res.status(403).json({ message: "Từ chối truy cập!" });
    try {
        let user = await User.findById(req.params.id);
        if (!user) return res.status(404).json({ success: false, message: "Không tìm thấy user!" });

        user.isLocked = !user.isLocked;
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

app.put('/api/admin/users/:id/change-password', verifyToken, async (req, res) => {
    if (req.user.role !== 'admin') return res.status(403).json({ message: "Từ chối truy cập!" });

    try {
        const { newPassword } = req.body;
        if (!newPassword || newPassword.length < 6) return res.status(400).json({ success: false, message: "Mật khẩu mới phải từ 6 ký tự trở lên!" });
        let user = await User.findById(req.params.id);
        if (!user) return res.status(404).json({ success: false, message: "Không tìm thấy tài khoản khách hàng này!" });
        const salt = await bcrypt.genSalt(10);
        user.password = await bcrypt.hash(newPassword, salt);
        await user.save();
        res.json({ success: true, message: `Đã đổi mật khẩu cho khách hàng [${user.username}] thành công!` });
    } catch (err) { res.status(500).json({ success: false, message: "Lỗi hệ thống máy chủ!" }); }
});

app.post('/api/admin/change-password', verifyToken, async (req, res) => {
    if (req.user.role !== 'admin') return res.status(403).json({ message: "Từ chối truy cập!" });
    try {
        const { newPassword } = req.body;
        if (!newPassword || newPassword.length < 6) return res.status(400).json({ success: false, message: "Mật khẩu mới phải từ 6 ký tự trở lên!" });
        let admin = await Admin.findById(req.user.id);
        if (!admin) return res.status(404).json({ success: false, message: "Không tìm thấy tài khoản Admin!" });
        const salt = await bcrypt.genSalt(10);
        admin.password = await bcrypt.hash(newPassword, salt);
        await admin.save();
        res.json({ success: true, message: "Đã đổi mật khẩu Admin thành công!" });
    } catch (err) { res.status(500).json({ success: false, message: "Lỗi hệ thống máy chủ!" }); }
});

// ==========================================
// API QUẢN TRỊ BÌNH LUẬN & ĐÁNH GIÁ (ADMIN)
// ==========================================
// 1. Lấy toàn bộ bình luận của tất cả sản phẩm
app.get('/api/admin/comments', verifyToken, async (req, res) => {
    if (req.user.role !== 'admin') return res.status(403).json({ message: "Từ chối truy cập!" });
    try {
        const products = await Product.find({ "comments.0": { $exists: true } });
        let allComments = [];
        products.forEach(p => {
            p.comments.forEach(c => {
                allComments.push({ productId: p._id, productName: p.name, productImg: p.img, ...c });
            });
        });
        // Sắp xếp bình luận mới nhất lên đầu
        allComments.sort((a, b) => b.id - a.id);
        res.json(allComments);
    } catch (err) { res.status(500).json({ message: "Lỗi hệ thống!" }); }
});

// 2. Xóa bình luận & Tiêu hủy ảnh đính kèm
app.delete('/api/admin/comments/:productId/:commentId', verifyToken, async (req, res) => {
    if (req.user.role !== 'admin') return res.status(403).json({ message: "Từ chối truy cập!" });
    try {
        const product = await Product.findById(req.params.productId);
        if (!product) return res.status(404).json({ success: false, message: "Không tìm thấy sản phẩm!" });

        const cmt = product.comments.find(c => c.id === req.params.commentId);
        if (cmt && cmt.img) await deleteCloudinaryImage(cmt.img); // Xóa ảnh rác trên Cloudinary

        product.comments = product.comments.filter(c => c.id !== req.params.commentId);
        await product.save();
        clearCache();
        res.json({ success: true, message: "Đã xóa vĩnh viễn bình luận!" });
    } catch (err) { res.status(500).json({ success: false, message: "Lỗi hệ thống!" }); }
});

// 3. Admin trả lời bình luận
app.put('/api/admin/comments/:productId/:commentId/reply', verifyToken, async (req, res) => {
    if (req.user.role !== 'admin') return res.status(403).json({ message: "Từ chối truy cập!" });
    try {
        const product = await Product.findById(req.params.productId);
        const commentIndex = product.comments.findIndex(c => c.id === req.params.commentId);

        product.comments[commentIndex].adminReply = req.body.replyText;
        product.markModified('comments'); // Báo cho MongoDB biết mảng Array đã bị thay đổi
        await product.save();

        clearCache();
        res.json({ success: true, message: "Đã gửi phản hồi thành công!" });
    } catch (err) { res.status(500).json({ success: false, message: "Lỗi hệ thống!" }); }
});

app.get('/api/health', (req, res) => { res.json({ status: 'ok', time: new Date().toISOString() }); });

// ==========================================
// API BÍ MẬT: CHUẨN HÓA DỮ LIỆU GIÁ (CHẠY 1 LẦN DUY NHẤT)
// ==========================================
app.get('/api/admin/fix-price-data', verifyToken, async (req, res) => {
    if (req.user.role !== 'admin') return res.status(403).json({ success: false, message: "Từ chối truy cập!" });
    try {
        const products = await Product.find({});
        let updatedCount = 0;

        for (let sp of products) {
            // Kiểm tra xem giá có đang bị lưu dưới dạng chữ (chứa "đ", dấu chấm) không
            if (typeof sp.price === 'string') {
                // Rút trích chỉ lấy các con số (Cắt bỏ "đ" và dấu "."), ví dụ: "5.000.000đ" -> 5000000
                let numPrice = parseInt(sp.price.replace(/\D/g, '')) || 0;

                // Cập nhật lại vào Database dưới dạng Number chuẩn
                await Product.updateOne({ _id: sp._id }, { $set: { price: numPrice } });
                updatedCount++;
            }
        }

        // Nếu bạn đã cài Caching ở bài trước, hãy xóa Cache để dữ liệu mới cập nhật
        if (typeof clearCache === 'function') clearCache();

        res.json({
            success: true,
            message: `Ca đại phẫu thành công! Đã chuyển đổi ${updatedCount} sản phẩm sang định dạng Số.`
        });
    } catch (err) {
        res.status(500).json({ success: false, message: err.message });
    }
});

// ==========================================
// API BÍ MẬT: TÍNH LẠI GIÁ VỐN (totalImportPrice) CHO CÁC ĐƠN HÀNG CŨ (CHẠY 1 LẦN)
// ==========================================
// Các đơn hàng tạo trước khi sửa lỗi tra sản phẩm theo productId (thay vì chỉ _id)
// và trước khi Admin nhập Giá Nhập Vốn đều bị kẹt ở totalImportPrice = 0.
// API này tính lại dựa trên importPrice HIỆN TẠI của sản phẩm (không đổi lại tồn kho).
app.get('/api/admin/fix-order-profit', verifyToken, async (req, res) => {
    if (req.user.role !== 'admin') return res.status(403).json({ success: false, message: "Từ chối truy cập!" });
    try {
        const orders = await Order.find({});
        let updatedCount = 0;

        for (let order of orders) {
            if (!order.items || order.items.length === 0) continue;

            let recalculated = 0;
            for (let item of order.items) {
                let qtyNum = parseInt(item.quantity) || 1;
                let product = await findProductByAnyId(item.id || item._id);
                if (product) recalculated += (product.importPrice || 0) * qtyNum;
            }

            if (recalculated !== order.totalImportPrice) {
                await Order.updateOne({ _id: order._id }, { $set: { totalImportPrice: recalculated } });
                updatedCount++;
            }
        }

        if (typeof clearCache === 'function') clearCache();

        res.json({
            success: true,
            message: `Đã tính lại giá vốn cho ${updatedCount}/${orders.length} đơn hàng!`
        });
    } catch (err) {
        res.status(500).json({ success: false, message: err.message });
    }
});

// ==========================================
// API CHUYÊN DỤNG CHO SEO & CHIA SẺ MẠNG XÃ HỘI (ZALO, FACEBOOK)
// ==========================================
app.get('/share/:id', async (req, res) => {
    try {
        const key = req.params.id;
        let sp = mongoose.Types.ObjectId.isValid(key) ? await Product.findById(key) : null;
        if (!sp) sp = await Product.findOne({ productId: key });

        if (!sp) return res.status(404).send("Sản phẩm không tồn tại hoặc đã bị xóa.");

        // URL trang thực tế trên Vercel của bạn
        const frontendUrl = `https://raumapc-frontend.vercel.app/pages/shop/product-detail.html?id=${sp.productId || sp._id}`;

        // Chuẩn hóa dữ liệu chống lỗi ngoặc kép
        const safeName = sp.name.replace(/"/g, '&quot;');
        const safeImg = sp.img && sp.img.startsWith('http') ? sp.img : "https://raumapc-frontend.vercel.app/assets/images/icons/logo.jpg";

        // Tạo mô tả ngắn
        let safeDesc = sp.description ? sp.description.replace(/<[^>]*>?/gm, '') : '';
        safeDesc = safeDesc.length > 150 ? safeDesc.substring(0, 150) + '...' : `Mua ngay ${safeName} chính hãng tại Rau Má PC với giá cực sốc.`;

        // Lắp ráp thẻ HTML có chứa Meta Tags tĩnh cho Bot
        const htmlTemplate = `
        <!DOCTYPE html>
        <html lang="vi">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>${safeName} - Rau Má PC</title>
            
            <!-- THẺ MÔ TẢ CHO GOOGLE -->
            <meta name="description" content="${safeDesc}">
            <meta name="keywords" content="Rau Má PC, ${sp.brand}, ${sp.category}, linh kiện máy tính">
            
            <!-- THẺ OPEN GRAPH CHO FACEBOOK, ZALO, TELEGRAM -->
            <meta property="og:title" content="${safeName} - Rau Má PC">
            <meta property="og:description" content="${safeDesc}">
            <meta property="og:image" content="${safeImg}">
            <meta property="og:type" content="product">
            <meta property="og:url" content="${frontendUrl}">
            
            <!-- THẺ CHUYỂN HƯỚNG TỐC ĐỘ CAO CHO NGƯỜI DÙNG THẬT -->
            <meta http-equiv="refresh" content="0; url=${frontendUrl}">
            <script>window.location.replace("${frontendUrl}");</script>
        </head>
        <body style="background: #f4f7fe; font-family: sans-serif; text-align: center; padding-top: 50px;">
            <p>Đang chuyển hướng đến sản phẩm... Nếu trình duyệt không tự chuyển, vui lòng <a href="${frontendUrl}" style="color: #1435c3;">bấm vào đây</a>.</p>
        </body>
        </html>
        `;

        res.send(htmlTemplate);
    } catch (error) {
        res.status(500).send("Lỗi máy chủ khi tạo thẻ chia sẻ!");
    }
});

function sortObject(obj) {
    let sorted = {};
    let str = [];
    let key;
    for (key in obj) { if (obj.hasOwnProperty(key)) { str.push(encodeURIComponent(key)); } }
    str.sort();
    for (key = 0; key < str.length; key++) {
        sorted[str[key]] = encodeURIComponent(obj[str[key]]).replace(/%20/g, "+");
    }
    return sorted;
}

// Bắt các lỗi bật ra ngoài mọi route (route nào cũng có try/catch riêng nên hiếm khi tới đây,
// nhưng vẫn cần lưới an toàn cuối cùng để không bỏ sót)
if (Sentry) Sentry.setupExpressErrorHandler(app);

// Chỉ thật sự mở cổng lắng nghe khi server.js được chạy trực tiếp (node server.js).
// Khi file này được require() để viết test (supertest), KHÔNG mở cổng thật - test tự gọi
// request(app) để gửi request giả lập, không cần server thật sự lắng nghe port nào cả.
if (require.main === module) {
    app.listen(process.env.PORT || 3000, () => console.log(`✅ Máy chủ đang chạy ở chuẩn bảo mật Doanh Nghiệp`));
}

module.exports = app;