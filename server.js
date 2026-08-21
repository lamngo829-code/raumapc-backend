const express = require('express');
const cors = require('cors');
const mongoose = require('mongoose');
const nodemailer = require('nodemailer');

const app = express();
app.use(cors());
app.use(express.json());

// ==========================================
// 1. CẤU HÌNH GỬI MAIL (NODEMAILER)
// ==========================================

const transporter = nodemailer.createTransport({
    host: 'smtp.gmail.com', // Khai báo rõ cổng máy chủ của Gmail
    port: 465,
    secure: true,
    auth: {
        user: 'lamngo829@gmail.com', // Gmail của bạn
        pass: 'uangzjjwgqhjjocn'     // Mật khẩu ứng dụng của bạn
    },
    family: 4 // <--- THẦN CHÚ Ở ĐÂY: Ép Render phải dùng chuẩn IPv4 truyền thống để không bị chặn!
});

// ==========================================
// 2. KẾT NỐI MONGODB
// ==========================================
mongoose.connect('mongodb+srv://lamngo829_db_user:KDJUXdVXOfCKUSfx@cluster0.r46tion.mongodb.net/raumapc?appName=Cluster0')
    .then(() => console.log('✅ Đã kết nối MongoDB!'))
    .catch(err => console.error('❌ Lỗi kết nối MongoDB:', err));

// ==========================================
// 3. KHUÔN MẪU DỮ LIỆU (SCHEMAS)
// ==========================================
const productSchema = new mongoose.Schema({
    name: String, price: String, img: String, warranty: String,
    specs: String, description: String, category: String 
});
const Product = mongoose.model('Product', productSchema);

const orderSchema = new mongoose.Schema({
    orderId: String,
    date: String,
    username: String, // Lưu Họ tên + SĐT + Địa chỉ
    account: String,  // Lưu định danh tài khoản đăng nhập (VD: lamngo829)
    email: String,    // Lưu Email để gửi thư
    items: Array,    
    total: Number,
    status: String
});
const Order = mongoose.model('Order', orderSchema);

// ==========================================
// 4. API SẢN PHẨM (PRODUCTS)
// ==========================================
app.get('/api/products', async (req, res) => {
    try {
        const products = await Product.find();
        res.json(products.map(sp => ({
            id: sp._id.toString(), name: sp.name, price: sp.price, img: sp.img,
            category: sp.category || 'khac'
        })));
    } catch (err) { res.status(500).json({ message: "Lỗi Server" }); }
});

app.post('/api/products', async (req, res) => {
    try { await new Product(req.body).save(); res.json({ message: "Đã thêm!" }); } 
    catch (err) { res.status(500).json({ message: "Lỗi!" }); }
});

app.put('/api/products/:id', async (req, res) => {
    try { await Product.findByIdAndUpdate(req.params.id, req.body); res.json({ message: "Đã sửa!" }); } 
    catch (err) { res.status(500).json({ message: "Lỗi!" }); }
});

app.delete('/api/products/:id', async (req, res) => {
    try { await Product.findByIdAndDelete(req.params.id); res.json({ message: "Đã xóa!" }); } 
    catch (err) { res.status(500).json({ message: "Lỗi!" }); }
});

// ==========================================
// 5. API ĐƠN HÀNG (ORDERS) & EMAIL
// ==========================================
// 5.1 Đặt hàng
app.post('/api/orders', async (req, res) => {
    try {
        const newOrder = new Order(req.body);
        await newOrder.save(); 
        console.log(`🛒 Đơn mới: ${newOrder.orderId}`);

        if (req.body.email) {
            const mailOptions = {
                from: 'lamngo829@gmail.com',
                to: req.body.email,
                subject: `Xác nhận đặt hàng thành công - Mã đơn: ${newOrder.orderId}`,
                html: `
                    <div style="font-family: Arial, sans-serif; max-width: 600px; margin: auto; padding: 20px; border: 1px solid #ddd; border-radius: 8px;">
                        <h2 style="color: #1435c3; text-align: center;">CẢM ƠN BẠN ĐÃ MUA SẮM TẠI RAU MÁ PC!</h2>
                        <p>Chào bạn,</p>
                        <p>Đơn hàng <strong>${newOrder.orderId}</strong> của bạn đã được ghi nhận.</p>
                        <table style="width: 100%; border-collapse: collapse; margin-top: 15px;">
                            <tr style="background: #f4f7fe;"><td style="padding: 10px; font-weight: bold;">Trạng thái:</td><td style="padding: 10px; color:#ff9800; font-weight:bold;">${newOrder.status}</td></tr>
                            <tr><td style="padding: 10px; font-weight: bold; border-top: 1px solid #ddd;">Tổng thanh toán:</td><td style="padding: 10px; color: #d70018; font-weight: bold; font-size: 16px; border-top: 1px solid #ddd;">${new Intl.NumberFormat('vi-VN').format(newOrder.total)}đ</td></tr>
                        </table>
                        <p style="margin-top: 20px;">Chúng tôi sẽ sớm liên hệ để giao hàng!</p>
                    </div>`
            };
            transporter.sendMail(mailOptions, (error) => {
                if (error) console.log("❌ Lỗi gửi mail:", error);
                else console.log('✅ Đã gửi email cho khách: ' + req.body.email);
            });
        }
        res.json({ message: "Đặt hàng thành công!" });
    } catch (error) { res.status(500).json({ message: "Lỗi khi lưu đơn hàng!" }); }
});

// 5.2 Lấy danh sách đơn hàng
app.get('/api/orders', async (req, res) => {
    try { res.json(await Order.find()); } 
    catch (err) { res.status(500).json({ message: "Lỗi!" }); }
});

// 5.3 Admin đổi trạng thái đơn
app.put('/api/orders/:id/status', async (req, res) => {
    try {
        await Order.findOneAndUpdate({ orderId: req.params.id }, { status: req.body.status });
        res.json({ message: "Cập nhật thành công!" });
    } catch (err) { res.status(500).json({ message: "Lỗi!" }); }
});

app.listen(process.env.PORT || 3000, () => console.log(`✅ Máy chủ đang chạy`));