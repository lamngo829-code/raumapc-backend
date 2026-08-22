const express = require('express');
const cors = require('cors');
const mongoose = require('mongoose');

const app = express();
app.use(cors());
app.use(express.json());

// ==========================================
// 1. KẾT NỐI MONGODB
// ==========================================
mongoose.connect('mongodb+srv://lamngo829_db_user:KDJUXdVXOfCKUSfx@cluster0.r46tion.mongodb.net/raumapc?appName=Cluster0')
    .then(() => console.log('✅ Đã kết nối MongoDB!'))
    .catch(err => console.error('❌ Lỗi kết nối MongoDB:', err));

// ==========================================
// 2. KHUÔN MẪU DỮ LIỆU (SCHEMAS)
// ==========================================
const productSchema = new mongoose.Schema({
    name: String, price: String, img: String, warranty: String,
    specs: String, description: String, category: String
});
const Product = mongoose.model('Product', productSchema);

const orderSchema = new mongoose.Schema({
    orderId: String,
    date: String,
    username: String,
    account: String,
    email: String,
    items: Array,
    total: Number,
    status: String
});
const Order = mongoose.model('Order', orderSchema);

// ==========================================
// 3. API SẢN PHẨM (PRODUCTS)
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
// 4. API ĐƠN HÀNG & GỬI MAIL QUA BREVO HTTP API (Vượt tường lửa Render)
// ==========================================
app.post('/api/orders', async (req, res) => {
    try {
        const newOrder = new Order(req.body);
        await newOrder.save();
        console.log(`🛒 Đơn mới đã lưu Database: ${newOrder.orderId}`);
        res.json({ message: "Đặt hàng thành công!" });
    } catch (error) {
        res.status(500).json({ message: "Lỗi khi lưu đơn hàng!" });
    }
});

// Admin lấy danh sách đơn
app.get('/api/orders', async (req, res) => {
    try { res.json(await Order.find()); }
    catch (err) { res.status(500).json({ message: "Lỗi!" }); }
});

// Admin đổi trạng thái đơn
app.put('/api/orders/:id/status', async (req, res) => {
    try {
        await Order.findOneAndUpdate({ orderId: req.params.id }, { status: req.body.status });
        res.json({ message: "Cập nhật thành công!" });
    } catch (err) { res.status(500).json({ message: "Lỗi!" }); }
});

// ==========================================
// 5. KHỞI ĐỘNG MÁY CHỦ
// ==========================================
app.listen(process.env.PORT || 3000, () => console.log(`✅ Máy chủ đang chạy`));