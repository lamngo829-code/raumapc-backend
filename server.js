const express = require('express');
const cors = require('cors');
const mongoose = require('mongoose'); // Khai báo thư viện kết nối Database

const app = express();
app.use(cors());
app.use(express.json());

// ====================================================
// 1. KẾT NỐI CƠ SỞ DỮ LIỆU MONGODB
// ====================================================
mongoose.connect('mongodb+srv://lamngo829_db_user:KDJUXdVXOfCKUSfx@cluster0.r46tion.mongodb.net/raumapc?appName=Cluster0')
    .then(() => console.log('✅ Đã kết nối thành công với CSDL MongoDB!'))
    .catch(err => console.error('❌ Lỗi kết nối CSDL:', err));

// ====================================================
// 2. TẠO KHUÔN MẪU SẢN PHẨM (SCHEMA) TRONG DATABASE
// ====================================================
const productSchema = new mongoose.Schema({
    name: String,
    price: String,
    img: String,
    warranty: String,
    specs: String,
    description: String,
    category: String // <--- THÊM DÒNG NÀY ĐỂ PHÂN LOẠI
});

const Product = mongoose.model('Product', productSchema);

// ====================================================
// 3. CÁC API THAO TÁC VỚI DATABASE THẬT
// ====================================================

// API Lấy danh sách (READ)
// ... (Kéo xuống API GET) ...
app.get('/api/products', async (req, res) => {
    try {
        const products = await Product.find(); 
        const formattedProducts = products.map(sp => ({
            id: sp._id.toString(),
            name: sp.name,
            price: sp.price,
            img: sp.img,
            warranty: sp.warranty,
            specs: sp.specs,
            description: sp.description,
            category: sp.category || 'khac' // <--- THÊM DÒNG NÀY (nếu SP cũ chưa có nhãn thì gom vào mục Khác)
        }));
        res.json(formattedProducts);
    } catch (error) {
        res.status(500).json({ message: "Lỗi lấy dữ liệu!" });
    }
});

// API Thêm sản phẩm (CREATE)
app.post('/api/products', async (req, res) => {
    try {
        const newProduct = new Product(req.body);
        await newProduct.save(); // Lệnh lưu thẳng vào ổ cứng
        res.json({ message: "Thêm sản phẩm thành công vào CSDL!" });
    } catch (error) {
        res.status(500).json({ message: "Lỗi lưu dữ liệu!" });
    }
});

// API Sửa sản phẩm (UPDATE)
app.put('/api/products/:id', async (req, res) => {
    try {
        // Tìm SP theo ID và cập nhật nội dung mới
        await Product.findByIdAndUpdate(req.params.id, req.body);
        res.json({ message: "Cập nhật sản phẩm thành công!" });
    } catch (error) {
        res.status(500).json({ message: "Lỗi cập nhật!" });
    }
});

// API Xóa sản phẩm (DELETE)
app.delete('/api/products/:id', async (req, res) => {
    try {
        await Product.findByIdAndDelete(req.params.id); // Lệnh xóa khỏi ổ cứng
        res.json({ message: "Đã xóa sản phẩm khỏi hệ thống!" });
    } catch (error) {
        res.status(500).json({ message: "Lỗi khi xóa!" });
    }
});



// ====================================================
// 4. QUẢN LÝ ĐƠN HÀNG (ORDERS) TRONG DATABASE
// ====================================================

// Tạo khuôn mẫu Đơn hàng
const orderSchema = new mongoose.Schema({
    orderId: String,
    date: String,
    username: String,
    items: Array,    // Chứa danh sách các sản phẩm đã mua
    total: Number,
    status: String
});

const Order = mongoose.model('Order', orderSchema);

// API 1: Khách hàng gửi đơn hàng lên Server (CREATE)
app.post('/api/orders', async (req, res) => {
    try {
        const newOrder = new Order(req.body);
        await newOrder.save(); // Lưu ngay vào két sắt MongoDB
        
        console.log("🛒 BÍP BÍP! Có đơn hàng mới nhận:", newOrder.orderId);
        res.json({ message: "Đặt hàng thành công!" });
    } catch (error) {
        res.status(500).json({ message: "Lỗi khi lưu đơn hàng!" });
    }
});

// API 2: Admin lấy danh sách đơn hàng về xem (READ)
app.get('/api/orders', async (req, res) => {
    try {
        const orders = await Order.find();
        res.json(orders);
    } catch (error) {
        res.status(500).json({ message: "Lỗi lấy danh sách đơn hàng!" });
    }
});



// Khởi động Server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`✅ Máy chủ đang chạy tại cổng ${PORT}`);
});


// API 3: Admin cập nhật trạng thái đơn hàng (UPDATE)
app.put('/api/orders/:id/status', async (req, res) => {
    try {
        const maDonHang = req.params.id; // Lấy mã đơn (VD: RM123456)
        const trangThaiMoi = req.body.status; // Lấy trạng thái Admin vừa chọn

        // Tìm đơn hàng trong két sắt và đổi trạng thái
        await Order.findOneAndUpdate({ orderId: maDonHang }, { status: trangThaiMoi });
        
        console.log(`📦 Đã chuyển đơn ${maDonHang} sang trạng thái: ${trangThaiMoi}`);
        res.json({ message: "Cập nhật trạng thái thành công!" });
    } catch (error) {
        res.status(500).json({ message: "Lỗi cập nhật trạng thái đơn hàng!" });
    }
});