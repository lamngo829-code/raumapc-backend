// Bộ test tập trung vào ĐÚNG các lỗi nghiêm trọng đã tìm thấy và sửa trong dự án này:
// - Trừ tồn kho 2 lần khi tạo đơn hàng
// - Không tìm được sản phẩm khi item.id là productId dạng chữ (từ ô Tìm kiếm) thay vì _id MongoDB
// - Hủy đơn không hoàn lại tồn kho
// - Giả mạo trạng thái "đã thanh toán" qua VNPay mà không xác thực chữ ký
// - API đơn hàng lộ dữ liệu khách hàng / không kiểm tra quyền Admin
// - Lãi luôn bằng Doanh thu vì không trừ giá vốn
const crypto = require('crypto');
const { MongoMemoryServer } = require('mongodb-memory-server');

let mongod, app, request, mongoose, jwt, Product, Order, User, Admin;

const VNP_SECRET = 'TESTSECRETKEYFORUNITTESTSONLY12';

// Tự ký y hệt cách VNPay THẬT sẽ ký (độc lập với code server, để test không tự kiểm tra chính nó)
function signVnpParams(params) {
    const sortedKeys = Object.keys(params).sort();
    const signData = sortedKeys
        .map(k => `${k}=${encodeURIComponent(params[k]).replace(/%20/g, '+')}`)
        .join('&');
    return crypto.createHmac('sha512', VNP_SECRET).update(Buffer.from(signData, 'utf-8')).digest('hex');
}

beforeAll(async () => {
    mongod = await MongoMemoryServer.create();
    process.env.MONGO_URI = mongod.getUri();
    process.env.JWT_SECRET = 'test-jwt-secret';
    process.env.VNP_HASHSECRET = VNP_SECRET;
    process.env.VNP_TMNCODE = 'TESTCODE';
    process.env.ADMIN_PASS = 'test-admin-pass-123';

    app = require('../server.js');
    request = require('supertest');
    mongoose = require('mongoose');
    jwt = require('jsonwebtoken');

    if (mongoose.connection.readyState !== 1) {
        await new Promise(resolve => mongoose.connection.once('connected', resolve));
    }

    Product = mongoose.model('Product');
    Order = mongoose.model('Order');
    User = mongoose.model('User');
    Admin = mongoose.model('Admin');
}, 60000);

afterAll(async () => {
    await mongoose.connection.close();
    await mongod.stop();
});

afterEach(async () => {
    const collections = mongoose.connection.collections;
    for (const key in collections) await collections[key].deleteMany({});
});

async function createProduct(overrides = {}) {
    return Product.create({
        productId: 'TEST0000001',
        name: 'Sản phẩm test',
        price: 1000000,
        importPrice: 700000,
        stock: 10,
        status: 'Còn hàng',
        category: 'cpu',
        img: 'http://example.com/img.jpg',
        ...overrides
    });
}

async function makeAdminToken() {
    const admin = await Admin.create({ fullName: 'Test Admin', username: 'testadmin_' + Date.now() + '_' + Math.random(), password: 'x', role: 'admin' });
    return jwt.sign({ id: admin._id.toString(), username: admin.username, role: 'admin' }, process.env.JWT_SECRET, { expiresIn: '1h' });
}

async function makeUserToken(username) {
    const user = await User.create({ fullName: 'Test User', username, password: 'x', phone: '0900000000', email: username + '@example.com', role: 'user' });
    return jwt.sign({ id: user._id.toString(), username: user.username, role: 'user' }, process.env.JWT_SECRET, { expiresIn: '1h' });
}

describe('Trừ / hoàn tồn kho khi đặt và hủy đơn hàng', () => {
    test('POST /api/orders chỉ trừ kho đúng 1 lần (chống lỗi trừ kho 2 lần)', async () => {
        const product = await createProduct({ stock: 10 });
        const userToken = await makeUserToken('khachtest1');

        const res = await request(app).post('/api/orders').set('Authorization', 'Bearer ' + userToken).send({
            orderId: 'TESTORDER1',
            date: new Date().toLocaleString('vi-VN'),
            username: 'Khách Test (0900000000 - Địa chỉ test)',
            email: 'test1@example.com',
            items: [{ id: product._id.toString(), name: product.name, price: product.price, quantity: 3 }],
            total: product.price * 3,
            status: 'Chờ duyệt',
            paymentMethod: 'Thanh toán COD'
        });

        expect(res.status).toBe(200);
        const updated = await Product.findById(product._id);
        expect(updated.stock).toBe(7); // 10 - 3, KHÔNG PHẢI 4 (nếu bị trừ 2 lần)
    });

    test('POST /api/orders tìm đúng sản phẩm khi item.id là productId dạng chữ (từ ô Tìm kiếm)', async () => {
        const product = await createProduct({ stock: 10, productId: 'VGA0000099', importPrice: 500000, price: 900000 });
        const userToken = await makeUserToken('khachtest2');

        const res = await request(app).post('/api/orders').set('Authorization', 'Bearer ' + userToken).send({
            orderId: 'TESTORDER2',
            date: new Date().toLocaleString('vi-VN'),
            username: 'Khách Test (0900000000 - Địa chỉ test)',
            email: 'test2@example.com',
            items: [{ id: 'VGA0000099', name: product.name, price: product.price, quantity: 2 }], // id dạng chữ, không phải _id
            total: product.price * 2,
            status: 'Chờ duyệt',
            paymentMethod: 'Thanh toán COD'
        });

        expect(res.status).toBe(200);
        const updated = await Product.findById(product._id);
        expect(updated.stock).toBe(8); // Phải trừ được kho dù id là chuỗi productId

        const order = await Order.findOne({ orderId: 'TESTORDER2' });
        expect(order.totalImportPrice).toBe(500000 * 2); // Phải tính được giá vốn dù id là chuỗi productId
    });

    test('Admin hủy đơn hàng sẽ hoàn lại đúng số lượng tồn kho đã trừ', async () => {
        const product = await createProduct({ stock: 10 });
        const adminToken = await makeAdminToken();
        const userToken = await makeUserToken('khachtest3');

        await request(app).post('/api/orders').set('Authorization', 'Bearer ' + userToken).send({
            orderId: 'TESTORDER3',
            date: new Date().toLocaleString('vi-VN'),
            username: 'Khách Test (0900000000 - Địa chỉ test)',
            email: 'test3@example.com',
            items: [{ id: product._id.toString(), name: product.name, price: product.price, quantity: 4 }],
            total: product.price * 4,
            status: 'Chờ duyệt',
            paymentMethod: 'Thanh toán COD'
        });

        expect((await Product.findById(product._id)).stock).toBe(6);

        const res = await request(app)
            .put('/api/orders/TESTORDER3/status')
            .set('Authorization', 'Bearer ' + adminToken)
            .send({ status: 'Đã hủy' });

        expect(res.status).toBe(200);
        expect((await Product.findById(product._id)).stock).toBe(10); // Hoàn lại đủ 4
    });
});

describe('Bảo mật quyền truy cập API đơn hàng', () => {
    test('GET /api/orders bị từ chối nếu không đăng nhập', async () => {
        const res = await request(app).get('/api/orders');
        expect(res.status).toBe(403);
    });

    test('GET /api/orders bị từ chối nếu không phải Admin', async () => {
        const userToken = await makeUserToken('khachthuong1');
        const res = await request(app).get('/api/orders').set('Authorization', 'Bearer ' + userToken);
        expect(res.status).toBe(403);
    });

    test('GET /api/orders/my chỉ trả về đơn hàng của chính khách đăng nhập, không lẫn khách khác', async () => {
        await Order.create({ orderId: 'A1', account: 'nguoiA', date: '01/01/2026', username: 'A', items: [], total: 100, status: 'Chờ duyệt' });
        await Order.create({ orderId: 'B1', account: 'nguoiB', date: '01/01/2026', username: 'B', items: [], total: 200, status: 'Chờ duyệt' });

        const tokenA = await makeUserToken('nguoiA');
        const res = await request(app).get('/api/orders/my').set('Authorization', 'Bearer ' + tokenA);

        expect(res.status).toBe(200);
        expect(res.body.length).toBe(1);
        expect(res.body[0].orderId).toBe('A1');
    });

    test('PUT /api/orders/:id/status bị từ chối nếu không đăng nhập', async () => {
        const res = await request(app).put('/api/orders/XYZ/status').send({ status: 'Hoàn thành' });
        expect(res.status).toBe(403);
    });

    test('DELETE /api/orders/:id bị từ chối nếu không đăng nhập', async () => {
        const res = await request(app).delete('/api/orders/XYZ');
        expect(res.status).toBe(403);
    });

    test('POST /api/orders bị từ chối nếu không đăng nhập (chống tạo đơn giả qua API trực tiếp)', async () => {
        const product = await createProduct({ stock: 10 });
        const res = await request(app).post('/api/orders').send({
            orderId: 'NOAUTH1', date: new Date().toLocaleString('vi-VN'), username: 'Khách Test',
            email: 'noauth@example.com', items: [{ id: product._id.toString(), name: product.name, price: product.price, quantity: 1 }],
            total: product.price, status: 'Chờ duyệt', paymentMethod: 'Thanh toán COD'
        });
        expect(res.status).toBe(403);
        expect((await Product.findById(product._id)).stock).toBe(10); // Không được trừ kho vì đơn không được tạo
    });

    test('POST /api/orders luôn gắn account theo tài khoản đăng nhập, không tin account client tự gửi lên', async () => {
        const userToken = await makeUserToken('nguoiThat');
        await request(app).post('/api/orders').set('Authorization', 'Bearer ' + userToken).send({
            orderId: 'SPOOF1', date: new Date().toLocaleString('vi-VN'), username: 'Khách Test',
            account: 'nguoiGiaMao', // Cố tình gửi account khác - phải bị bỏ qua
            email: 'spoof@example.com', items: [], total: 0, status: 'Chờ duyệt', paymentMethod: 'Thanh toán COD'
        });
        const order = await Order.findOne({ orderId: 'SPOOF1' });
        expect(order.account).toBe('nguoiThat'); // Không phải 'nguoiGiaMao'
    });
});

describe('Xác thực chữ ký thanh toán VNPay (chống giả mạo)', () => {
    async function createPendingOrder(orderId) {
        await Order.create({
            orderId, account: 'khachvnpay', date: '01/01/2026', username: 'VNPay Test',
            items: [], total: 5000000, status: 'Đang chờ thanh toán', paymentMethod: 'Thanh toán VNPay'
        });
    }

    test('Chữ ký hợp lệ (giống VNPay thật ký) sẽ cập nhật đơn hàng thành Đã thanh toán', async () => {
        await createPendingOrder('VNPOK1');

        const params = { vnp_TxnRef: 'VNPOK1', vnp_ResponseCode: '00', vnp_Amount: '500000000' };
        const secureHash = signVnpParams(params);

        const res = await request(app).get('/api/vnpay/verify-return').query({ ...params, vnp_SecureHash: secureHash });

        expect(res.status).toBe(200);
        expect(res.body.success).toBe(true);
        expect(res.body.status).toBe('Đã thanh toán (Chờ giao)');
    });

    test('Chữ ký bị giả mạo (không đúng bí mật thật) sẽ bị từ chối, KHÔNG cập nhật đơn hàng', async () => {
        await createPendingOrder('VNPFAKE1');

        // Kẻ tấn công tự chế URL, không biết VNP_HASHSECRET thật nên không ký đúng được
        const res = await request(app).get('/api/vnpay/verify-return').query({
            vnp_TxnRef: 'VNPFAKE1', vnp_ResponseCode: '00', vnp_SecureHash: 'chuoi-gia-mao-khong-hop-le'
        });

        expect(res.status).toBe(400);
        expect(res.body.success).toBe(false);

        const order = await Order.findOne({ orderId: 'VNPFAKE1' });
        expect(order.status).toBe('Đang chờ thanh toán'); // Đơn hàng KHÔNG được đổi thành đã thanh toán
    });

    test('Thanh toán thất bại/hủy sẽ chuyển đơn sang Đã hủy và hoàn lại tồn kho đã trừ trước đó', async () => {
        const product = await createProduct({ stock: 10 });
        await Order.create({
            orderId: 'VNPCANCEL1', account: 'khachvnpay2', date: '01/01/2026', username: 'VNPay Cancel Test',
            items: [{ id: product._id.toString(), name: product.name, price: product.price, quantity: 2 }],
            total: product.price * 2, status: 'Đang chờ thanh toán', paymentMethod: 'Thanh toán VNPay'
        });
        await Product.updateOne({ _id: product._id }, { $inc: { stock: -2 } }); // Mô phỏng đã trừ kho lúc tạo đơn

        const params = { vnp_TxnRef: 'VNPCANCEL1', vnp_ResponseCode: '24' }; // Mã 24 = khách hủy
        const secureHash = signVnpParams(params);

        const res = await request(app).get('/api/vnpay/verify-return').query({ ...params, vnp_SecureHash: secureHash });

        expect(res.status).toBe(200);
        expect(res.body.status).toBe('Đã hủy');
        expect((await Product.findById(product._id)).stock).toBe(10); // Hoàn lại tồn kho
    });
});

describe('Tính Lãi từ Doanh thu', () => {
    test('Lãi = Doanh thu - Tổng giá vốn (không còn luôn bằng Doanh thu)', async () => {
        const todayStr = new Date().toLocaleDateString('vi-VN'); // d/m/yyyy, khớp regex parse ngày trong server.js
        await Order.create({
            orderId: 'REV1', account: 'khachrev', date: todayStr, username: 'Rev Test',
            items: [], total: 10000000, totalImportPrice: 6000000, status: 'Hoàn thành'
        });

        const adminToken = await makeAdminToken();
        const res = await request(app).get('/api/admin/revenue').set('Authorization', 'Bearer ' + adminToken);
        expect(res.status).toBe(200);
        expect(res.body.totalRevenue).toBe(10000000);
        expect(res.body.totalProfit).toBe(4000000); // 10tr - 6tr, KHÔNG bằng Doanh thu
    });

    test('GET /api/admin/revenue bị từ chối nếu không đăng nhập hoặc không phải Admin', async () => {
        const noAuthRes = await request(app).get('/api/admin/revenue');
        expect(noAuthRes.status).toBe(403);

        const userToken = await makeUserToken('khachthuong2');
        const userRes = await request(app).get('/api/admin/revenue').set('Authorization', 'Bearer ' + userToken);
        expect(userRes.status).toBe(403);
    });
});
