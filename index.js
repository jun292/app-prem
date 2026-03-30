const express = require('express');
const cors = require('cors');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const path = require('path');
const axios = require('axios');
require('dotenv').config();
const { connectDB } = require('./config');
const { rateLimit } = require('express-rate-limit');

const app = express();

// --- PENGATURAN KEAMANAN & PARSER ---
app.use(cors());
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));
app.disable('x-powered-by');

// --- FOLDER PUBLIC ---
app.use(express.static(path.join(__dirname, 'public')));

// ============================================================================
// ========================= SCHEMA DATABASE MONGODB ==========================
// ============================================================================

// Anti DDoS & Spam (Maksimal 5x coba daftar dalam 15 menit per IP)
const registerLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, 
    max: 5, 
    message: { success: false, message: "Terlalu banyak percobaan. Silakan coba lagi dalam 15 menit." }
});
//=====================================//


// 1. Schema User (Sistem Auth)
const userSchema = new mongoose.Schema({
    username: { type: String, required: true, unique: true, trim: true },
    email: { type: String, required: true, unique: true, lowercase: true },
    password: { type: String, required: true },
    balance: { type: Number, default: 0 },
    role: { type: String, default: 'user' },
    createdAt: { type: Date, default: Date.now }
});
const User = mongoose.models.User || mongoose.model('User', userSchema);

// 2. Schema Transaksi (Untuk riwayat order App Premium)
const transactionSchema = new mongoose.Schema({
    invoice: { type: String, required: true, unique: true }, // ID Invoice Deposit Premku
    email: { type: String, required: true },
    product_id: { type: Number, required: true },
    product_name: { type: String, required: true },
    qty: { type: Number, default: 1 },
    amount: { type: Number, required: true }, // Total Harga Bayar
    status: { type: String, default: 'pending' }, // pending, paid, canceled, failed
    accounts: { type: Array, default: [] }, // Data username/password akun premium
    order_id_premku: { type: String, default: null }, // ID Order saat beli ke Premku
    createdAt: { type: Date, default: Date.now }
});
const Transaction = mongoose.models.Transaction || mongoose.model('Transaction', transactionSchema);


// ============================================================================
// ========================== ROUTES AUTHENTICATION ===========================
// ============================================================================

app.post('/api/auth/register', registerLimiter, async (req, res) => {
    try {
        await connectDB();
        const { username, email, password, recaptchaToken } = req.body;

        if (!username || !email || !password) throw new Error("Semua kolom harus diisi.");
        if (password.length < 6) throw new Error("Password minimal 6 karakter.");
        
        // Jika kamu ingin memverifikasi reCAPTCHA ke Server Google (Opsional tapi sangat disarankan)
        // const verifyRecaptcha = await axios.post(`https://www.google.com/recaptcha/api/siteverify?secret=${process.env.RECAPTCHA_SECRET_KEY}&response=${recaptchaToken}`);
        // if (!verifyRecaptcha.data.success) throw new Error("Verifikasi reCAPTCHA gagal, bot terdeteksi.");

        // Cek Email Spesifik
        const existEmail = await User.findOne({ email: email.toLowerCase() });
        if (existEmail) throw new Error("Email ini sudah terdaftar. Silakan gunakan email lain.");

        // Cek Username Spesifik
        const existUser = await User.findOne({ username: username });
        if (existUser) throw new Error("Username ini sudah dipakai. Silakan gunakan username lain.");

        // Enkripsi
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);

        // Simpan
        const newUser = new User({ username, email: email.toLowerCase(), password: hashedPassword });
        await newUser.save();

        res.json({ success: true, message: "Pendaftaran berhasil! Silakan login." });
    } catch (error) {
        res.status(400).json({ success: false, message: error.message });
    }
});

// 2. Login API
app.post('/api/auth/login', async (req, res) => {
    try {
        await connectDB();
        const { email, password } = req.body;
        if (!email || !password) throw new Error("Email dan Password harus diisi.");

        const user = await User.findOne({ email });
        if (!user) throw new Error("Akun tidak ditemukan.");

        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) throw new Error("Password salah.");

        const token = jwt.sign(
            { id: user._id, username: user.username, role: user.role },
            process.env.JWT_SECRET,
            { expiresIn: '7d' }
        );

        res.json({ success: true, message: "Login berhasil!", token, user: { username: user.username, email: user.email, balance: user.balance } });
    } catch (error) { res.status(400).json({ success: false, message: error.message }); }
});


// ============================================================================
// ======================== APP PREMIUM APIs (PREMKU) =========================
// ============================================================================

const PREMKU_URL = 'https://premku.com/api';
const PREMKU_KEY = process.env.PREMKU_API_KEY;
const ADMIN_MARKUP = 3000; // Keuntungan Admin per item (Silakan ubah nominalnya)

// 1. Ambil Katalog Produk
app.get('/api/app/products', async (req, res) => {
    try {
        const extRes = await axios.post(`${PREMKU_URL}/products`, { api_key: PREMKU_KEY });
        if (!extRes.data.success) throw new Error("Gagal mengambil data dari supplier.");

        let products = extRes.data.products.map(p => {
            return { ...p, price: p.price + ADMIN_MARKUP }; // Tambahkan keuntungan
        });
        res.json({ success: true, products });
    } catch (error) { res.status(500).json({ success: false, message: error.message }); }
});

// 2. Cek Stok Real-Time
app.post('/api/app/check-stock', async (req, res) => {
    try {
        const { product_id } = req.body;
        const stockRes = await axios.post(`${PREMKU_URL}/stock`, { api_key: PREMKU_KEY, product_id: parseInt(product_id) });
        if (stockRes.data.success) return res.json({ success: true, stock: stockRes.data.stock });
        throw new Error("Gagal cek stok.");
    } catch (error) { res.status(500).json({ success: false, message: error.message }); }
});

// 3. Checkout (Buat Tagihan QRIS)
app.post('/api/app/checkout', async (req, res) => {
    try {
        await connectDB();
        const { product_id, qty, email } = req.body;
        if (!email || !product_id || qty < 1) throw new Error("Data tidak lengkap.");

        // Pastikan harga & nama produk valid
        const extRes = await axios.post(`${PREMKU_URL}/products`, { api_key: PREMKU_KEY });
        const product = extRes.data.products.find(p => p.id === parseInt(product_id));
        if (!product) throw new Error("Produk tidak ditemukan.");
        
        // Cek Stok Realtime sebelum bayar
        const stockRes = await axios.post(`${PREMKU_URL}/stock`, { api_key: PREMKU_KEY, product_id: parseInt(product_id) });
        if(stockRes.data.stock < qty) throw new Error("Stok tidak mencukupi, silakan kurangi jumlah beli.");

        const finalPricePerItem = product.price + ADMIN_MARKUP;
        const totalBayar = finalPricePerItem * qty;

        // Buat Deposit ke Premku
        const depRes = await axios.post(`${PREMKU_URL}/pay`, { api_key: PREMKU_KEY, amount: totalBayar });
        if (!depRes.data.success) throw new Error(depRes.data.message || "Gagal membuat tagihan.");

        const depositData = depRes.data.data;

        // Simpan Transaksi di DB Kita
        const newTx = new Transaction({
            invoice: depositData.invoice,
            email: email,
            product_id: product_id,
            product_name: product.name,
            qty: qty,
            amount: depositData.total_bayar,
            status: 'pending'
        });
        await newTx.save();

        res.json({ success: true, invoice: depositData.invoice, total_bayar: depositData.total_bayar, qr_image: depositData.qr_image });
    } catch (error) { res.status(500).json({ success: false, message: error.message }); }
});

// 4. Cek Pembayaran & Auto-Order
app.post('/api/app/check-payment', async (req, res) => {
    try {
        await connectDB();
        const { invoice } = req.body;
        const tx = await Transaction.findOne({ invoice });

        if (!tx) throw new Error("Transaksi tidak ditemukan.");
        if (tx.status === 'paid') return res.json({ success: true, status: 'success', accounts: tx.accounts });
        if (tx.status === 'canceled' || tx.status === 'failed') return res.json({ success: true, status: tx.status });

        // Cek Status Deposit ke Premku
        const depStatusRes = await axios.post(`${PREMKU_URL}/pay_status`, { api_key: PREMKU_KEY, invoice });
        if (!depStatusRes.data.success) throw new Error("Gagal mengecek status deposit.");

        // JIKA LUNAS (SUCCESS)
        if (depStatusRes.data.data.status === 'success') {
            try {
                // A. Jika Order belum dibuat (Masih lunas deposit saja)
                if (!tx.order_id_premku) {
                    const orderRes = await axios.post(`${PREMKU_URL}/order`, {
                        api_key: PREMKU_KEY,
                        product_id: tx.product_id,
                        qty: tx.qty
                    });
                    if (!orderRes.data.success) throw new Error(orderRes.data.message);
                    tx.order_id_premku = orderRes.data.invoice;
                    await tx.save();
                }

                // B. Cek Status Order untuk mengambil Akun
                const statRes = await axios.post(`${PREMKU_URL}/status`, { api_key: PREMKU_KEY, invoice: tx.order_id_premku });

                if (statRes.data.success && statRes.data.status === 'success') {
                    // ORDER SUKSES, SIMPAN AKUN KE DB
                    tx.status = 'paid';
                    tx.accounts = statRes.data.accounts;
                    await tx.save();
                    return res.json({ success: true, status: 'success', accounts: tx.accounts });
                } else if (statRes.data.success && statRes.data.status === 'pending') {
                    return res.json({ success: true, status: 'processing' });
                } else {
                    throw new Error("Order diproses, tapi server belum mengembalikan akun.");
                }
            } catch (errOrder) {
                // Saldo masuk, tapi gagal order API
                tx.status = 'failed';
                await tx.save();
                return res.status(400).json({ success: false, message: "Pembayaran berhasil, namun sistem gagal memproses akun. Silakan hubungi Admin dengan screenshot QRIS ini." });
            }
        } 
        else if (depStatusRes.data.data.status === 'canceled') {
            tx.status = 'canceled';
            await tx.save();
            return res.json({ success: true, status: 'canceled' });
        }

        // Masih Pending
        return res.json({ success: true, status: 'pending' });
    } catch (error) { res.status(500).json({ success: false, message: error.message }); }
});

// 5. Cancel Deposit
app.post('/api/app/cancel', async (req, res) => {
    try {
        await connectDB();
        const { invoice } = req.body;
        const cancelRes = await axios.post(`${PREMKU_URL}/cancel_pay`, { api_key: PREMKU_KEY, invoice });
        
        if (cancelRes.data.success) {
            await Transaction.findOneAndUpdate({ invoice }, { status: 'canceled' });
            return res.json({ success: true });
        } else { throw new Error(cancelRes.data.message); }
    } catch (error) { res.status(500).json({ success: false, message: error.message }); }
});

// 6. Ambil Order Terakhir (Untuk Notifikasi Live Toast di Halaman Depan)
app.get('/api/app/latest-order', async (req, res) => {
    try {
        await connectDB();
        // Ambil 1 transaksi sukses terakhir
        const latestTx = await Transaction.findOne({ status: 'paid' }).sort({ createdAt: -1 });
        
        if (latestTx) {
            // Ambil gambar produk untuk ditampilkan di toast
            const extRes = await axios.post(`${PREMKU_URL}/products`, { api_key: PREMKU_KEY });
            const p = extRes.data.products.find(x => x.id === latestTx.product_id);
            
            res.json({
                success: true,
                order: {
                    product_name: latestTx.product_name,
                    amount: latestTx.amount,
                    image: p ? p.image : null
                }
            });
        } else {
            res.json({ success: false });
        }
    } catch (e) { res.status(500).json({ success: false }); }
});

// 7. TRACKING INVOICE (Cek Riwayat User)
app.post('/api/app/track', async (req, res) => {
    try {
        await connectDB();
        const { invoice } = req.body;
        
        if (!invoice) throw new Error("Masukkan ID Invoice yang valid.");

        // Cari transaksi berdasarkan invoice (Hanya ambil data yang perlu agar aman)
        const tx = await Transaction.findOne(
            { invoice: invoice.toUpperCase() }, 
            'invoice product_name qty amount status accounts createdAt'
        );

        if (!tx) throw new Error("Data Invoice tidak ditemukan di sistem.");

        // Kirim kembali data transaksi
        res.json({ success: true, data: tx });
    } catch (error) { 
        res.status(404).json({ success: false, message: error.message }); 
    }
});


// ============================================================================
// ======================= RUTE HALAMAN FRONTEND (VIEWS) ======================
// ============================================================================

// Mengarahkan halaman utama (root) ke Landing Page Katalog (buyapp.html)
app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'public/index.html')));

// Rute untuk Login dan Register
app.get('/login', (req, res) => res.sendFile(path.join(__dirname, 'public/dashboard/login.html')));
app.get('/register', (req, res) => res.sendFile(path.join(__dirname, 'public/dashboard/daftar.html')));
app.get('/riwayatuser', (req, res) => res.sendFile(path.join(__dirname, 'public/riwayatuser.html')));

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`🚀 Server menyala di port ${PORT}`));
module.exports = app;