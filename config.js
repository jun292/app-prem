const mongoose = require('mongoose');
require('dotenv').config();

let cached = global.mongoose;

if (!cached) {
    cached = global.mongoose = { conn: null, promise: null };
}

async function connectDB() {
    if (cached.conn) return cached.conn;

    if (!cached.promise) {
        const opts = { bufferCommands: false, serverSelectionTimeoutMS: 5000 };
        console.log("🔄 Menghubungkan ke MongoDB...");
        cached.promise = mongoose.connect(process.env.MONGODB_URI, opts).then((mongoose) => {
            console.log("✅ MongoDB Connected Berhasil");
            return mongoose;
        });
    }

    try {
        cached.conn = await cached.promise;
    } catch (e) {
        cached.promise = null;
        console.error("❌ Gagal Konek Database:", e);
        throw e;
    }

    return cached.conn;
}

module.exports = { connectDB };