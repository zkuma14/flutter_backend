// db.js (수정된 코드 👍)
const { Pool } = require('pg');
require('dotenv').config();

const pool = new Pool({
  user: process.env.DB_USER,
  host: process.env.DB_HOST,
  database: process.env.DB_DATABASE,
  password: process.env.DB_PASSWORD,
  port: process.env.DB_PORT,
  
  // ⭐️⭐️⭐️ 이 코드를 추가하세요! ⭐️⭐️⭐️
  ssl: {
    rejectUnauthorized: false
  }
  // ⭐️⭐️⭐️⭐️⭐️⭐️⭐️⭐️⭐️⭐️⭐️⭐️⭐️⭐️⭐️⭐️
});

module.exports = {
  query: (text, params) => pool.query(text, params),
};