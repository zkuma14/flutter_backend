// db.js (⭐️ 수정본)
const { Pool } = require('pg');
require('dotenv').config();

const pool = new Pool({
  user: process.env.DB_USER,
  host: process.env.DB_HOST,
  database: process.env.DB_DATABASE,
  password: process.env.DB_PASSWORD,
  port: process.env.DB_PORT,
  ssl: {
    rejectUnauthorized: false
  }
});

const { Pool } = require('pg');

const pool = new Pool({
  user: '당신의_DB_사용자_이름', // 예: 'user_xyz'
  host: 'render에서_제공한_호스트_주소', // 예: 'dpg-abcd123-a.us-west-2.render.com'
  database: '당신의_DB_이름', // 예: 'mydbname'
  password: '당신의_DB_비밀번호',
  port: 5432, // PostgreSQL 기본 포트
  ssl: {
    // Render와 같은 클라우드 DB는 SSL 연결이 필요할 수 있습니다.
    rejectUnauthorized: false
  }
});

module.exports = {
  // ⭐️ 기존 쿼리 (트랜잭션 X)
  query: (text, params) => pool.query(text, params),
  
  // ⭐️⭐️⭐️ 트랜잭션을 위해 이 함수를 추가하세요! ⭐️⭐️⭐️
  getClient: () => pool.connect(),
};