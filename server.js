// server.js
const express = require('express');
const cors = require('cors');
const app = express();
const PORT = 3000;

// 미들웨어 설정
app.use(cors()); // Flutter 앱의 요청을 허용
app.use(express.json()); // JSON 형식의 요청 본문을 파싱

// 테스트용 기본 라우트
app.get('/', (req, res) => {
  res.send('Node.js Server is running!');
});

// 서버 리스닝
app.listen(PORT, () => {
  console.log(`Server listening on port ${PORT}`);
});
// server.js (이어서 작성)
const db = require('./db');

// 게시글 전체 조회 API (GET /posts)
app.get('/posts', async (req, res) => {
  try {
    const result = await db.query('SELECT * FROM posts ORDER BY created_at DESC');
    // DB에서 받은 데이터를 JSON으로 클라이언트에 응답
    res.json(result.rows); 
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: '데이터를 불러오는 데 실패했습니다.' });
  }
});