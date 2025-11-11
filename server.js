// server.js (⭐️ 최종 완성본)
const express = require('express');
const http = require('http'); // ⭐️ WebSocket을 위해 http 모듈 사용
const WebSocket = require('ws'); // ⭐️ WebSocket 모듈
const cors = require('cors');
const jwt = require('jsonwebtoken'); // ⭐️ JWT 모듈
const db = require('./db'); // ⭐️ db.js
require('dotenv').config(); // ⭐️ .env 파일 로드

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET; // ⭐️ 대문자 JWT_SECRET

// 1. 미들웨어 설정
app.use(cors());
app.use(express.json()); // JSON 형식의 요청 본문을 파싱

// ---------------------------------
// 🔑 2. 인증 API (Flutter의 AuthService)
// ---------------------------------

// POST /auth/login (익명 로그인/회원가입)
app.post('/auth/login', async (req, res) => {
  const { displayName } = req.body;
  if (!displayName) {
    return res.status(400).json({ message: 'displayName이 필요합니다.' });
  }

  try {
    // 1. 이름이 같은 유저가 있으면 찾고, 없으면 새로 만듭니다.
    let userResult = await db.query(
      'SELECT * FROM users WHERE display_name = $1', 
      [displayName]
    );
    let user = userResult.rows[0];

    if (!user) {
        // 2. 새 사용자 생성 (⭐️ 'email', 'password_hash'에 가짜 데이터 추가)
        
        // ⭐️ 2-1. 중복되지 않는 가짜 이메일 생성 (예: 1678886400000@dummy.com)
        const dummyEmail = `${Date.now()}@dummy.com`;
        // ⭐️ 2-2. 가짜 패스워드
        const dummyPassword = 'dummy_password_hash'; 

        userResult = await db.query(
          `INSERT INTO users (display_name, preferred_sport, email, password_hash) 
           VALUES ($1, $2, $3, $4) 
           RETURNING *`,
          [displayName, '', dummyEmail, dummyPassword] // ⭐️ 4개 값 전달
        );
        user = userResult.rows[0];
      }

    // 3. JWT 토큰 생성 (사용자 ID와 이름을 담음)
    const token = jwt.sign(
      { userId: user.id, name: user.display_name }, 
      JWT_SECRET, // ⭐️ 대문자 JWT_SECRET
      { expiresIn: '30d' } // 30일 유효
    );

    // 4. Flutter 앱에 유저 정보와 토큰 반환
    res.json({ user, token });

  } catch (err) {
    console.error(err);
    res.status(500).json({ message: '서버 오류' });
  }
});

// ---------------------------------
// 🔐 3. 인증 미들웨어 (⭐️ 핵심 보안)
// ---------------------------------
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1]; // Bearer TOKEN

  if (token == null) return res.sendStatus(401); // 토큰 없음

  jwt.verify(token, JWT_SECRET, (err, user) => { // ⭐️ 대문자 JWT_SECRET
    if (err) return res.sendStatus(403); // 유효하지 않은 토큰
    req.user = user; // ⭐️ 요청 객체에 유저 정보를 심음
    next(); // 다음 단계로 이동
  });
};

// ---------------------------------
// 👤 4. 사용자 API (프로필)
// ---------------------------------

// GET /users/me (내 프로필 정보)
app.get('/users/me', authenticateToken, async (req, res) => {
  try {
    const userId = req.user.userId; // ⭐️ 미들웨어가 검증한 내 ID
    const userResult = await db.query('SELECT * FROM users WHERE id = $1', [userId]);
    
    // 숨긴 유저 목록도 가져오기 (hidden_users 테이블)
    const hiddenResult = await db.query('SELECT hidden_id FROM hidden_users WHERE hider_id = $1', [userId]);
    const hiddenUsers = hiddenResult.rows.map(row => row.hidden_id);
    
    const user = userResult.rows[0];
    user.hidden_users = hiddenUsers; // ⭐️ Flutter 모델에 맞게 데이터 조합

    res.json(user);
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: '서버 오류' });
  }
});

// PUT /users/me (프로필 수정)
app.put('/users/me', authenticateToken, async (req, res) => {
  const userId = req.user.userId;
  const { displayName, preferredSport } = req.body;

  try {
    const result = await db.query(
      'UPDATE users SET display_name = $1, preferred_sport = $2 WHERE id = $3 RETURNING *',
      [displayName, preferredSport, userId]
    );
    res.json(result.rows[0]);
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: '프로필 업데이트 실패' });
  }
});

// GET /users (다른 사용자 목록 - '나'와 '숨긴' 사용자 제외)
app.get('/users', authenticateToken, async (req, res) => {
    const userId = req.user.userId;
    try {
        // ⭐️ 내가 숨긴 사람(h.hidden_id)을 제외(IS NULL)하고, '나'도 제외
        const query = `
            SELECT u.* FROM users u
            LEFT JOIN hidden_users h ON u.id = h.hidden_id AND h.hider_id = $1
            WHERE u.id != $1 AND h.hidden_id IS NULL;
        `;
        const result = await db.query(query, [userId]);
        res.json(result.rows);
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: '사용자 목록 로드 실패' });
    }
});


// ---------------------------------
// 💬 5. 채팅방 API
// ---------------------------------

// GET /rooms (내 채팅방 목록)
app.get('/rooms', authenticateToken, async (req, res) => {
  const userId = req.user.userId;
  try {
    // ⭐️ 1.1, 1.3 기능이 모두 포함된 복잡한 쿼리
    const query = `
      SELECT 
        cr.id, 
        cr.last_message, 
        cr.last_message_timestamp,
        p.unread_count AS "my_unread_count", -- ⭐️ 내 안읽음 개수
        p.left_at, -- ⭐️ 내가 떠난 시간 (영구 삭제용)
        -- ⭐️ 1:1 채팅방이면 상대방 이름, 그룹이면 그룹 이름
        CASE 
          WHEN cr.room_name IS NULL THEN 
            (SELECT u.display_name FROM participants p_inner 
             JOIN users u ON u.id = p_inner.user_id
             WHERE p_inner.chat_room_id = cr.id AND p_inner.user_id != $1)
          ELSE cr.room_name
        END AS "room_name"
      FROM chat_rooms cr
      JOIN participants p ON cr.id = p.chat_room_id
      WHERE p.user_id = $1 AND p.is_hidden = FALSE -- ⭐️ 내가 숨기지 않은 방만
      ORDER BY cr.last_message_timestamp DESC;
    `;
    const result = await db.query(query, [userId]);
    res.json(result.rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: '채팅방 로드 오류' });
  }
});

// ⭐️⭐️⭐️ 누락되었던 "채팅방 생성" API ⭐️⭐️⭐️
// POST /rooms (새 채팅방 생성)
app.post('/rooms', authenticateToken, async (req, res) => {
  const { userIds, roomName } = req.body; // userIds는 상대방 ID 목록
  const creatorId = req.user.userId; // 방을 만든 사람 ID (내 ID)

  // 1. 모든 참가자 목록 (나 + 상대방)
  const allParticipantIds = [creatorId, ...userIds];

  try {
    // ⭐️ 트랜잭션 시작
    await db.query('BEGIN');

    // 2. chat_rooms 테이블에 방 생성
    const roomResult = await db.query(
      'INSERT INTO chat_rooms (room_name, last_message, last_message_timestamp) VALUES ($1, $2, NOW()) RETURNING id',
      [roomName, '채팅방이 생성되었습니다.']
    );
    const newChatRoomId = roomResult.rows[0].id;

    // 3. participants 테이블에 모든 참가자 추가
    const participantPromises = allParticipantIds.map(userId => {
      return db.query(
        'INSERT INTO participants (chat_room_id, user_id, unread_count, is_hidden, left_at) VALUES ($1, $2, $3, $4, $5)',
        [newChatRoomId, userId, 0, false, null] // ⭐️ 0, false, null로 초기화
      );
    });
    
    // 4. 모든 참가자 추가 쿼리가 성공할 때까지 대기
    await Promise.all(participantPromises);

    // 5. ⭐️ 모든 작업 성공 시 DB에 최종 반영
    await db.query('COMMIT');

    // 6. Flutter 앱에 새로 만들어진 방 ID 응답
    res.status(201).json({ id: newChatRoomId });

  } catch (err) {
    // 7. ⭐️ 작업 중 하나라도 실패하면 모두 되돌림
    await db.query('ROLLBACK');
    console.error(err);
    res.status(500).json({ message: '채팅방 생성 실패' });
  }
});
// ⭐️⭐️⭐️ 여기까지 ⭐️⭐️⭐️

// GET /rooms/:roomId/messages (특정 방의 메시지 목록)
app.get('/rooms/:roomId/messages', authenticateToken, async (req, res) => {
    const { roomId } = req.params;
    const userId = req.user.userId;
    const { leftAt } = req.query; // ⭐️ ?leftAt=... (Flutter가 보낸 '떠난 시간')

    try {
        // 1. 이 유저가 방에 속해있는지 확인 (보안)
        const partCheck = await db.query(
            'SELECT * FROM participants WHERE chat_room_id = $1 AND user_id = $2',
            [roomId, userId]
        );
        if (partCheck.rows.length === 0) {
            return res.status(403).json({ message: '권한이 없습니다.' });
        }

        // 2. 메시지 조회 쿼리
        let query = 'SELECT m.* FROM messages m WHERE m.chat_room_id = $1';
        let params = [roomId];
        
        // ⭐️ '떠난 시간'이 있으면, 그 시간 이후의 메시지만 필터링
        if (leftAt) {
            query += ' AND m.created_at > $2';
            params.push(leftAt);
        }
        
        query += ' ORDER BY m.created_at DESC LIMIT 50'; // 최신 50개

        const result = await db.query(query, params);
        res.json(result.rows);

    } catch (err) {
        console.error(err);
        res.status(500).json({ message: '메시지 로드 실패' });
    }
});


// POST /rooms/:roomId/messages (메시지 전송)
app.post('/rooms/:roomId/messages', authenticateToken, async (req, res) => {
  const { text } = req.body;
  const { roomId } = req.params;
  const senderId = req.user.userId;

  try {
    // ⭐️ 트랜잭션: 여러 작업을 하나로 묶음 (중요)
    await db.query('BEGIN');

    // 1. messages 테이블에 메시지 삽입
    const messageResult = await db.query(
      'INSERT INTO messages (chat_room_id, sender_id, text) VALUES ($1, $2, $3) RETURNING *',
      [roomId, senderId, text]
    );
    const newMessage = messageResult.rows[0];

    // 2. chat_rooms 테이블의 마지막 메시지 업데이트
    await db.query(
      'UPDATE chat_rooms SET last_message = $1, last_message_timestamp = $2 WHERE id = $3',
      [text, newMessage.created_at, roomId]
    );

    // 3. participants 테이블의 안읽음 카운트 업데이트 (⭐️ 중요 로직)
    await db.query(
      `UPDATE participants SET 
         unread_count = CASE 
           WHEN user_id = $1 THEN 0 
           ELSE unread_count + 1 
         END,
         is_hidden = FALSE, -- ⭐️ 새 메시지 오면 숨김 해제
         left_at = NULL     -- ⭐️ 새 메시지 오면 '떠난 시간' 초기화
       WHERE chat_room_id = $2`,
      [senderId, roomId]
    );
    
    await db.query('COMMIT'); // ⭐️ 모든 작업 성공 시 DB에 최종 반영

    // ⭐️ (핵심) WebSocket으로 이 방에 연결된 모든 클라이언트에게 새 메시지 전송
    broadcastMessage(roomId, newMessage);

    res.status(201).json(newMessage);
  } catch (err) {
    await db.query('ROLLBACK'); // ⭐️ 작업 중 하나라도 실패하면 모두 되돌림
    console.error(err);
    res.status(500).json({ message: '메시지 전송 오류' });
  }
});

// (기타 /rooms 생성, /rooms/:roomId/hide 등 다른 API들도 여기에 구현)


// ---------------------------------
// ⚡️ 6. WebSocket 서버 설정 (실시간 알림용)
// ---------------------------------

// 1. Express 앱을 http 서버로 감싸기 (WebSocket과 포트를 공유하기 위함)
const server = http.createServer(app); 

// 2. WebSocket 서버를 http 서버에 연결
const wss = new WebSocket.Server({ server });

// ⭐️ key: userId, value: ws (어떤 유저가 어떤 WebSocket 연결을 쓰는지)
const clients = {}; 

wss.on('connection', (ws, req) => {
  // ⭐️ 1. 연결 시 토큰 검증 (Flutter가 ws://.../chat?token=...로 요청)
  const token = req.url.split('token=')[1];
  if (!token) {
    return ws.close(1008, '토큰이 필요합니다.');
  }

  let userId;
  try {
    const payload = jwt.verify(token, JWT_SECRET); // ⭐️ 대문자 JWT_SECRET
    userId = payload.userId;
    clients[userId] = ws; // ⭐️ 이 유저(userId)는 이 ws 연결을 쓴다고 저장
    console.log(`[WS] 클라이언트 연결됨: ${userId}`);
  } catch (err) {
    return ws.close(1008, '유효하지 않은 토큰');
  }

  ws.on('message', (message) => {
    // (지금은 서버가 받기만 하고, Flutter가 보내는 경우는 없으므로 비워둠)
    console.log(`[WS] 수신: ${message}`);
  });

  ws.on('close', () => {
    delete clients[userId]; // ⭐️ 연결 종료 시 맵에서 제거
    console.log(`[WS] 클라이언트 연결 끊김: ${userId}`);
  });
});

// ⭐️ 7. WebSocket 메시지 브로드캐스트 함수 (⭐️ API가 DB 저장 후 호출)
async function broadcastMessage(roomId, message) {
  // 1. 이 방에 속한 모든 사용자 ID 조회 (participants 테이블)
  const result = await db.query('SELECT user_id FROM participants WHERE chat_room_id = $1', [roomId]);
  const userIds = result.rows.map(row => row.user_id);

  // 2. Flutter의 'Message' 모델에 맞는 JSON 생성
  const payload = JSON.stringify({
    type: 'newMessage', // ⭐️ Flutter ChatService가 받을 이벤트 타입
    payload: {
      id: message.id,
      chat_room_id: message.chat_room_id,
      sender_id: message.sender_id,
      text: message.text,
      created_at: message.created_at,
      unread_count: userIds.length - 1, // (간단 예시. 정확도는 개선 필요)
    }
  });

  // 3. 현재 접속 중인(clients 맵에 있는) 유저에게만 메시지 전송
  for (const uid of userIds) {
    const ws = clients[uid];
    if (ws && ws.readyState === WebSocket.OPEN) {
      ws.send(payload);
      
      // ⭐️ (개선) 채팅방 목록 갱신을 위한 'roomUpdate' 이벤트도 보내야 함
    }
  }
}


// ---------------------------------
// 8. 서버 시작
// ---------------------------------
// app.listen 대신 http 서버(server)를 실행합니다.
server.listen(PORT, () => {
  console.log(`Server (HTTP + WS) listening on port ${PORT}`);
});
