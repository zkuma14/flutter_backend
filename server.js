// server.js (⭐️ Google 인증 + DB 트랜잭션 + Real API 융합본)
// (DB 스키마가 서버 코드에 맞춰져 있다고 가정하고, snake_case 통신 문제를 수정한 버전)

const express = require('express');
const http = require('http');
const WebSocket = require('ws');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const db = require('./db'); // ⭐️ db.getClient()가 포함된 DB 모듈
require('dotenv').config();
const { OAuth2Client } = require('google-auth-library'); // ⭐️ Google 인증 라이브러리 (File 1)

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET;
const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID; // ⭐️ .env에서 Google 클라이언트 ID 로드 (File 1)
const client = new OAuth2Client(GOOGLE_CLIENT_ID); // ⭐️ Google 클라이언트 초기화 (File 1)

// 1. 미들웨어 설정
app.use(cors());
app.use(express.json());

// ---------------------------------
// 🔑 2. 인증 API (⭐️ Google 로그인 포함)
// ---------------------------------

// POST /auth/login (익명 로그인/회원가입)
app.post('/auth/login', async (req, res) => {
  const { displayName } = req.body;
  if (!displayName) {
    return res.status(400).json({ message: 'displayName이 필요합니다.' });
  }
  try {
    let userResult = await db.query(
      'SELECT * FROM users WHERE display_name = $1',
      [displayName]
    );
    let user = userResult.rows[0];
    if (!user) {
      const dummyEmail = `${Date.now()}@dummy.com`;
      // ⭐️ DB 스키마에 kakao_id, google_id가 없을 수 있으므로 INSERT 문에서 제거 (사용자 스키마 기반)
      userResult = await db.query(
        `INSERT INTO users (display_name, preferred_sport, email) 
           VALUES ($1, $2, $3) 
           RETURNING *`,
        [displayName, '', dummyEmail]
      );
      user = userResult.rows[0];
    }
    const token = jwt.sign(
      { userId: user.id, name: user.display_name },
      JWT_SECRET,
      { expiresIn: '30d' }
    );
    res.json({ user, token });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: '서버 오류' });
  }
});

// ⭐️ POST /auth/google/login (신규 Google 로그인 - File 1)
app.post('/auth/google/login', async (req, res) => {
  const { idToken } = req.body; 

  if (!idToken) {
    return res.status(400).json({ message: 'Google ID 토큰이 필요합니다.' });
  }

  try {
    // 1. Google 서버에 ID 토큰 검증 요청
    const ticket = await client.verifyIdToken({
      idToken,
      audience: GOOGLE_CLIENT_ID, 
    });

    const payload = ticket.getPayload();
    const googleId = payload['sub']; 
    const googleName = payload['name'];
    const googleEmail = payload['email'];

    // 2. DB에서 Google ID로 사용자 조회
    let userResult = await db.query(
      'SELECT * FROM users WHERE google_id = $1',
      [googleId]
    );
    let user = userResult.rows[0];

    // 3. 사용자가 없으면 새로 회원가입
    if (!user) {
      // ⭐️ DB 스키마에 kakao_id가 없을 수 있으므로 INSERT 문에서 제거
      const newUserResult = await db.query(
        `INSERT INTO users (display_name, email, google_id, preferred_sport)
         VALUES ($1, $2, $3, $4)
         RETURNING *`,
        [googleName, googleEmail, googleId, '']
      );
      user = newUserResult.rows[0];
    }

    // 4. 우리 앱의 JWT 토큰 생성
    const token = jwt.sign(
      { userId: user.id, name: user.display_name },
      JWT_SECRET,
      { expiresIn: '30d' }
    );

    // 5. Flutter에 유저 정보와 우리 앱 토큰 반환
    res.json({ user, token });

  } catch (err) {
    console.error(err);
    if (err.message.includes('Invalid token')) {
      return res.status(401).json({ message: '유효하지 않은 Google 토큰입니다.' });
    }
    res.status(500).json({ message: 'Google 로그인 처리 중 서버 오류' });
  }
});

// ---------------------------------
// 🔐 3. 인증 미들웨어
// ---------------------------------
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (token == null) {
    // ⭐️ 응답을 보내고 반드시 함수를 종료(return)해야 합니다.
    return res.sendStatus(401); // 401 Unauthorized
  }

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      // ⭐️ 응답을 보내고 반드시 함수를 종료(return)해야 합니다.
      return res.sendStatus(403); // 403 Forbidden
    }
    
    // 성공 시에는 next()를 호출하고 함수를 종료합니다.
    req.user = user;
    next();
  });
};

// ---------------------------------
// 👤 4. 사용자 API (프로필)
// ---------------------------------
// (hidden_users 테이블이 있다는 가정 하에 원본 유지)
app.get('/users/me', authenticateToken, async (req, res) => {
  try {
    const userId = req.user.userId;
    const userResult = await db.query('SELECT * FROM users WHERE id = $1', [userId]);
    const user = userResult.rows[0];

    if (user) {
        res.json(user);
    } else {
        res.status(404).json({ message: '사용자를 찾을 수 없습니다.' });
    }
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: '서버 오류' });
  }
});

// ⭐️ [수정] PUT /users/me (프로필 수정 - 생년월일 추가)
app.put('/users/me', authenticateToken, async (req, res) => {
  const userId = req.user.userId;
  // birthDate 추가됨
  const { displayName, preferredSport, birthDate } = req.body;

  try {
    // birth_date 컬럼 업데이트 추가
    const result = await db.query(
      `UPDATE users 
       SET display_name = $1, preferred_sport = $2, birth_date = $3 
       WHERE id = $4 
       RETURNING *`,
      [displayName, preferredSport, birthDate, userId]
    );
    res.json(result.rows[0]);
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: '프로필 업데이트 실패' });
  }
});

// ⭐️ [보강] POST /users/leave (회원 탈퇴 - 게시글 및 연관 데이터 완벽 삭제)
app.post('/users/leave', authenticateToken, async (req, res) => {
    const userId = req.user.userId;
    const client = await db.getClient();

    try {
        await client.query('BEGIN');

        // 1. 내가 '참여'한 기록 삭제 (남의 글에서 나를 지움)
        await client.query('DELETE FROM post_members WHERE user_id = $1', [userId]);
        
        // 2. 내가 '작성'한 게시글에 달린 다른 사람들의 참여 기록 삭제
        // (이걸 먼저 안 지우면 게시글 삭제 시 에러 남)
        await client.query(`
            DELETE FROM post_members 
            WHERE post_id IN (SELECT id FROM posts WHERE user_id = $1)
        `, [userId]);

        // 3. 내가 '작성'한 게시글 삭제
        await client.query('DELETE FROM posts WHERE user_id = $1', [userId]);

        // 4. 기타 정보 삭제 (채팅 참여, 메시지, 숨김 친구 등)
        await client.query('DELETE FROM participants WHERE user_id = $1', [userId]);
        await client.query('DELETE FROM messages WHERE sender_id = $1', [userId]);
        await client.query('DELETE FROM hidden_users WHERE hider_id = $1 OR hidden_id = $1', [userId]);

        // 5. 최종적으로 사용자 삭제
        await client.query('DELETE FROM users WHERE id = $1', [userId]);

        await client.query('COMMIT');
        console.log(`✅ 사용자(ID: ${userId}) 탈퇴 및 데이터 삭제 완료`);
        res.sendStatus(200);

    } catch (err) {
        await client.query('ROLLBACK');
        console.error('❌ 회원 탈퇴 치명적 오류:', err); // 서버 터미널에서 이 로그를 꼭 확인하세요!
        res.status(500).json({ message: '회원 탈퇴 실패', error: err.toString() });
    } finally {
        client.release();
    }
});

// GET /users (다른 사용자 목록 - '나'와 '숨긴' 사용자 제외)
// (hidden_users 테이블이 있다는 가정 하에 원본 유지)
app.get('/users', authenticateToken, async (req, res) => {
    const userId = req.user.userId;
    try {
        const query = `
            SELECT * FROM users WHERE id != $1;
        `;
        const result = await db.query(query, [userId]);
        res.json(result.rows);
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: '사용자 목록 로드 실패. DB 스키마를 확인하세요.' });
    }
});

// POST /users/hide (사용자 숨기기 API)
// (hidden_users 테이블이 있다는 가정 하에 원본 유지)
// ⭐️ 제공된 DB 스키마에 hidden_users 테이블이 없으므로 주석 처리합니다.
// ⭐️ 필요 시 테이블 생성 후 주석을 해제하여 사용하세요.
// app.post('/users/hide', authenticateToken, async (req, res) => {
//   const hiderId = req.user.userId;
//   const { userId: hiddenId } = req.body;
//   try {
//     await db.query('INSERT INTO hidden_users (hider_id, hidden_id) VALUES ($1, $2)', [hiderId, hiddenId]);
//     res.sendStatus(201);
//   } catch (err) {
//     console.error(err);
//     res.status(500).json({ message: '사용자 숨기기 실패' });
//   }
// });


// ---------------------------------
// 💬 5. 채팅방 API (⭐️ DB 트랜잭션 최적화 - File 2)
// (chat_rooms, participants 테이블이 있다는 가정 하에 원본 유지)
// ---------------------------------
// GET /rooms (채팅방 목록)
app.get('/rooms', authenticateToken, async (req, res) => {
  const userId = req.user.userId;
  try {
    const query = `
      SELECT 
        cr.id, 
        cr.last_message, 
        cr.last_message_timestamp,
        p.unread_count AS "my_unread_count", 
        p.left_at, 
        CASE 
          WHEN cr.room_name IS NULL THEN 
            (SELECT u.display_name FROM participants p_inner 
             JOIN users u ON u.id = p_inner.user_id
             WHERE p_inner.chat_room_id = cr.id AND p_inner.user_id != $1)
          ELSE cr.room_name
        END AS "room_name"
      FROM chat_rooms cr
      JOIN participants p ON cr.id = p.chat_room_id
      WHERE p.user_id = $1 AND p.is_hidden = FALSE 
      ORDER BY cr.last_message_timestamp DESC;
    `;
    const result = await db.query(query, [userId]);
    res.json(result.rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: '채팅방 로드 오류' });
  }
});

// POST /rooms (새 채팅방 생성 - ⭐️ File 2 트랜잭션)
app.post('/rooms', authenticateToken, async (req, res) => {
  const { userIds, roomName } = req.body; 
  const creatorId = req.user.userId; 

  const allParticipantIds = [creatorId, ...userIds];
  
  const client = await db.getClient(); // ⭐️ File 2
  try {
    await client.query('BEGIN'); // ⭐️ File 2

    const roomResult = await client.query( // ⭐️ File 2
      'INSERT INTO chat_rooms (room_name, last_message, last_message_timestamp) VALUES ($1, $2, NOW()) RETURNING id',
      [roomName, '채팅방이 생성되었습니다.']
    );
    const newChatRoomId = roomResult.rows[0].id;

    const participantPromises = allParticipantIds.map(userId => {
      return client.query( // ⭐️ File 2
        'INSERT INTO participants (chat_room_id, user_id, unread_count, is_hidden, left_at) VALUES ($1, $2, $3, $4, $5)',
        [newChatRoomId, userId, 0, false, null] 
      );
    });
    
    await Promise.all(participantPromises);

    await client.query('COMMIT'); // ⭐️ File 2

    res.status(201).json({ id: newChatRoomId });

  } catch (err) {
    await client.query('ROLLBACK'); // ⭐️ File 2
    console.error(err);
    res.status(500).json({ message: '채팅방 생성 실패' });
  } finally {
    client.release(); // ⭐️ File 2
  }
});

// GET /rooms/:roomId/messages (특정 방의 메시지 목록)
app.get('/rooms/:roomId/messages', authenticateToken, async (req, res) => {
    const { roomId } = req.params;
    const userId = req.user.userId;
    const { leftAt } = req.query; 

    try {
        const partCheck = await db.query(
            'SELECT * FROM participants WHERE chat_room_id = $1 AND user_id = $2',
            [roomId, userId]
        );
        if (partCheck.rows.length === 0) {
            return res.status(403).json({ message: '권한이 없습니다.' });
        }

        let query = 'SELECT m.* FROM messages m WHERE m.chat_room_id = $1';
        let params = [roomId];
        
        if (leftAt) {
            query += ' AND m.created_at > $2';
            params.push(leftAt);
        }
        
        query += ' ORDER BY m.created_at DESC LIMIT 50'; 

        const result = await db.query(query, params);
        res.json(result.rows);

    } catch (err) {
        console.error(err);
        res.status(500).json({ message: '메시지 로드 실패' });
    }
});


// POST /rooms/:roomId/messages (메시지 전송 - ⭐️ File 2 트랜잭션)
app.post('/rooms/:roomId/messages', authenticateToken, async (req, res) => {
  const { text } = req.body;
  const { roomId } = req.params;
  const senderId = req.user.userId;

  const client = await db.getClient(); // ⭐️ File 2
  try {
    await client.query('BEGIN'); // ⭐️ File 2

    // 1. messages 테이블에 메시지 삽입
    const messageResult = await client.query( // ⭐️ File 2
      'INSERT INTO messages (chat_room_id, sender_id, text) VALUES ($1, $2, $3) RETURNING *',
      [roomId, senderId, text]
    );
    const newMessage = messageResult.rows[0];

    // 2. chat_rooms 테이블의 마지막 메시지 업데이트
    await client.query( // ⭐️ File 2
      'UPDATE chat_rooms SET last_message = $1, last_message_timestamp = $2 WHERE id = $3',
      [text, newMessage.created_at, roomId]
    );

    // 3. participants 테이블의 안읽음 카운트 업데이트
    await client.query( // ⭐️ File 2
      `UPDATE participants SET 
         unread_count = CASE 
           WHEN user_id = $1 THEN 0 
           ELSE unread_count + 1 
         END,
         is_hidden = FALSE, 
         left_at = NULL     
       WHERE chat_room_id = $2`,
      [senderId, roomId]
    );
    
    await client.query('COMMIT'); // ⭐️ File 2

    // (핵심) WebSocket으로 이 방에 연결된 모든 클라이언트에게 새 메시지 전송
    broadcastMessage(roomId, newMessage);

    res.status(201).json(newMessage);
  } catch (err) {
    await client.query('ROLLBACK'); // ⭐️ File 2
    console.error(err);
    res.status(500).json({ message: '메시지 전송 오류' });
  } finally {
    client.release(); // ⭐️ File 2
  }
});

// POST /rooms/:roomId/read (안읽음 0 처리 API)
app.post('/rooms/:roomId/read', authenticateToken, async (req, res) => {
  const { roomId } = req.params;
  const userId = req.user.userId;
  try {
    await db.query(
      'UPDATE participants SET unread_count = 0 WHERE chat_room_id = $1 AND user_id = $2',
      [roomId, userId]
    );
    res.sendStatus(200);
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: '읽음 처리 실패' });
  }
});

// POST /rooms/:roomId/hide (채팅방 '영구' 나가기/숨기기 API)
app.post('/rooms/:roomId/hide', authenticateToken, async (req, res) => {
  const { roomId } = req.params;
  const userId = req.user.userId;
  try {
    await db.query(
      'UPDATE participants SET is_hidden = TRUE, left_at = NOW() WHERE chat_room_id = $1 AND user_id = $2',
      [roomId, userId]
    );
    res.sendStatus(200);
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: '채팅방 숨기기 실패' });
  }
});

// ---------------------------------
// 🏃‍♂️ 6. [신규] 포스트 API (⭐️ Real API - File 2)
// (DB 스키마가 일치한다고 가정)
// ---------------------------------
// GET /posts
app.get('/posts', authenticateToken, async (req, res) => {
    try {
        const query = `
            SELECT 
                p.id, p.title, p.content, p.exercise_type, p.max_players, 
                p.status, p.exercise_datetime, p.chat_room_id,
                u.display_name AS author_name,
                l.location_name,
                (SELECT COUNT(*) FROM post_members pm WHERE pm.post_id = p.id) AS current_players
            FROM posts p
            JOIN users u ON p.user_id = u.id
            LEFT JOIN locations l ON p.location_id = l.id
            WHERE p.status = 'RECRUITING'
            ORDER BY p.created_at DESC;
        `;
        const result = await db.query(query);
        res.json(result.rows);
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: '게시물 로드 실패. DB 스키마(posts, locations, post_members)를 확인하세요.' });
    }
});

// POST /posts
app.post('/posts', authenticateToken, async (req, res) => {
  const { 
    title, 
    content, 
    exercise_type,   
    max_players, 
    location_name,   
    exercise_datetime 
  } = req.body;

  const userId = req.user.userId;

  if (!title || !exercise_type) {
    console.log("❌ 필수 데이터 누락됨");
    return res.status(400).json({ message: '필수 정보가 누락되었습니다.' });
  }

  const client = await db.getClient();
  try {
    await client.query('BEGIN');

    // -------------------------------------------------------
    // ⭐️ 3. [핵심] 장소 ID 자동 처리 로직 (Clean DB 유지 비결)
    // -------------------------------------------------------
    let finalLocationId;
    
    // A. 이름으로 이미 존재하는 장소인지 확인
    const locCheck = await client.query(
      'SELECT id FROM locations WHERE location_name = $1', 
      [location_name]
    );

    if (locCheck.rows.length > 0) {
      // B. 이미 있으면 그 ID 사용
      finalLocationId = locCheck.rows[0].id;
    } else {
      // C. 없으면 "새로 만들어서" ID 생성 (좌표는 임시로 0,0 처리)
      // 만약 DB의 locations 테이블에 latitude, longitude가 NOT NULL이라면 0.0이라도 넣어야 함
      const newLoc = await client.query(
        `INSERT INTO locations (location_name, latitude, longitude, address) 
         VALUES ($1, 0.0, 0.0, $1) 
         RETURNING id`,
        [location_name]
      );
      finalLocationId = newLoc.rows[0].id;
    }
    // -------------------------------------------------------

    // 채팅방 생성
    const roomName = `[${exercise_type}] ${title}`;
    const roomResult = await client.query(
      'INSERT INTO chat_rooms (room_name, last_message, last_message_timestamp) VALUES ($1, $2, NOW()) RETURNING id',
      [roomName, '운동 로비가 생성되었습니다.']
    );
    const newChatRoomId = roomResult.rows[0].id;

    // 게시글 생성 (자동으로 구한 finalLocationId 사용)
    const postResult = await client.query(
        `INSERT INTO posts (user_id, title, content, exercise_type, max_players, location_id, exercise_datetime, chat_room_id, status)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, 'RECRUITING')
         RETURNING *`,
        [userId, title, content, exercise_type, max_players, finalLocationId, exercise_datetime, newChatRoomId]
    );
    const newPost = postResult.rows[0];

    await client.query(
        'INSERT INTO participants (chat_room_id, user_id) VALUES ($1, $2)',
        [newChatRoomId, userId]
    );
    await client.query(
        'INSERT INTO post_members (post_id, user_id) VALUES ($1, $2)',
        [newPost.id, userId]
    );

    await client.query('COMMIT');
    res.status(201).json(newPost);

  } catch (err) {
    await client.query('ROLLBACK');
    console.error("게시물 생성 에러:", err);
    res.status(500).json({ message: '게시물 생성 실패', error: err.toString() });
  } finally {
    client.release();
  }
});

// POST /posts/:postId/join
app.post('/posts/:postId/join', authenticateToken, async (req, res) => {
    const { postId } = req.params;
    const userId = req.user.userId;
    const client = await db.getClient();
    try {
        await client.query('BEGIN');
        const postResult = await client.query(
            `SELECT p.chat_room_id, p.max_players, 
              (SELECT COUNT(*) FROM post_members pm WHERE pm.post_id = p.id) AS current_players
             FROM posts p WHERE p.id = $1`,
            [postId]
        );
        if (postResult.rows.length === 0) { throw new Error('게시물을 찾을 수 없습니다.'); }
        const post = postResult.rows[0];
        const { chat_room_id, max_players, current_players } = post;
        
        // ⭐️ COUNT(*)는 문자열(string)로 반환될 수 있으므로, 숫자로 변환하여 비교
        if (parseInt(current_players, 10) >= parseInt(max_players, 10)) { 
            throw new Error('인원이 가득 찼습니다.'); 
        }
        
        const memberCheck = await client.query(
            'SELECT * FROM post_members WHERE post_id = $1 AND user_id = $2',
            [postId, userId]
        );
        if (memberCheck.rows.length === 0) {
            await client.query(
                'INSERT INTO post_members (post_id, user_id) VALUES ($1, $2)',
                [postId, userId]
            );
            await client.query(
                'INSERT INTO participants (chat_room_id, user_id) VALUES ($1, $2) ON CONFLICT DO NOTHING',
                [chat_room_id, userId]
            );
        }
        await client.query('COMMIT');
        res.status(200).json({ 
            message: '참가 완료', 
            chatRoomId: chat_room_id 
        });
    } catch (err) {
        await client.query('ROLLBACK');
        console.error(err);
        res.status(500).json({ message: err.message || '참가 실패' });
    } finally {
        client.release();
    }
});

// ---------------------------------
// 🗺️ 7. [신규] 맵 API (⭐️ Real API / GeoJSON - File 2)
// (locations 테이블을 사용하도록 통일)
// ---------------------------------
app.get('/facilities', authenticateToken, async (req, res)=>{
  const {minLat, minLng, maxLat, maxLng, zoom} = req.query;

  if (!minLat || !minLng || !maxLat || !maxLng || zoom === undefined){
    console.log('[DEBUG 필수 쿼리 파라미터 누락');
    return res.status(400).json({message: '지도 경계값을 찾을 수 없음'});
  }

  const zoomLevel = parseInt(zoom,10);
  let cellSize;

  // 줌 레벨에 따른 클러스터링 셀 크기 조절
  if (zoomLevel < 10){
    cellSize = 0.05;
  } else if (zoomLevel < 15){
    cellSize = 0.01;
  } else {
    cellSize = 0.002;
  }
  
  try{
    // ⭐️ 수정: 'facilities_for_map' 대신 'locations' 테이블 사용 (posts API와 통일)
    const sql = `
      SELECT "시설명", "시설유형명", "시설위도", "시설경도",
      "시설상태값',"도로명우편주소","주소","시설주소2명",
      "시설전화번호","시설홈페이지URL","담당자전화번호","실내외구분명",
      "준공일자",
      FROM public.facilities_for_map 
      WHERE ST_Contains(
        ST_MakeEnvelope($1, $2, $3, $4, 4326), 
        geom 
      )
      LIMIT 5000; 
    `;
    
    const params = [
      parseFloat(minLng),
      parseFloat(minLat),
      parseFloat(maxLng),
      parseFloat(maxLat),
    ];
    
    const result = await db.query(sql, params);
    const allFacilitiesInView = result.rows;

    // 2. 조회된 시설들을 그리드 기반으로 클러스터링
    const clusters = {};

    for (const facility of allFacilitiesInView){
      // ⭐️ 'locations' 스키마에 맞게 컬럼명 수정
      const lat = parseFloat(facility.시설위도);
      const lng = parseFloat(facility.시설경도);

      const gridLat = Math.floor(lat / cellSize) * cellSize;
      const gridLng = Math.floor(lng / cellSize) * cellSize;
      const gridKey = `${gridLat.toFixed(5)}-${gridLng.toFixed(5)}`;

      if (!clusters[gridKey]){
        clusters[gridKey] = [];
      }
      clusters[gridKey].push(facility);
    }

    // 3. 클라이언트가 렌더링할 수 있는 'ClusterableItem' 형식으로 변환
    const clusterableItems = [];
    const clusterThreshold = 10; // 100개 이상 모이면 클러스터로 표시

    for(const gridKey in clusters){
      const facilitiesInCell = clusters[gridKey];

      if(facilitiesInCell.length >= clusterThreshold && zoomLevel < 17) {
        // 클러스터로 묶기
        // ⭐️ 'locations' 스키마에 맞게 컬럼명 수정
        const avgLat = facilitiesInCell.reduce((sum,f) => sum + parseFloat(f.시설위도), 0) / facilitiesInCell.length;
        const avgLng = facilitiesInCell.reduce((sum,f) => sum + parseFloat(f.시설경도), 0) / facilitiesInCell.length;

        clusterableItems.push({
          location: {latitude: avgLat, longitude: avgLng},
          isCluster: true,
          count: facilitiesInCell.length,
          facility: null,
        });
      } else {
        // 개별 마커로 표시
        for(const facility of facilitiesInCell){
          clusterableItems.push({
            location: {latitude: parseFloat(facility.시설위도), longitude: parseFloat(facility.시설경도)},
            isCluster: false,
            facility: {
              시설명: facility.시설명,
              시설유형명: facility.시설유형명,
              시설위도: facility.시설위도,
              시설경도: facility.시설경도,
              시설상태값: facility.시설상태값,
              도로명우편주소: facility.도로명우편주소,
              주소: facility.주소,
              시설주소2명: facility.시설주소2명,
              시설전화번호: facility.시설전화번호,
              시설홈페이지URL: facility.시설홈페이지URL,
              담당자전화번호: facility.담당자전화번호,
              실내외구분명: facility.실내외구분명,
              준공일자: facility.준공일자,
            },
            count: 1,
          });
        }
      }
    }
    res.json(clusterableItems);

  }catch(err){
    console.error(err);
    res.status(500).json({message: '시설 로드 실패'});
  }
});

// ---------------------------------
// ⚡️ 8. WebSocket 서버 설정
// ---------------------------------
const server = http.createServer(app); 
const wss = new WebSocket.Server({ server });
const clients = {}; 

wss.on('connection', (ws, req) => {
  const token = req.url.split('token=')[1];
  if (!token) {
    return ws.close(1008, '토큰이 필요합니다.');
  }

  let userId;
  try {
    const payload = jwt.verify(token, JWT_SECRET); 
    userId = payload.userId.toString(); 
    clients[userId] = ws; 
    console.log(`[WS] 클라이언트 연결됨: ${userId}`);
  } catch (err) {
    return ws.close(1008, '유효하지 않은 토큰');
  }

  ws.on('message', (message) => {
    console.log(`[WS] 수신: ${message}`);
  });

  ws.on('close', () => {
    delete clients[userId]; 
    console.log(`[WS] 클라이언트 연결 끊김: ${userId}`);
  });
});

// ---------------------------------
// ⭐️ 9. [핵심] WebSocket 브로드캐스트 (⭐️ 1-Query 최적화 - File 1)
// ---------------------------------
async function broadcastMessage(roomId, message) {
  try {
    // 1. ⭐️ 이 방에 속한 모든 참가자의 '최신' 채팅방 정보를 '한 번에' 조회 (File 1 방식)
    const roomQuery = `
      SELECT 
        cr.id, 
        cr.last_message, 
        cr.last_message_timestamp,
        p.user_id, -- ⭐️ 이벤트를 받을 사용자 ID
        p.unread_count AS "my_unread_count",
        p.left_at,
        CASE 
          WHEN cr.room_name IS NULL THEN 
            (SELECT u.display_name FROM participants p_inner 
             JOIN users u ON u.id = p_inner.user_id
             WHERE p_inner.chat_room_id = cr.id AND p_inner.user_id != p.user_id)
          ELSE cr.room_name
        END AS "room_name"
      FROM chat_rooms cr
      JOIN participants p ON cr.id = p.chat_room_id
      WHERE cr.id = $1;
    `;
    
    const result = await db.query(roomQuery, [roomId]);
    
    // 2. ⭐️ 'Message' 모델에 맞는 JSON 생성 (모든 수신자 공통)
    const messagePayload = JSON.stringify({
      type: 'newMessage', 
      payload: {
        id: message.id,
        chat_room_id: message.chat_room_id,
        sender_id: message.sender_id,
        text: message.text,
        created_at: message.created_at,
        unread_count: result.rows.filter(r => r.user_id.toString() !== message.sender_id.toString()).length, 
      }
    });

    // 3. ⭐️ 현재 접속 중인 유저에게 *각자*에 맞는 이벤트 전송
    for (const roomData of result.rows) {
      const uid = roomData.user_id.toString(); 
      const ws = clients[uid];

      if (ws && ws.readyState === WebSocket.OPEN) {
        
        // ⭐️ 이벤트 1: 새 메시지 전송 (ChatScreen용)
        ws.send(messagePayload);
        
        // ⭐️ 이벤트 2: 채팅방 목록 갱신 전송 (ChatListPage용)
        const roomUpdatePayload = JSON.stringify({
          type: 'roomUpdate',
          payload: {
            id: roomData.id.toString(), 
            room_name: roomData.room_name,
            last_message: roomData.last_message,
            last_message_timestamp: roomData.last_message_timestamp,
            my_unread_count: roomData.my_unread_count,
            left_at: roomData.left_at,
          }
        });
        ws.send(roomUpdatePayload);
      }
    }
  } catch (err) {
    console.error("WebSocket 브로드캐스트 오류:", err);
  }
}

// ---------------------------------
// 10. 서버 시작
// ---------------------------------
server.listen(PORT, () => {
  console.log(`Server (HTTP + WS) listening on port ${PORT}`);
});
