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
// 🏋️‍♀️ 5. 게시물(Post) 및 운동 모집 API
// ---------------------------------

/**
 * [GET] /posts
 * 전체 게시물 목록 조회
 * - 작성자 정보, 현재 참여 인원, 위치 이름 등을 조인하여 반환
 * - Dart 모델(Post.fromJson)과 필드명을 일치시켜야 함
 */
app.get('/posts', authenticateToken, async (req, res) => {
  try {
    // 💡 복잡한 정보를 한 번에 가져오기 위한 쿼리
    // 1. users 테이블 조인: 작성자 이름(author_name), 프로필(profile_image)
    // 2. locations 테이블 조인: 위치 이름(location_name)
    // 3. 서브쿼리: 현재 참여 인원 수 계산 (current_players)
    const query = `
      SELECT 
        p.id,
        p.exercise_type,
        p.title,
        p.content,
        p.max_players,
        p.view_count,
        p.chat_room_id,
        p.exercise_datetime,
        p.location_id,
        l.name AS location_name,
        u.display_name AS author_name,
        u.profile_image,
        (SELECT COUNT(*)::int FROM post_members pm WHERE pm.post_id = p.id) AS current_players
      FROM posts p
      JOIN users u ON p.user_id = u.id
      LEFT JOIN locations l ON p.location_id = l.id
      ORDER BY p.exercise_datetime ASC; 
    `;
    // 날짜순 정렬 (가장 임박한 운동이 위로 오게 하려면 ASC, 최신글 위주는 create_at DESC)

    const result = await db.query(query);
    res.json(result.rows);
  } catch (err) {
    console.error('게시물 목록 조회 실패:', err);
    res.status(500).json({ message: '게시물을 불러오지 못했습니다.' });
  }
});

/**
 * [POST] /posts
 * 새 게시물 작성
 * - 트랜잭션 필수: 채팅방 생성 -> 게시글 생성 -> 멤버 등록 -> 채팅 참여
 */
app.post('/posts', authenticateToken, async (req, res) => {
  const client = await db.getClient();
  const userId = req.user.userId;
  const { 
    exercise_type, 
    title, 
    content, 
    location_id, 
    max_players, 
    exercise_datetime 
  } = req.body;

  try {
    await client.query('BEGIN');

    // 1. 채팅방 생성 (게시글과 1:1 매핑)
    // chat_rooms 테이블에 name 컬럼이 있다면 제목을 넣거나 '운동 모임' 등으로 설정
    const chatRoomResult = await client.query(
      `INSERT INTO chat_rooms (created_at) VALUES (NOW()) RETURNING id`
    );
    const newChatRoomId = chatRoomResult.rows[0].id;

    // 2. 게시글 생성
    const insertPostQuery = `
      INSERT INTO posts (
        user_id, exercise_type, title, content, 
        location_id, max_players, exercise_datetime, 
        chat_room_id, view_count, created_at
      )
      VALUES ($1, $2, $3, $4, $5, $6, $7, $8, 0, NOW())
      RETURNING *
    `;
    const postResult = await client.query(insertPostQuery, [
      userId, exercise_type, title, content, 
      location_id, max_players, exercise_datetime, newChatRoomId
    ]);
    const newPost = postResult.rows[0];

    // 3. 작성자를 모임 멤버(post_members)로 등록
    await client.query(
      `INSERT INTO post_members (post_id, user_id, joined_at) VALUES ($1, $2, NOW())`,
      [newPost.id, userId]
    );

    // 4. 작성자를 채팅방 참여자(participants)로 등록
    // (사용자의 닉네임을 가져와서 chat_name으로 사용)
    const userRes = await client.query('SELECT display_name, profile_image FROM users WHERE id = $1', [userId]);
    const userProfile = userRes.rows[0];

    await client.query(
      `INSERT INTO participants (chat_room_id, user_id, chat_name, joined_at) 
       VALUES ($1, $2, $3, NOW())`,
      [newChatRoomId, userId, userProfile.display_name]
    );

    await client.query('COMMIT');

    // 5. 클라이언트에 반환할 데이터 구성 (GET /posts 와 포맷 통일)
    // location_name을 가져오기 위해 locations 테이블 조회 필요
    const locRes = await db.query('SELECT name FROM locations WHERE id = $1', [location_id]);
    const locationName = locRes.rows.length > 0 ? locRes.rows[0].name : '알 수 없는 위치';

    const responseData = {
      ...newPost,
      author_name: userProfile.display_name,
      profile_image: userProfile.profile_image,
      location_name: locationName,
      current_players: 1, // 작성자 1명
      max_players: max_players
    };

    res.status(201).json(responseData);

  } catch (err) {
    await client.query('ROLLBACK');
    console.error('게시물 작성 실패:', err);
    res.status(500).json({ message: '게시물 작성 중 오류가 발생했습니다.' });
  } finally {
    client.release();
  }
});

/**
 * [POST] /posts/:id/join
 * 게시물 참여하기 (Post Detail 화면의 '참여하기' 버튼)
 * - 인원 수 확인 -> post_members 추가 -> participants 추가 -> 시스템 메시지 전송
 */
app.post('/posts/:id/join', authenticateToken, async (req, res) => {
  const client = await db.getClient();
  const userId = req.user.userId;
  const postId = req.params.id;

  try {
    await client.query('BEGIN');

    // 1. 게시글 정보 및 현재 인원 확인 (Lock을 걸어 동시성 제어 권장 - FOR UPDATE)
    const postQuery = `
      SELECT p.*, 
        (SELECT COUNT(*)::int FROM post_members pm WHERE pm.post_id = p.id) as current_count
      FROM posts p 
      WHERE p.id = $1 
      FOR UPDATE
    `;
    const postRes = await client.query(postQuery, [postId]);
    
    if (postRes.rows.length === 0) {
      throw new Error('존재하지 않는 게시물입니다.');
    }

    const post = postRes.rows[0];

    // 2. 유효성 검사
    // 2-1. 이미 참여했는지 확인
    const checkMember = await client.query(
      'SELECT * FROM post_members WHERE post_id = $1 AND user_id = $2', 
      [postId, userId]
    );
    if (checkMember.rows.length > 0) {
      await client.query('ROLLBACK');
      return res.status(409).json({ message: '이미 참여 중인 모임입니다.' });
    }

    // 2-2. 정원 초과 확인
    if (post.current_count >= post.max_players) {
      await client.query('ROLLBACK');
      return res.status(409).json({ message: '모집 인원이 마감되었습니다.' });
    }

    // 3. 멤버 추가 (post_members)
    await client.query(
      `INSERT INTO post_members (post_id, user_id, joined_at) VALUES ($1, $2, NOW())`,
      [postId, userId]
    );

    // 4. 채팅방 참여 (participants)
    // 내 정보 가져오기
    const userRes = await client.query('SELECT display_name FROM users WHERE id = $1', [userId]);
    const myName = userRes.rows[0].display_name;

    // 채팅방에 이미 나갔다가 다시 들어오는 경우 고려 (INSERT ON CONFLICT or Check)
    // 여기서는 간단히 INSERT 시도하되, 기존에 있으면 UPDATE 처리 (숨김 해제 등) 로직이 필요할 수 있음
    // 간단하게 DELETE 후 INSERT 혹은 Upsert 로직 사용. 여기선 단순 INSERT
    
    // 혹시 chat_room_id가 null이면 에러
    if (!post.chat_room_id) throw new Error('채팅방이 연결되지 않은 게시물입니다.');

    // 기존 참여 기록 확인 (나갔던 유저일 수 있음)
    const checkPart = await client.query(
      'SELECT * FROM participants WHERE chat_room_id = $1 AND user_id = $2',
      [post.chat_room_id, userId]
    );

    if (checkPart.rows.length > 0) {
      // 나갔던 유저라면 다시 활성화
      await client.query(
        `UPDATE participants SET is_hidden = FALSE, joined_at = NOW() 
         WHERE chat_room_id = $1 AND user_id = $2`,
        [post.chat_room_id, userId]
      );
    } else {
      // 신규 참여
      await client.query(
        `INSERT INTO participants (chat_room_id, user_id, chat_name, joined_at) 
         VALUES ($1, $2, $3, NOW())`,
        [post.chat_room_id, userId, myName]
      );
    }

    // 5. 시스템 메시지 전송 ("OOO님이 참여하셨습니다")
    const sysMsg = `${myName}님이 모임에 참여하셨습니다.`;
    const msgResult = await client.query(
      `INSERT INTO messages (chat_room_id, sender_id, text, msg_type, created_at) 
       VALUES ($1, $2, $3, 'SYSTEM', NOW()) RETURNING *`,
      [post.chat_room_id, userId, sysMsg]
    );

    // 6. 채팅방 마지막 메시지 업데이트
    await client.query(
      'UPDATE chat_rooms SET last_message = $1, last_message_timestamp = NOW() WHERE id = $2',
      [sysMsg, post.chat_room_id]
    );

    await client.query('COMMIT');

    // 웹소켓 브로드캐스트 (채팅방에 있는 사람들에게 알림)
    // broadcastMessage(post.chat_room_id, msgResult.rows[0]); 

    res.json({ 
      message: '참여가 완료되었습니다.', 
      chatRoomId: post.chat_room_id 
    });

  } catch (err) {
    await client.query('ROLLBACK');
    console.error('모임 참여 실패:', err);
    res.status(500).json({ message: err.message || '참여 처리 중 오류가 발생했습니다.' });
  } finally {
    client.release();
  }
});

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

// ⭐️ [수정] GET /rooms/:roomId/messages (채팅 이름(chat_name) 반환)
app.get('/rooms/:roomId/messages', authenticateToken, async (req, res) => {
    const { roomId } = req.params;
    const userId = req.user.userId;

    try {
        // ... 권한 체크 (기존 동일) ...

        // 💡 조인해서 participants의 chat_name을 가져옵니다.
        // 메시지 보낸 사람의 당시 닉네임(익명N)을 보여주기 위함
        const result = await db.query(
            `SELECT m.*, p.chat_name, p.profile_image
             FROM messages m
             LEFT JOIN participants p ON m.chat_room_id = p.chat_room_id AND m.sender_id = p.user_id
             WHERE m.chat_room_id = $1
             ORDER BY m.created_at ASC LIMIT 100`,
            [roomId]
        );
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
// ⭐️ [수정] POST /posts (게시글 생성 - 익명 로직 추가)
app.post('/posts', authenticateToken, async (req, res) => {
  const { 
    title, content, exercise_type, max_players, location_name, exercise_datetime,
    is_anonymous // 💡 클라이언트에서 받음 (기본 true)
  } = req.body;

  const userId = req.user.userId;
  const userDisplayName = req.user.name; // JWT에서 꺼낸 이름

  if (!title || !exercise_type) {
    return res.status(400).json({ message: '필수 정보가 누락되었습니다.' });
  }

  const client = await db.getClient();
  try {
    await client.query('BEGIN');

    // -------------------------------------------------------
    // ⭐️ 3. [핵심] 장소 ID 자동 처리 로직 (Clean DB 유지 비결)
    // -------------------------------------------------------
    let finalLocationId;
    const locCheck = await client.query('SELECT id FROM locations WHERE location_name = $1', [location_name]);
    if (locCheck.rows.length > 0) { finalLocationId = locCheck.rows[0].id; } 
    else {
      const newLoc = await client.query('INSERT INTO locations (location_name, latitude, longitude, address) VALUES ($1, 0, 0, $1) RETURNING id', [location_name]);
      finalLocationId = newLoc.rows[0].id;
    }
    // -------------------------------------------------------

    // 1. 채팅방 생성
    const roomName = `[${exercise_type}] ${title}`;
    const roomResult = await client.query(
      'INSERT INTO chat_rooms (room_name, last_message, last_message_timestamp, is_group) VALUES ($1, $2, NOW(), TRUE) RETURNING id',
      [roomName, '운동 로비가 생성되었습니다.']
    );
    const newChatRoomId = roomResult.rows[0].id;

    // 2. 게시글 생성 (is_anonymous 추가)
    const postResult = await client.query(
        `INSERT INTO posts (user_id, title, content, exercise_type, max_players, location_id, exercise_datetime, chat_room_id, status, view_count, is_anonymous)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, 'RECRUITING', 0, $9)
         RETURNING *`,
        [userId, title, content, exercise_type, max_players, finalLocationId, exercise_datetime, newChatRoomId, is_anonymous]
    );
    const newPost = postResult.rows[0];

    // 3. 채팅방 참여자 등록 (방장 이름 설정)
    // 익명이면 '글쓴이', 아니면 실제 이름
    const leaderChatName = is_anonymous ? '글쓴이' : userDisplayName;

    await client.query(
        'INSERT INTO participants (chat_room_id, user_id, chat_name) VALUES ($1, $2, $3)',
        [newChatRoomId, userId, leaderChatName]
    );

    // 4. 게시글 멤버 등록
    await client.query(
        `INSERT INTO post_members (post_id, user_id, role, status) VALUES ($1, $2, 'LEADER', 'ACCEPTED')`,
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

// ⭐️ [수정] POST /posts/:postId/join (참여하기 - 익명 번호 부여)
app.post('/posts/:postId/join', authenticateToken, async (req, res) => {
    const { postId } = req.params;
    const userId = req.user.userId;
    const userDisplayName = req.user.name;

    const client = await db.getClient();
    try {
        await client.query('BEGIN');

        // 1. 게시글 정보 확인 (익명 여부 확인)
        const postResult = await client.query(
            `SELECT p.*, 
              (SELECT COUNT(*) FROM post_members pm WHERE pm.post_id = p.id) AS current_players
             FROM posts p WHERE p.id = $1 FOR UPDATE`,
            [postId]
        );

        if (postResult.rows.length === 0) throw new Error('게시물을 찾을 수 없습니다.');
        const post = postResult.rows[0];
        
        if (parseInt(post.current_players) >= post.max_players) {
            throw new Error('인원이 가득 찼습니다.');
        }

        // 2. 이미 참여했는지 확인
        const memberCheck = await client.query(
            'SELECT 1 FROM post_members WHERE post_id = $1 AND user_id = $2',
            [postId, userId]
        );

        if (memberCheck.rows.length === 0) {
            // 3. 멤버 추가
            await client.query(
                `INSERT INTO post_members (post_id, user_id, role, status) VALUES ($1, $2, 'MEMBER', 'ACCEPTED')`,
                [postId, userId]
            );
            
            // 4. 채팅방 참여 (이름 결정)
            let myChatName = userDisplayName;
            
            if (post.is_anonymous) {
                // 현재 채팅방 인원수 조회 -> 다음 번호 부여
                const countResult = await client.query(
                    'SELECT COUNT(*) FROM participants WHERE chat_room_id = $1',
                    [post.chat_room_id]
                );
                const nextNum = parseInt(countResult.rows[0].count) + 1; // 방장(1명) 있으니 2부터 시작하거나, 방장 포함 전체 수
                // 방장이 '글쓴이'고 나머지가 '익명1'부터 시작하길 원한다면:
                // 현재 1명(방장) -> 나는 '익명1'
                // 현재 2명 -> 나는 '익명2'
                myChatName = `익명${parseInt(countResult.rows[0].count)}`; 
            }

            await client.query(
                `INSERT INTO participants (chat_room_id, user_id, chat_name) VALUES ($1, $2, $3) ON CONFLICT DO NOTHING`,
                [post.chat_room_id, userId, myChatName]
            );
        }

        await client.query('COMMIT');
        res.json({ message: '참여 완료', chatRoomId: post.chat_room_id });
    } catch (err) {
        await client.query('ROLLBACK');
        console.error(err);
        res.status(500).json({ message: err.message || '참여 실패' });
    } finally {
        client.release();
    }
});

// ---------------------------------
// 🗺️ 7. 맵 API (시설 정보 조회)
// ---------------------------------
app.get('/facilities', authenticateToken, async (req, res)=>{
  const {minLat, minLng, maxLat, maxLng, zoom} = req.query;

  if (!minLat || !minLng || !maxLat || !maxLng || zoom === undefined){
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
    // ⭐️ [수정] 쉼표(,) 오타를 완벽하게 제거한 쿼리
    // "준공일자" 뒤에 쉼표가 없어야 합니다!
    console.log("=== [DEBUG] 콤마 삭제한 버전 실행 중 ===");
    const sql = `
      SELECT "시설명", "시설유형명", "시설위도", "시설경도",
      "시설상태값", "도로명우편번호", "주소", "시설주소2명",
      "시설전화번호", "시설홈페이지URL", "담당자전화번호", "실내외구분명",
      "준공일자" 
      FROM facilities_for_map 
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
      // DB 컬럼이 한글이므로 한글 Key로 접근
      const lat = parseFloat(facility.시설위도);
      const lng = parseFloat(facility.시설경도);

      if (isNaN(lat) || isNaN(lng)) continue; // 좌표 오류 시 건너뜀

      const gridLat = Math.floor(lat / cellSize) * cellSize;
      const gridLng = Math.floor(lng / cellSize) * cellSize;
      const gridKey = `${gridLat.toFixed(5)}-${gridLng.toFixed(5)}`;

      if (!clusters[gridKey]){
        clusters[gridKey] = [];
      }
      clusters[gridKey].push(facility);
    }

    // 3. 클라이언트 포맷(ClusterableItem)으로 변환
    const clusterableItems = [];
    const clusterThreshold = 5; // 5개 이상이면 묶음

    for(const gridKey in clusters){
      const facilitiesInCell = clusters[gridKey];

      if(facilitiesInCell.length >= clusterThreshold && zoomLevel < 17) {
        // [클러스터 생성]
        const avgLat = facilitiesInCell.reduce((sum,f) => sum + parseFloat(f.시설위도), 0) / facilitiesInCell.length;
        const avgLng = facilitiesInCell.reduce((sum,f) => sum + parseFloat(f.시설경도), 0) / facilitiesInCell.length;

        clusterableItems.push({
          location: {latitude: avgLat, longitude: avgLng},
          isCluster: true,
          count: facilitiesInCell.length,
          facility: null,
        });
      } else {
        // [개별 마커 생성]
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
              도로명우편번호: facility.도로명우편번호,
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

  } catch(err){
    console.error(err);
    res.status(500).json({message: '시설 로드 실패', error: err.toString()});
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
