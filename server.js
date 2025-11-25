// server.js ⭐️ Google 인증 + DB 트랜잭션 + Real API 융합본)
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

// ⭐️ [수정] POST /rooms/:roomId/leave (방장이 나가면 게시글 삭제)
app.post('/rooms/:roomId/leave', authenticateToken, async (req, res) => {
  const { roomId } = req.params;
  const userId = req.user.userId;

  const client = await db.getClient();
  try {
    await client.query('BEGIN');

    // 1. 이 방과 연결된 게시글이 있고, 내가 그 게시글의 작성자(LEADER)인지 확인
    const postCheck = await client.query(
        `SELECT id FROM posts WHERE chat_room_id = $1 AND user_id = $2`,
        [roomId, userId]
    );

    // 🚨 [CASE 1] 내가 방장이다 -> 게시글 폭파 (삭제)
    if (postCheck.rows.length > 0) {
        const postId = postCheck.rows[0].id;
        console.log(`🚨 방장(${userId})이 나감 -> 게시글(${postId}) 및 채팅방 폭파`);

        // 연관 데이터 삭제 순서: 멤버 -> 게시글 -> 메시지 -> 참가자 -> 채팅방
        await client.query('DELETE FROM post_members WHERE post_id = $1', [postId]);
        await client.query('DELETE FROM posts WHERE id = $1', [postId]);
        await client.query('DELETE FROM messages WHERE chat_room_id = $1', [roomId]);
        await client.query('DELETE FROM participants WHERE chat_room_id = $1', [roomId]);
        await client.query('DELETE FROM chat_rooms WHERE id = $1', [roomId]);
    } 
    // 💨 [CASE 2] 일반 멤버다 -> 그냥 나가기 (숨김 처리)
    else {
        // 내 채팅 이름 가져오기
        const partResult = await client.query(
            'SELECT chat_name FROM participants WHERE chat_room_id = $1 AND user_id = $2',
            [roomId, userId]
        );
        const myName = partResult.rows.length > 0 ? partResult.rows[0].chat_name : '알 수 없음';

        // 모임 멤버에서 삭제
        await client.query(`
            DELETE FROM post_members 
            WHERE user_id = $1 AND post_id = (SELECT id FROM posts WHERE chat_room_id = $2)
        `, [userId, roomId]);

        // 채팅방 숨김 처리
        await client.query(
            'UPDATE participants SET is_hidden = TRUE, left_at = NOW() WHERE chat_room_id = $1 AND user_id = $2',
            [roomId, userId]
        );

        // 시스템 메시지 전송
        const sysMsg = `${myName}님이 모임에서 나갔습니다.`;
        const msgResult = await client.query(
            `INSERT INTO messages (chat_room_id, sender_id, text, msg_type) 
             VALUES ($1, $2, $3, 'SYSTEM') RETURNING *`,
            [roomId, userId, sysMsg]
        );
        
        // 소켓 전송
        broadcastMessage(roomId, msgResult.rows[0]);
    }

    await client.query('COMMIT');
    res.sendStatus(200);
  } catch (err) {
    await client.query('ROLLBACK');
    console.error(err);
    res.status(500).json({ message: '방 나가기 실패' });
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
        
        -- ⭐️ [추가] 채팅방 인원수 계산 (나가지 않은 사람만 카운트)
        (SELECT COUNT(*) FROM participants p2 WHERE p2.chat_room_id = cr.id AND p2.is_hidden = FALSE)::int AS "user_count",

        CASE 
          WHEN cr.room_name IS NULL THEN 
            (SELECT u.display_name FROM participants p_inner 
             JOIN users u ON u.id = p_inner.user_id
             WHERE p_inner.chat_room_id = cr.id AND p_inner.user_id != $1 LIMIT 1)
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

app.get('/rooms/:roomId/messages', authenticateToken, async (req, res) => {
    const { roomId } = req.params;
    const userId = req.user.userId;
    const { leftAt } = req.query; 

    console.log(`\n🔍 [DEBUG] 메시지 로드 요청 시작 (방: ${roomId})`);

    try {
        // 1. 권한 체크 (참여자 명단에 있는지)
        const partCheck = await db.query(
            'SELECT 1 FROM participants WHERE chat_room_id = $1 AND user_id = $2',
            [roomId, userId]
        );
        
        if (partCheck.rows.length === 0) {
            return res.status(403).json({ message: '권한이 없습니다.' });
        }

        // 2. [추가됨] 내 입장 시간 확인 (post_members 테이블에서 joined_at 가져오기)
        // 게시글을 통해 들어온 경우, 가입한 시간 이전의 대화는 안 보이게 합니다.
        const joinTimeRes = await db.query(`
            SELECT pm.joined_at 
            FROM post_members pm
            JOIN posts p ON p.id = pm.post_id
            WHERE p.chat_room_id = $1 AND pm.user_id = $2
        `, [roomId, userId]);

        // 기본값: 1970년 (모든 메시지 다 보임 - 일반 채팅방 등)
        let filterDate = new Date(0); 
        
        // 게시글 채팅방 멤버라면, 가입 시간(joined_at)으로 필터링 날짜 설정
        if (joinTimeRes.rows.length > 0) {
            filterDate = new Date(joinTimeRes.rows[0].joined_at);
            console.log(`🕒 [DEBUG] 필터링: ${filterDate.toISOString()} 이후 메시지만 표시`);
        }

        // 3. 쿼리 생성
        // 조건: (채팅방 ID 일치) AND (작성시간 >= 내 입장시간)
        let query = `
            SELECT m.*, p.chat_name, u.profile_image
            FROM messages m
            LEFT JOIN participants p ON m.chat_room_id = p.chat_room_id AND m.sender_id = p.user_id
            LEFT JOIN users u ON m.sender_id = u.id
            WHERE m.chat_room_id = $1 AND m.created_at >= $2
        `;
        
        // 파라미터 배열: $1=roomId, $2=filterDate
        const params = [roomId, filterDate];

        // 4. 추가 조건: leftAt (클라이언트가 이미 로딩한 시점 이후만 가져오기 - 더보기 기능용)
        // 파라미터가 하나 추가되므로 $3이 됩니다.
        if (leftAt && leftAt !== 'null' && leftAt !== 'undefined') {
            query += ` AND m.created_at > $3`;
            params.push(leftAt);
        }

        query += ` ORDER BY m.created_at DESC LIMIT 100`;

        // 5. 실행
        const result = await db.query(query, params);
        console.log(`✅ [DEBUG] 메시지 ${result.rows.length}개 로드 성공`);
        
        res.json(result.rows);

    } catch (err) {
        console.error("❌ [DEBUG] 에러 발생:", err);
        res.status(500).json({ message: '메시지 로드 실패' });
    }
});

// ⭐️ [수정] POST /rooms/:roomId/messages (메시지 전송 + 안읽음 수 저장)
app.post('/rooms/:roomId/messages', authenticateToken, async (req, res) => {
  const { text } = req.body;
  const { roomId } = req.params;
  const senderId = req.user.userId;

  const client = await db.getClient();
  try {
    await client.query('BEGIN');

    // 1. 채팅방 인원수 확인 (나 빼고 몇 명인지)
    const countRes = await client.query(
        'SELECT COUNT(*) FROM participants WHERE chat_room_id = $1',
        [roomId]
    );
    // 전체 인원 - 1(나) = 안 읽은 사람 수
    // (만약 상대방이 현재 접속중이라도 일단 DB에는 카운트를 넣고, 클라이언트가 읽음 처리 API를 호출하며 깎습니다)
    let initialUnreadCount = parseInt(countRes.rows[0].count) - 1;
    if (initialUnreadCount < 0) initialUnreadCount = 0;

    // 2. messages 테이블에 저장 (unread_count 포함!)
    const messageResult = await client.query(
      `INSERT INTO messages (chat_room_id, sender_id, text, msg_type, unread_count) 
       VALUES ($1, $2, $3, 'TEXT', $4) 
       RETURNING *`,
      [roomId, senderId, text, initialUnreadCount]
    );
    const newMessage = messageResult.rows[0];

    // 3. 채팅방 갱신
    await client.query(
      'UPDATE chat_rooms SET last_message = $1, last_message_timestamp = $2 WHERE id = $3',
      [text, newMessage.created_at, roomId]
    );

    // 4. 안읽음 카운트 증가 (participants 테이블)
    // 내가 아닌 사람들의 unread_count를 +1
    await client.query(
      `UPDATE participants SET 
         unread_count = unread_count + 1,
         is_hidden = FALSE, 
         left_at = NULL     
       WHERE chat_room_id = $1 AND user_id != $2`,
      [roomId, senderId]
    );
    
    await client.query('COMMIT');

    // 5. 전송
    broadcastMessage(roomId, newMessage);

    res.status(201).json(newMessage);
  } catch (err) {
    await client.query('ROLLBACK');
    console.error(err);
    res.status(500).json({ message: '메시지 전송 오류' });
  } finally {
    client.release();
  }
});

// ⭐️ [수정] POST /rooms/:roomId/read (읽음 처리 + 숫자 깎기 + 알림 방송)
app.post('/rooms/:roomId/read', authenticateToken, async (req, res) => {
  const { roomId } = req.params;
  const userId = req.user.userId;

  const client = await db.getClient();
  try {
    await client.query('BEGIN');

    // 1. 내가 안 읽은 메시지가 있는지 확인 (내 unread_count 확인)
    const myStatus = await client.query(
        'SELECT unread_count FROM participants WHERE chat_room_id = $1 AND user_id = $2',
        [roomId, userId]
    );

    // 내가 읽을 게 있었다면 -> 메시지들의 카운트를 깎는다.
    if (myStatus.rows.length > 0 && myStatus.rows[0].unread_count > 0) {
        // 이 방의 모든 메시지 중, 안읽음 숫자가 0보다 큰 것들을 -1 해줌
        // (정교하게 하려면 내가 안 읽은 시점 이후것만 해야 하지만, "입장=모두읽음" 룰 적용)
        await client.query(
            `UPDATE messages 
             SET unread_count = unread_count - 1 
             WHERE chat_room_id = $1 AND unread_count > 0`,
            [roomId]
        );
    }

    // 2. 내 상태를 '모두 읽음(0)'으로 변경
    await client.query(
      'UPDATE participants SET unread_count = 0 WHERE chat_room_id = $1 AND user_id = $2',
      [roomId, userId]
    );

    await client.query('COMMIT');

    // ⭐️ 3. [핵심] "누군가 읽었습니다"라고 방 사람들에게 방송
    // (이걸 받아야 상대방 폰에서 숫자가 줄어듭니다)
    const readPayload = JSON.stringify({
        type: 'roomRead',
        payload: { chatRoomId: roomId }
    });

    // 접속 중인 방 멤버들에게 전송
    const members = await db.query('SELECT user_id FROM participants WHERE chat_room_id = $1', [roomId]);
    for (const m of members.rows) {
        const ws = clients[m.user_id];
        if (ws && ws.readyState === WebSocket.OPEN) {
            ws.send(readPayload);
        }
    }

    res.sendStatus(200);
  } catch (err) {
    await client.query('ROLLBACK');
    console.error(err);
    res.status(500).json({ message: '읽음 처리 실패' });
  } finally {
    client.release();
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

                p.view_count,
                
                p.user_id, -- ⭐️ [추가] 작성자 ID (익명 여부 상관없이 본인 확인용)

                CASE 
                    WHEN p.is_anonymous = TRUE THEN '익명'
                    ELSE u.display_name 
                END AS author_name,

                CASE 
                    WHEN p.is_anonymous = TRUE THEN NULL 
                    ELSE u.profile_image 
                END AS profile_image,

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
        res.status(500).json({ message: '게시물 로드 실패' });
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

    newPost.author_name = is_anonymous ? '익명' : userDisplayName;
    newPost.location_name = location_name; // (선택사항) 장소 이름도 바로 보여주려면 추가
    newPost.current_players = 1; // 방금 만들었으니 1명

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

// ⭐️ [수정] POST /posts/:postId/join (참여 + 시스템 메시지 + 히스토리 리셋)
app.post('/posts/:postId/join', authenticateToken, async (req, res) => {
    const { postId } = req.params;
    const userId = req.user.userId;
    const userDisplayName = req.user.name;

    const client = await db.getClient();
    try {
        await client.query('BEGIN');

        // 1. 게시글 정보 확인
        const postResult = await client.query(
            `SELECT p.*, 
              (SELECT COUNT(*) FROM post_members pm WHERE pm.post_id = p.id) AS current_players
             FROM posts p WHERE p.id = $1 FOR UPDATE`,
            [postId]
        );

        if (postResult.rows.length === 0) throw new Error('게시물을 찾을 수 없습니다.');
        const post = postResult.rows[0];
        
        if (parseInt(post.current_players) >= post.max_players) {
            // 이미 멤버라면 인원수 체크 통과
            const isMember = await client.query('SELECT 1 FROM post_members WHERE post_id=$1 AND user_id=$2', [postId, userId]);
            if (isMember.rows.length === 0) {
                throw new Error('인원이 가득 찼습니다.');
            }
        }

        // 2. 멤버 추가 (이미 존재하면 joined_at을 최신으로 갱신 -> 이전 채팅 안 보이게 하려고!)
        await client.query(
            `INSERT INTO post_members (post_id, user_id, role, status, joined_at) 
             VALUES ($1, $2, 'MEMBER', 'ACCEPTED', NOW()) 
             ON CONFLICT (post_id, user_id) 
             DO UPDATE SET joined_at = NOW(), status = 'ACCEPTED'`, 
            [postId, userId]
        );
        
        // 3. 채팅방 참여 이름 결정
        let myChatName = userDisplayName;
        if (post.is_anonymous) {
            // 내 이름이 이미 있는지 확인
            const existName = await client.query(
                'SELECT chat_name FROM participants WHERE chat_room_id = $1 AND user_id = $2',
                [post.chat_room_id, userId]
            );
            
            if (existName.rows.length > 0) {
                myChatName = existName.rows[0].chat_name;
            } else {
                // 없으면 새 번호 부여
                const countResult = await client.query(
                    'SELECT COUNT(*) FROM participants WHERE chat_room_id = $1',
                    [post.chat_room_id]
                );
                // 방장(1) + 멤버(n) = 다음 번호
                myChatName = `익명${parseInt(countResult.rows[0].count) + 1}`; 
            }
        }

        // 4. 채팅방 참여 (participants) - 숨김 해제
        const updateResult = await client.query(
            `UPDATE participants 
             SET is_hidden = FALSE, left_at = NULL 
             WHERE chat_room_id = $1 AND user_id = $2 
             RETURNING *`,
            [post.chat_room_id, userId]
        );

        if (updateResult.rowCount === 0) {
            await client.query(
                `INSERT INTO participants (chat_room_id, user_id, chat_name, is_hidden, left_at) 
                 VALUES ($1, $2, $3, FALSE, NULL)`,
                [post.chat_room_id, userId, myChatName]
            );
        }

        // ⭐️ 5. [추가] 시스템 메시지 전송 ("익명3님이 참여했습니다")
        // (단, 방금 막 들어온 경우에만 띄우는 게 좋지만, 여기선 재입장도 띄웁니다)
        const sysMsg = `${myChatName}님이 모임에 참여하였습니다.`;
        const msgResult = await client.query(
            `INSERT INTO messages (chat_room_id, sender_id, text, msg_type) 
             VALUES ($1, $2, $3, 'SYSTEM') RETURNING *`,
            [post.chat_room_id, userId, sysMsg]
        );

        await client.query('COMMIT');
        
        // 소켓 전송
        broadcastMessage(post.chat_room_id, msgResult.rows[0]);

        res.json({ message: '참여 완료', chatRoomId: post.chat_room_id });
    } catch (err) {
        await client.query('ROLLBACK');
        console.error(err);
        res.status(500).json({ message: err.message || '참여 실패' });
    } finally {
        client.release();
    }
});

// ⭐️ [수정] 조회수 증가 API (NULL 방지 + 로그 추가)
app.post('/posts/:id/view', async (req, res) => {
    const { id } = req.params;
    
    console.log(`👀 조회수 증가 요청 들어옴: Post ID ${id}`);

    try {
        // COALESCE(view_count, 0) -> 만약 값이 NULL이면 0으로 취급해서 +1 함
        const result = await db.query(
            `UPDATE posts 
             SET view_count = COALESCE(view_count, 0) + 1 
             WHERE id = $1 
             RETURNING view_count`, 
            [id]
        );

        if (result.rows.length > 0) {
            console.log(`✅ 조회수 업데이트 성공! 현재: ${result.rows[0].view_count}`);
            res.status(200).json({ views: result.rows[0].view_count });
        } else {
            console.log(`❌ 조회수 업데이트 실패: 게시글 ID(${id})를 찾을 수 없음`);
            res.status(404).json({ message: '게시글을 찾을 수 없습니다.' });
        }
    } catch (err) {
        console.error("❌ 조회수 에러:", err);
        res.status(500).json({ message: '서버 오류' });
    }
});

// ⭐️ [추가] 게시글 삭제 API (작성자만)
app.delete('/posts/:id', authenticateToken, async (req, res) => {
    const { id } = req.params;
    const userId = req.user.userId;
    const client = await db.getClient();

    try {
        await client.query('BEGIN');

        // 1. 본인 확인
        const check = await client.query('SELECT * FROM posts WHERE id = $1 AND user_id = $2', [id, userId]);
        if (check.rows.length === 0) {
            throw new Error('권한이 없거나 게시글이 없습니다.');
        }
        const chatRoomId = check.rows[0].chat_room_id;

        // 2. 연관 데이터 삭제 (순서 중요: 멤버 -> 게시글 -> 메시지 -> 참가자 -> 채팅방)
        await client.query('DELETE FROM post_members WHERE post_id = $1', [id]);
        await client.query('DELETE FROM posts WHERE id = $1', [id]); // 게시글 삭제
        
        // 채팅방도 삭제할까요? (보통 게시글 지우면 방도 폭파)
        if (chatRoomId) {
            await client.query('DELETE FROM messages WHERE chat_room_id = $1', [chatRoomId]);
            await client.query('DELETE FROM participants WHERE chat_room_id = $1', [chatRoomId]);
            await client.query('DELETE FROM chat_rooms WHERE id = $1', [chatRoomId]);
        }

        await client.query('COMMIT');
        res.sendStatus(200);
    } catch (err) {
        await client.query('ROLLBACK');
        console.error(err);
        res.status(500).json({ message: '삭제 실패' });
    } finally {
        client.release();
    }
});

// ⭐️ [수정] PUT /posts/:id (모든 내용 수정 가능)
app.put('/posts/:id', authenticateToken, async (req, res) => {
    const { id } = req.params;
    // 💡 수정 가능한 모든 필드 받기
    const { 
        title, content, exercise_type, max_players, 
        location_name, exercise_datetime, is_anonymous 
    } = req.body; 
    const userId = req.user.userId;

    const client = await db.getClient();
    try {
        await client.query('BEGIN');

        // 1. 장소 처리 (위치 이름이 바뀌었을 수 있으므로)
        let finalLocationId;
        if (location_name) {
            const locCheck = await client.query('SELECT id FROM locations WHERE location_name = $1', [location_name]);
            if (locCheck.rows.length > 0) { finalLocationId = locCheck.rows[0].id; } 
            else {
                const newLoc = await client.query('INSERT INTO locations (location_name, latitude, longitude, address) VALUES ($1, 0, 0, $1) RETURNING id', [location_name]);
                finalLocationId = newLoc.rows[0].id;
            }
        }

        // 2. 게시글 업데이트
        // (COALESCE를 사용하여 입력된 값만 수정하고, 없으면 기존 값 유지)
        const result = await client.query(
            `UPDATE posts 
             SET title = COALESCE($1, title), 
                 content = COALESCE($2, content),
                 exercise_type = COALESCE($3, exercise_type),
                 max_players = COALESCE($4, max_players),
                 location_id = COALESCE($5, location_id),
                 exercise_datetime = COALESCE($6, exercise_datetime),
                 is_anonymous = COALESCE($7, is_anonymous)
             WHERE id = $8 AND user_id = $9 
             RETURNING *`,
            [title, content, exercise_type, max_players, finalLocationId, exercise_datetime, is_anonymous, id, userId]
        );
        
        if (result.rows.length === 0) {
            throw new Error('수정 권한이 없거나 게시글이 없습니다.');
        }

        // 3. 채팅방 이름도 업데이트 (선택 사항: "[종목] 제목" 형식을 유지하려면)
        const post = result.rows[0];
        const newRoomName = `[${post.exercise_type}] ${post.title}`;
        await client.query('UPDATE chat_rooms SET room_name = $1 WHERE id = $2', [newRoomName, post.chat_room_id]);

        await client.query('COMMIT');
        res.json(post);
    } catch (err) {
        await client.query('ROLLBACK');
        console.error(err);
        res.status(500).json({ message: '수정 실패' });
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
    const sql = `
      SELECT "시설명", "시설유형명", "시설위도", "시설경도",
      "시설상태값", "도로명우편번호", "주소", "시설주소2명",
      "시설전화번호", "시설홈페이지URL", "담당자전화번호", "실내외구분명",
      "준공일자", "firstSports", "secondSports" 
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
              firstSports: facility.firstSports,
              secondSports: facility.secondSports
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

//----------------------
//운동 카테고리
//----------------------

app.get('/sports/categories', authenticateToken, async(req,res)=>{
  try{
    const sql = `
    SELECT category, json_agg(sport_name ORDER BY sport_name) as sports
    FROM sport_mapping
    GROUP BY category
    ORDER BY category;
  `;

  const resule = await db.query(sql);
  res.json(result.rows);
  }catch(err){
    console.error('[EROOR] /sports/categories 오류:',err);
    res.status(500).json({message: '카테고리 로드 실패'});
  }
});

// ---------------------------------
// ⚡️ 8. WebSocket 서버 설정 (⭐️ Heartbeat 추가)
// ---------------------------------
const server = http.createServer(app); 
const wss = new WebSocket.Server({ server });
const clients = {}; 

// ⭐️ 연결 유지(Heartbeat) 설정
function heartbeat() {
  this.isAlive = true;
}

wss.on('connection', (ws, req) => {
  const token = req.url.split('token=')[1];
  if (!token) return ws.close(1008, '토큰 없음');

  let userId;
  try {
    const payload = jwt.verify(token, JWT_SECRET); 
    userId = payload.userId.toString(); 
    
    clients[userId] = ws; 
    ws.isAlive = true; // ⭐️ 초기 생존 확인
    ws.on('pong', heartbeat); // ⭐️ 퐁 응답 시 생존 확인

    console.log(`[WS] 클라이언트 연결됨: ${userId}`);
  } catch (err) {
    return ws.close(1008, '유효하지 않은 토큰');
  }

  //실시간 매칭 용
  ws.on('message', async(message)=>{
    try{
      const data = JSON.parse(message);

      switch(data.type){
        case 'join_match':
          await handleJoinMatch(userId, data.payload);
          break;
        case 'cancle_match':
          await handleJoinMatch(userId);
          break;
      }
    }catch(e){
      console.error('소켓 메시지 처리 오류:',e);
    }
  });

  //

  ws.on('close', () => {
    if (userId) delete clients[userId]; 
    console.log(`[WS] 클라이언트 연결 끊김: ${userId}`);
  });
});

// ⭐️ 30초마다 연결 확인 (죽은 연결 정리)
const interval = setInterval(function ping() {
  wss.clients.forEach(function each(ws) {
    if (ws.isAlive === false) return ws.terminate();
    ws.isAlive = false;
    ws.ping(); // 클라이언트에게 'ping' 전송
  });
}, 30000);

wss.on('close', function close() {
  clearInterval(interval);
});

// ---------------------------------
// ⭐️ 9. [수정] WebSocket 브로드캐스트 (단순화 & 디버깅 강화 버전)
// ---------------------------------
async function broadcastMessage(roomId, message) {
  console.log(`📡 [WS] 브로드캐스트 시작 (방: ${roomId})`);

  try {
    // 1. 보낸 사람의 '이 방에서의 닉네임(익명N)' 찾기
    const senderRes = await db.query(
      'SELECT chat_name FROM participants WHERE chat_room_id = $1 AND user_id = $2',
      [roomId, message.sender_id]
    );
    const senderName = senderRes.rows.length > 0 ? senderRes.rows[0].chat_name : '알 수 없음';

    // 2. 이 방에 있는 '모든 참가자' 목록 가져오기
    const participantsRes = await db.query(
      'SELECT user_id, unread_count FROM participants WHERE chat_room_id = $1',
      [roomId]
    );
    const participants = participantsRes.rows;
    console.log(`👥 [WS] 전송 대상: 총 ${participants.length}명`);

    // 3. 방 정보 가져오기 (채팅방 목록 갱신용)
    const roomRes = await db.query(
      'SELECT room_name, last_message, last_message_timestamp FROM chat_rooms WHERE id = $1',
      [roomId]
    );
    const roomInfo = roomRes.rows[0];

    // 4. 각 참가자에게 전송
    for (const p of participants) {
      const targetUserId = p.user_id.toString();
      const ws = clients[targetUserId]; // 접속해 있는 소켓 찾기

      if (ws && ws.readyState === WebSocket.OPEN) {
        // A. 채팅방 안으로 쏘는 메시지 (newMessage)
        const messagePayload = JSON.stringify({
          type: 'newMessage',
          payload: {
            id: message.id,
            chat_room_id: message.chat_room_id,
            sender_id: message.sender_id,
            text: message.text,
            created_at: message.created_at,
            unread_count: message.unread_count, // (참고: 정확한 계산은 별도 로직 필요하나 일단 전송)
            chat_name: senderName, // ⭐️ 익명 이름 전송
          }
        });
        ws.send(messagePayload);

        // B. 채팅방 목록 갱신 신호 (roomUpdate)
        // (상대방의 방 이름은 내 이름이거나 그룹명이어야 하는데, 일단 DB의 room_name이나 시스템 로직 따름)
        const updatePayload = JSON.stringify({
          type: 'roomUpdate',
          payload: {
            id: roomId,
            room_name: roomInfo.room_name || senderName, // 방 이름이 없으면 보낸 사람 이름 표시
            last_message: roomInfo.last_message,
            last_message_timestamp: roomInfo.last_message_timestamp,
            my_unread_count: p.unread_count,
            left_at: null, 
          }
        });
        ws.send(updatePayload);

        console.log(`✅ [WS] 전송 성공 -> User ${targetUserId}`);
      } else {
        console.log(`📴 [WS] 전송 실패 (미접속) -> User ${targetUserId}`);
      }
    }
  } catch (err) {
    console.error("❌ [WS] 브로드캐스트 오류:", err);
  }
}

//실시간 매칭 로직
async function handleJoinMatch(userId, payload) {
  const {sport,lat,lng,target_count} = payload;
  console.log('[MATCH] 유저(${userId}) 대기열 등록: ${sport}, ${target_count}명');

  const client = await db.getClient();
  try{
    await client.query('BEGIN');
    await client.query('DELETE FROM match_queue WHERE user_id = $1', [userId]);
    await client.query(
      `INSERT INTO match_queue (user_id, socket_id, sport, target_count, geom)
      VALUES ($1, $2, $3, $4, ST_SetSRID(ST_MakePoint($5, $6), 4326))`,
      [userId, 'socket_placeholder', sport, target_count, lng, lat]
    );

    await client.query('COMMIT');
    await tryMatchMaking(client, sport, target_count);
  }catch(err){
    await client.query('ROLLBACK');
    console.error('[MATCH] 등록 실패:',err);
  }finally{
    client.release();
  }
}
async function tryMatchMaking(client, sport, targetCount) {
  try {
    // 2-1. 조건에 맞는 대기자 검색 (같은 종목, 같은 인원수)
    // (거리 제한 3km 추가: ST_DWithin)
    const query = `
      SELECT user_id, ST_AsText(geom) as location
      FROM match_queue 
      WHERE sport = $1 
        AND target_count = $2
        AND is_active = TRUE
      ORDER BY created_at ASC
      LIMIT $2
    `;
    
    const result = await client.query(query, [sport, targetCount]);
    const members = result.rows;

    // 2-2. 인원이 꽉 찼으면 매칭 성사!
    if (members.length === parseInt(targetCount)) {
      console.log(`[MATCH] 성사! 멤버: ${members.map(m=>m.user_id)}`);
      
      await client.query('BEGIN');

      // A. 채팅방 생성
      const roomRes = await client.query(
        `INSERT INTO chat_rooms (room_name, last_message, last_message_timestamp) 
         VALUES ($1, $2, NOW()) RETURNING id`,
        [`⚡ ${sport} 퀵 매치`, '매칭이 성사되었습니다!']
      );
      const roomId = roomRes.rows[0].id;

      // B. 참가자 추가
      for (const member of members) {
        await client.query(
          `INSERT INTO participants (chat_room_id, user_id, unread_count) VALUES ($1, $2, 0)`,
          [roomId, member.user_id]
        );
      }

      // C. 대기열에서 삭제
      const userIds = members.map(m => m.user_id);
      await client.query(
        `DELETE FROM match_queue WHERE user_id = ANY($1::int[])`,
        [userIds]
      );

      await client.query('COMMIT');

      // D. 알림 전송 (WebSocket)
      const notifyPayload = JSON.stringify({
        type: 'match_success',
        payload: { roomId: roomId, sport: sport }
      });

      for (const member of members) {
        const targetWs = clients[member.user_id];
        if (targetWs && targetWs.readyState === WebSocket.OPEN) {
          targetWs.send(notifyPayload);
        }
      }
    }
  } catch (err) {
    await client.query('ROLLBACK');
    console.error('[MATCH] 매칭 프로세스 오류:', err);
  }
}

// 3. 매칭 취소
async function handleCancelMatch(userId) {
  try {
    await db.query('DELETE FROM match_queue WHERE user_id = $1', [userId]);
    console.log(`[MATCH] 유저(${userId}) 취소됨`);
  } catch (err) {
    console.error('[MATCH] 취소 실패:', err);
  }
}

// ---------------------------------
// 10. 서버 시작
// ---------------------------------
server.listen(PORT, () => {
  console.log(`Server (HTTP + WS) listening on port ${PORT}`);
});
