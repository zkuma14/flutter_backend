// server.js (⭐️ 트랜잭션 버그 수정본)
const express = require('express');
const http = require('http');
const WebSocket = require('ws');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const db = require('./db'); // ⭐️ 수정된 db.js (getClient 포함)
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET;

// (1. 미들웨어 설정 - 기존과 동일)
app.use(cors());
app.use(express.json());

// (2. 인증 API - 기존과 동일)
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
        const dummyPassword = 'dummy_password_hash'; 
        userResult = await db.query(
          `INSERT INTO users (display_name, preferred_sport, email, password_hash) 
           VALUES ($1, $2, $3, $4) 
           RETURNING *`,
          [displayName, '', dummyEmail, dummyPassword]
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

// (3. 인증 미들웨어 - 기존과 동일)
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (token == null) return res.sendStatus(401);
  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.sendStatus(403);
    req.user = user;
    next();
  });
};

// (4. 사용자 API - 기존과 동일)
app.get('/users/me', authenticateToken, async (req, res) => {
  try {
    const userId = req.user.userId;
    const userResult = await db.query('SELECT * FROM users WHERE id = $1', [userId]);
    const hiddenResult = await db.query('SELECT hidden_id FROM hidden_users WHERE hider_id = $1', [userId]);
    const hiddenUsers = hiddenResult.rows.map(row => row.hidden_id);
    const user = userResult.rows[0];
    user.hidden_users = hiddenUsers;
    res.json(user);
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: '서버 오류' });
  }
});
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
app.get('/users', authenticateToken, async (req, res) => {
    const userId = req.user.userId;
    try {
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

// (GET /rooms - 기존과 동일)
app.get('/rooms', authenticateToken, async (req, res) => {
  const userId = req.user.userId;
  try {
    const query = `
      SELECT 
        cr.id, cr.last_message, cr.last_message_timestamp,
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

// ⭐️⭐️⭐️ 1. POST /rooms (트랜잭션 수정본) ⭐️⭐️⭐️
// ⭐️ (이 부분이 이전 코드의 버그를 수정한 것입니다)
app.post('/rooms', authenticateToken, async (req, res) => {
  const { userIds, roomName } = req.body;
  const creatorId = req.user.userId;
  const allParticipantIds = [creatorId, ...userIds];
  
  // ⭐️ 1. DB에서 '클라이언트' 1개를 빌려옴
  const client = await db.getClient(); 

  try {
    // ⭐️ 2. 트랜잭션 시작 (빌려온 클라이언트로)
    await client.query('BEGIN');

    // 3. chat_rooms에 방 생성
    const roomResult = await client.query(
      'INSERT INTO chat_rooms (room_name, last_message, last_message_timestamp) VALUES ($1, $2, NOW()) RETURNING id',
      [roomName, '채팅방이 생성되었습니다.']
    );
    const newChatRoomId = roomResult.rows[0].id;

    // 4. participants 테이블에 참가자 추가
    const participantPromises = allParticipantIds.map(userId => {
      return client.query(
        'INSERT INTO participants (chat_room_id, user_id, unread_count, is_hidden, left_at) VALUES ($1, $2, $3, $4, $5)',
        [newChatRoomId, userId, 0, false, null]
      );
    });
    await Promise.all(participantPromises); // ⭐️ 모든 참가자 쿼리 실행

    // 5. ⭐️ 트랜잭션 완료
    await client.query('COMMIT');
    
    res.status(201).json({ id: newChatRoomId });

  } catch (err) {
    // 6. ⭐️ 오류 발생 시 되돌리기
    await client.query('ROLLBACK');
    console.error(err);
    res.status(500).json({ message: '채팅방 생성 실패' });
  } finally {
    // 7. ⭐️ (중요) 빌려온 클라이언트를 DB 풀(Pool)에 반납
    client.release();
  }
});

// (GET /rooms/:roomId/messages - 기존과 동일)
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


// ⭐️⭐️⭐️ 2. POST /rooms/:roomId/messages (트랜잭션 수정본) ⭐️⭐️⭐️
// ⭐️ (이 부분도 버그를 수정한 것입니다)
app.post('/rooms/:roomId/messages', authenticateToken, async (req, res) => {
  const { text } = req.body;
  const { roomId } = req.params;
  const senderId = req.user.userId;
  
  // ⭐️ 1. 클라이언트 빌려오기
  const client = await db.getClient();

  try {
    // ⭐️ 2. 트랜잭션 시작
    await client.query('BEGIN');

    // 3. messages 테이블에 삽입
    const messageResult = await client.query(
      'INSERT INTO messages (chat_room_id, sender_id, text) VALUES ($1, $2, $3) RETURNING *',
      [roomId, senderId, text]
    );
    const newMessage = messageResult.rows[0];

    // 4. chat_rooms 마지막 메시지 업데이트
    await client.query(
      'UPDATE chat_rooms SET last_message = $1, last_message_timestamp = $2 WHERE id = $3',
      [text, newMessage.created_at, roomId]
    );

    // 5. participants 안읽음 카운트 업데이트
    await client.query(
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
    
    // 6. ⭐️ 트랜잭션 완료
    await client.query('COMMIT');
    
    // ⭐️ WebSocket 알림은 COMMIT 이후에 전송
    broadcastMessage(roomId, newMessage); 
    res.status(201).json(newMessage);

  } catch (err) {
    // 7. ⭐️ 오류 시 되돌리기
    await client.query('ROLLBACK');
    console.error(err);
    res.status(500).json({ message: '메시지 전송 오류' });
  } finally {
    // 8. ⭐️ 클라이언트 반납
    client.release();
  }
});

// ---------------------------------
// ⚡️ 6. WebSocket 서버 설정 (실시간 알림용)
// ---------------------------------

// (WebSocket 부분 - 기존과 동일)
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
    userId = payload.userId;
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

// ⭐️ 7. WebSocket 메시지 브로드캐스트 함수
async function broadcastMessage(roomId, message) {
  const result = await db.query('SELECT user_id FROM participants WHERE chat_room_id = $1', [roomId]);
  const userIds = result.rows.map(row => row.user_id);

  const payload = JSON.stringify({
    type: 'newMessage',
    payload: {
      id: message.id,
      chat_room_id: message.chat_room_id,
      sender_id: message.sender_id,
      text: message.text,
      created_at: message.created_at,
      unread_count: userIds.length - 1,
    }
  });

  for (const uid of userIds) {
    const ws = clients[uid];
    if (ws && ws.readyState === WebSocket.OPEN) {
      ws.send(payload);
    }
  }
}

// ---------------------------------
// 8. 서버 시작
// ---------------------------------
server.listen(PORT, () => {
  console.log(`Server (HTTP + WS) listening on port ${PORT}`);
});

//맵
//카메라 위치에 따라 표시할 시설 가져오기
app.get('/facilities', authenticateToken, async (req, res)=>{
  const {minLat, minLng, maxLat, maxLng, zoom} = req.query;

  if (!minLat || !minLng || !maxLat || !maxLng || zoom === undefined){
    return res.status(400).json({message: '지도 경계값을 찾을 수 없음'});
    }

    const zoomLevel = parseInt(zoom,10);
    let cellSize;

    if (zoomLevel < 10){
      cellSize = 0.1;
    } else if (zoomLevel < 15){
      cellSize = 0.02;
    } else {
      cellSize = 0.005;
    }
  
  try{
    const sql = `
      SELECT * FROM public.facilities_for_map 
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

    const clsuters = {};

    for (const facility of allFacilitiesInView){
      const lat = parseFloat(facility.시설위도);
      const lng = parseFloat(facility.시설경도);

      const gridLat = Math.floor(lat / cellSize) * cellSize;
      const gridLng = Math.floor(lng / cellSize) * cellSize;
      const gridKey = `${gridLat.toFixed(5)}-${gridLng.toFixed(5)}`;

      if (!cluster[gridKey]){
        clusters[gridKey] = [];
      }
      clusters[gridKey.push(facility)];
    }

    const clusterableItems = [];
    const clusterThreshold = 100;

    for(const gridKey in clusters){
      const facilitiesInCell = clusters[gridKey];

      if(facilitiesInCell.length >= clusterThreshold && zoomLevel < 17) {
        const avgLat = facilitiesInCell.reduce((sum,f) => sum + parseFloat(f.시설위도),0)/facilitiesInCell.length;
        const avgLng = facilitiesInCell.reduce((sum,f) => sum + parseFloat(f.시설경도),0)/facilitiesInCell.length;

        clusterableItems.push({
          location: {latitude: avgLat, longitude: avgLng},
          isCluster: true,
          count: facilitiesInCell.length,
          facility: null,
        });
      } else {
        for(const facility of facilitiesInCell){
          clusterableItems.push({
            location: {latitude: parseFloat(facility.시설위도), longitude: parseFloat(facility.시설경도)},
            isCluster: false,
            facility: {
              id: facility.id.toString(),
              name: facility.시설명,
              iconpath: facility.icon_path || "assets/marker.png",
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