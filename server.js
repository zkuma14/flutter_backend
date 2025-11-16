// server.js (최종 통합본)
const express = require('express');
const http = require('http');
const WebSocket = require('ws');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const db = require('./db'); // 수정된 db.js (getClient 포함)
require('dotenv').config();

const app = express();
// 포트 번호는 환경 변수에서 가져오거나 기본값 3000 사용
const PORT = process.env.PORT || 3000; 
const JWT_SECRET = process.env.JWT_SECRET;

// ---------------------------------
// 1. 미들웨어 설정
// ---------------------------------
app.use(cors());
app.use(express.json());

// ---------------------------------
// 2. 인증 API (로그인/회원가입 처리)
// ---------------------------------
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
            // 사용자가 없으면 더미 정보로 생성
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
        
        // JWT 토큰 생성
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

// ---------------------------------
// 3. 인증 미들웨어
// ---------------------------------
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

// ---------------------------------
// 4. 사용자/프로필 API
// ---------------------------------
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
// 5. 게시물 API (이전 가이드에서 제공된 CRUD)
// ---------------------------------

// 5-1. 게시물 조회 (Read)
app.get('/posts', authenticateToken, async (req, res) => {
    try {
        // created_at 컬럼을 가정하고 최신 순으로 정렬
        const result = await db.query('SELECT * FROM posts ORDER BY created_at DESC');
        res.json(result.rows);
    } catch (err) {
        console.error('게시물 조회 오류:', err);
        res.status(500).send('서버 오류');
    }
});

// 5-2. 게시물 생성 (Create)
app.post('/posts', authenticateToken, async (req, res) => {
    // Post 모델의 필드를 req.body에서 받습니다.
    const { exercise, title, content, location, members } = req.body; 
    const authorId = req.user.userId; // 작성자 ID를 인증 토큰에서 가져옴
    
    try {
        const queryText = `
            INSERT INTO posts (exercise, title, content, location, members, author_id, created_at) 
            VALUES ($1, $2, $3, $4, $5, $6, NOW()) RETURNING *
        `;
        const values = [exercise, title, content, location, members, authorId];
        
        const result = await db.query(queryText, values);
        res.status(201).json(result.rows[0]); 
    } catch (err) {
        console.error('게시물 생성 오류:', err);
        res.status(500).send('서버 오류');
    }
});

// ---------------------------------
// 6. 채팅방 API (트랜잭션 적용)
// ---------------------------------

// 6-1. 채팅방 목록 조회
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

// 6-2. 채팅방 생성 (트랜잭션)
app.post('/rooms', authenticateToken, async (req, res) => {
    const { userIds, roomName } = req.body;
    const creatorId = req.user.userId;
    const allParticipantIds = [creatorId, ...userIds];
    
    const client = await db.getClient(); 

    try {
        await client.query('BEGIN');

        const roomResult = await client.query(
            'INSERT INTO chat_rooms (room_name, last_message, last_message_timestamp) VALUES ($1, $2, NOW()) RETURNING id',
            [roomName, '채팅방이 생성되었습니다.']
        );
        const newChatRoomId = roomResult.rows[0].id;

        const participantPromises = allParticipantIds.map(userId => {
            return client.query(
                'INSERT INTO participants (chat_room_id, user_id, unread_count, is_hidden, left_at) VALUES ($1, $2, $3, $4, $5)',
                [newChatRoomId, userId, 0, false, null]
            );
        });
        await Promise.all(participantPromises); 

        await client.query('COMMIT');
        
        res.status(201).json({ id: newChatRoomId });

    } catch (err) {
        await client.query('ROLLBACK');
        console.error(err);
        res.status(500).json({ message: '채팅방 생성 실패' });
    } finally {
        client.release();
    }
});

// 6-3. 메시지 목록 조회
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


// 6-4. 메시지 전송 (트랜잭션 및 WS 브로드캐스트)
app.post('/rooms/:roomId/messages', authenticateToken, async (req, res) => {
    const { text } = req.body;
    const { roomId } = req.params;
    const senderId = req.user.userId;
    
    const client = await db.getClient();

    try {
        await client.query('BEGIN');

        // 1. messages 테이블에 삽입
        const messageResult = await client.query(
            'INSERT INTO messages (chat_room_id, sender_id, text) VALUES ($1, $2, $3) RETURNING *',
            [roomId, senderId, text]
        );
        const newMessage = messageResult.rows[0];

        // 2. chat_rooms 마지막 메시지 업데이트
        await client.query(
            'UPDATE chat_rooms SET last_message = $1, last_message_timestamp = $2 WHERE id = $3',
            [text, newMessage.created_at, roomId]
        );

        // 3. participants 안 읽음 카운트 업데이트 (보낸 사람 제외 +1)
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
        
        await client.query('COMMIT');
        
        // WebSocket 알림은 COMMIT 이후에 전송
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


// ---------------------------------
// 7. 지도/시설 API (GeoSpatial 쿼리)
// ---------------------------------

// 7-1. 카메라 위치에 따라 표시할 시설 가져오기
app.get('/facilities', authenticateToken, async (req, res)=>{
    const {minLat, minLng, maxLat, maxLng} = req.query;
    if (!minLat || !minLng || !maxLat || !maxLng){
        return res.status(400).json({message: '지도 경계값을 찾을 수 없음'});
    }
    try{
        // ST_MakeEnvelope(minX, minY, maxX, maxY, srid)
        // 위경도이므로 minLng, minLat, maxLng, maxLat 순서입니다.
        const sql = `
            SELECT * FROM public.facilities_for_map 
            WHERE ST_Contains(
                ST_MakeEnvelope($1, $2, $3, $4, 4326), 
                geom
            )
            LIMIT 1000;
        `;
        
        const params = [minLng, minLat, maxLng, maxLat];
        const result = await db.query(sql, params);
        
        // GeoJSON 형식으로 변환하여 반환 (Flutter mapboxgl 등에 사용)
        const geoJsonFeatures = result.rows.map(row=>{
            return{
                type: "Feature",
                properties: {
                    // DB 컬럼명을 그대로 사용
                    ...row,
                    cluster: false,
                },
                geometry: {
                    type: "Point",
                    // 지도 좌표계에 따라 [경도, 위도] 순서로 변환
                    coordinates: [row.시설경도, row.시설위도] 
                }
            }
        });

        res.json(geoJsonFeatures);

    }catch(err){
        console.error(err);
        res.status(500).json({message: '시설 로드 실패'});
    }
});

// ---------------------------------
// 8. WebSocket 서버 설정 (실시간 알림용)
// ---------------------------------
const server = http.createServer(app); 
const wss = new WebSocket.Server({ server });
const clients = {}; 

wss.on('connection', (ws, req) => {
    // URL 쿼리 파라미터에서 토큰 추출
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

// 9. WebSocket 메시지 브로드캐스트 함수
async function broadcastMessage(roomId, message) {
    const result = await db.query('SELECT user_id FROM participants WHERE chat_room_id = $1', [roomId]);
    const userIds = result.rows.map(row => row.user_id);

    // 클라이언트에게 전송할 메시지 페이로드
    const payload = JSON.stringify({
        type: 'newMessage',
        payload: {
            id: message.id,
            chat_room_id: message.chat_room_id,
            sender_id: message.sender_id,
            text: message.text,
            created_at: message.created_at,
            // 실제 unread_count는 클라이언트가 서버에서 룸 목록을 리로드하여 업데이트해야 합니다.
            // 여기서는 임시로 참여자 수를 보낼 수 있습니다. (하지만 DB 업데이트가 정확)
            // 브로드캐스트는 실시간 푸시 알림 역할에 집중합니다.
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
// 10. 서버 시작
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