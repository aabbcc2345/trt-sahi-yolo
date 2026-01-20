const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');

const app = express();
const PORT = 3000;
const SECRET_KEY = 'your_secret_key';

// 初始化数据库
const db = new sqlite3.Database('./minesweeper.db', (err) => {
  if (err) {
    console.error('Database connection error:', err.message);
  } else {
    console.log('Connected to SQLite database.');
    // 创建用户表
    db.run(`CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE NOT NULL,
      password TEXT NOT NULL,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )`);
    // 创建游戏记录表
    db.run(`CREATE TABLE IF NOT EXISTS game_records (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      difficulty TEXT NOT NULL,
      time INTEGER NOT NULL,
      mines INTEGER NOT NULL,
      success BOOLEAN NOT NULL,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (user_id) REFERENCES users (id)
    )`);
  }
});

app.use(cors());
app.use(express.json());
app.use(express.static('public'));

// 中间件：验证JWT
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  
  if (!token) return res.status(401).json({ message: 'Access token missing' });
  
  jwt.verify(token, SECRET_KEY, (err, user) => {
    if (err) return res.status(403).json({ message: 'Invalid token' });
    req.user = user;
    next();
  });
};

// 注册接口
app.post('/api/register', (req, res) => {
  const { username, password } = req.body;
  
  if (!username || !password) {
    return res.status(400).json({ message: 'Username and password are required' });
  }
  
  // 哈希密码
  bcrypt.hash(password, 10, (err, hashedPassword) => {
    if (err) {
      return res.status(500).json({ message: 'Password hashing failed' });
    }
    
    // 插入用户
    db.run('INSERT INTO users (username, password) VALUES (?, ?)', [username, hashedPassword], function(err) {
      if (err) {
        if (err.code === 'SQLITE_CONSTRAINT') {
          return res.status(409).json({ message: 'Username already exists' });
        }
        return res.status(500).json({ message: 'Registration failed' });
      }
      
      res.status(201).json({ message: 'User registered successfully' });
    });
  });
});

// 登录接口
app.post('/api/login', (req, res) => {
  const { username, password } = req.body;
  
  if (!username || !password) {
    return res.status(400).json({ message: 'Username and password are required' });
  }
  
  // 查询用户
  db.get('SELECT * FROM users WHERE username = ?', [username], (err, user) => {
    if (err) {
      return res.status(500).json({ message: 'Login failed' });
    }
    
    if (!user) {
      return res.status(401).json({ message: 'Invalid username or password' });
    }
    
    // 验证密码
    bcrypt.compare(password, user.password, (err, result) => {
      if (err || !result) {
        return res.status(401).json({ message: 'Invalid username or password' });
      }
      
      // 生成JWT
      const token = jwt.sign({ id: user.id, username: user.username }, SECRET_KEY, { expiresIn: '1h' });
      res.json({ token, user: { id: user.id, username: user.username } });
    });
  });
});

// 获取用户游戏记录
app.get('/api/records', authenticateToken, (req, res) => {
  const userId = req.user.id;
  
  db.all('SELECT * FROM game_records WHERE user_id = ? ORDER BY created_at DESC', [userId], (err, records) => {
    if (err) {
      return res.status(500).json({ message: 'Failed to fetch records' });
    }
    res.json(records);
  });
});

// 添加游戏记录
app.post('/api/records', authenticateToken, (req, res) => {
  const { difficulty, time, mines, success } = req.body;
  const userId = req.user.id;
  
  if (!difficulty || time === undefined || mines === undefined || success === undefined) {
    return res.status(400).json({ message: 'All fields are required' });
  }
  
  db.run('INSERT INTO game_records (user_id, difficulty, time, mines, success) VALUES (?, ?, ?, ?, ?)', 
    [userId, difficulty, time, mines, success], function(err) {
      if (err) {
        return res.status(500).json({ message: 'Failed to save record' });
      }
      res.status(201).json({ id: this.lastID, message: 'Record saved successfully' });
    });
});

// 更新游戏记录
app.put('/api/records/:id', authenticateToken, (req, res) => {
  const { id } = req.params;
  const { difficulty, time, mines, success } = req.body;
  const userId = req.user.id;
  
  // 检查记录是否属于该用户
  db.get('SELECT * FROM game_records WHERE id = ? AND user_id = ?', [id, userId], (err, record) => {
    if (err) {
      return res.status(500).json({ message: 'Failed to update record' });
    }
    
    if (!record) {
      return res.status(404).json({ message: 'Record not found' });
    }
    
    // 更新记录
    db.run('UPDATE game_records SET difficulty = ?, time = ?, mines = ?, success = ? WHERE id = ?', 
      [difficulty, time, mines, success, id], (err) => {
        if (err) {
          return res.status(500).json({ message: 'Failed to update record' });
        }
        res.json({ message: 'Record updated successfully' });
      });
  });
});

// 删除游戏记录
app.delete('/api/records/:id', authenticateToken, (req, res) => {
  const { id } = req.params;
  const userId = req.user.id;
  
  // 检查记录是否属于该用户
  db.get('SELECT * FROM game_records WHERE id = ? AND user_id = ?', [id, userId], (err, record) => {
    if (err) {
      return res.status(500).json({ message: 'Failed to delete record' });
    }
    
    if (!record) {
      return res.status(404).json({ message: 'Record not found' });
    }
    
    // 删除记录
    db.run('DELETE FROM game_records WHERE id = ?', [id], (err) => {
      if (err) {
        return res.status(500).json({ message: 'Failed to delete record' });
      }
      res.json({ message: 'Record deleted successfully' });
    });
  });
});

// 启动服务器
app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});
