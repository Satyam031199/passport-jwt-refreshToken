// userModel.js
const pool = require('./db');
const bcrypt = require('bcryptjs');

async function findUserByEmail(email) {
  const [rows] = await pool.query('SELECT * FROM users WHERE email = ?', [email]);
  return rows[0];
}

async function findUserById(id) {
  const [rows] = await pool.query('SELECT * FROM users WHERE id = ?', [id]);
  return rows[0];
}

async function updateUserRefreshToken(id, refreshToken) {
  await pool.query('UPDATE users SET refreshToken = ? WHERE id = ?', [refreshToken, id]);
}

async function createUser(email, password, role) {
  const hashedPassword = bcrypt.hashSync(password, 10);
  const [result] = await pool.query(
    'INSERT INTO users (email, password, role) VALUES (?, ?, ?)',
    [email, hashedPassword, role]
  );
  return result.insertId; // Return the ID of the newly created user
}

module.exports = {
  findUserByEmail,
  findUserById,
  updateUserRefreshToken,
  createUser
};
