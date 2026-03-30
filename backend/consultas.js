const pool = require('./db')
const bcrypt = require('bcryptjs')

const registrarUsuario = async (usuario) => {
  const { email, password, rol, lenguage } = usuario
  const passwordEncriptada = bcrypt.hashSync(password, 10)
  const consulta = 'INSERT INTO usuarios (email, password, rol, lenguage) VALUES ($1, $2, $3, $4)'
  const values = [email, passwordEncriptada, rol, lenguage]
  await pool.query(consulta, values)
}

const verificarCredenciales = async (email, password) => {
  const consulta = 'SELECT * FROM usuarios WHERE email = $1'
  const { rows, rowCount } = await pool.query(consulta, [email])
  if (!rowCount) throw { code: 401, message: 'Email o contraseña incorrecta' }
  const passwordCorrecta = bcrypt.compareSync(password, rows[0].password)
  if (!passwordCorrecta) throw { code: 401, message: 'Email o contraseña incorrecta' }
  return rows[0]
}

const obtenerUsuario = async (email) => {
  const consulta = 'SELECT * FROM usuarios WHERE email = $1'
  const { rows } = await pool.query(consulta, [email])
  return rows
}

module.exports = { registrarUsuario, verificarCredenciales, obtenerUsuario }