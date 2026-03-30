const express = require('express')
const cors = require('cors')
const jwt = require('jsonwebtoken')
require('dotenv').config()

const { registrarUsuario, verificarCredenciales, obtenerUsuario } = require('./consultas')

const app = express()
app.use(express.json())
app.use(cors())

const logger = (req, res, next) => {
  console.log(`${req.method} ${req.url}`)
  next()
}

const verificarToken = (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1]
  if (!token) return res.status(401).json({ message: 'Token no proporcionado' })
  try {
    const payload = jwt.verify(token, process.env.JWT_SECRET)
    req.user = payload
    next()
  } catch {
    res.status(401).json({ message: 'Token inválido' })
  }
}

const verificarCredencialesMiddleware = (req, res, next) => {
  const { email, password } = req.body
  if (!email || !password) {
    return res.status(400).json({ message: 'Email y password son obligatorios' })
  }
  next()
}

app.use(logger)

app.post('/usuarios', async (req, res) => {
  try {
    await registrarUsuario(req.body)
    res.status(201).json({ message: 'Usuario registrado con éxito' })
  } catch (error) {
    res.status(500).json({ message: error.message })
  }
})

app.post('/login', verificarCredencialesMiddleware, async (req, res) => {
  try {
    const { email, password } = req.body
    const usuario = await verificarCredenciales(email, password)
    const token = jwt.sign({ email }, process.env.JWT_SECRET)
    res.json({ token })
  } catch (error) {
    res.status(error.code || 500).json({ message: error.message })
  }
})

app.get('/usuarios', verificarToken, async (req, res) => {
  try {
    const usuario = await obtenerUsuario(req.user.email)
    res.json(usuario)
  } catch (error) {
    res.status(500).json({ message: error.message })
  }
})

app.listen(3000, () => console.log('Servidor corriendo en puerto 3000'))