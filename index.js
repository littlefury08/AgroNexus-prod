import express from "express";
import mysql from "mysql2/promise";
import cors from "cors";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import dotenv from "dotenv";
import { Server } from "socket.io";
import http from "http";
import path from "path";
import multer from "multer";

dotenv.config();

const app = express();
app.use(cors());
app.use(express.json());

const JWT_SECRET = process.env.JWT_SECRET || "claveultrasecreeta123";
const JWT_EXPIRES = process.env.JWT_EXPIRES || "2h";

const dbConfig = {
  host: process.env.MYSQL_ADDON_HOST,
  user: process.env.MYSQL_ADDON_USER,
  password: process.env.MYSQL_ADDON_PASSWORD,
  database: process.env.MYSQL_ADDON_DB,
};

const pool = mysql.createPool({
  ...dbConfig,
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0,
  acquireTimeout: 60000,
  timeout: 60000,
});

const uploadsDir = path.join(process.cwd(), "uploads");

app.use("/uploads", express.static(uploadsDir));

const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, uploadsDir);
  },
  filename: (req, file, cb) => {
    const unique = Date.now() + "-" + file.originalname.replace(/\s+/g, "_");
    cb(null, unique);
  },
});
const upload = multer({ storage });

(async () => {
  try {
    const conn = await pool.getConnection();
    console.log("✅ Conectado a MySQL (agronexus)");
    conn.release();
  } catch (error) {
    console.error("❌ Error conectando a MySQL:", error);
    process.exit(1);
  }
})();

const server = http.createServer(app);

const io = new Server(server, {
  cors: {
    origin: process.env.URL_FRONTEND || "http://localhost:3000",
    methods: ["GET", "POST"],
  },
});

const usuariosConectados = new Map();

io.on("connection", (socket) => {
  console.log("Nuevo cliente conectado:", socket.id);

  socket.on("registrarUsuario", (userId) => {
    usuariosConectados.set(userId, socket.id);
  });

  socket.on("enviarMensaje", ({ roomId, mensaje }) => {
    io.to(roomId.toString()).emit("nuevoMensaje", mensaje);
  });

  socket.on("unirseSala", (roomId) => {
    socket.join(roomId.toString());
  });

  socket.on("disconnect", () => {
    for (let [userId, sockId] of usuariosConectados.entries()) {
      if (sockId === socket.id) {
        usuariosConectados.delete(userId);
      }
    }
  });
});

async function getGrupoRole(userId, grupoId) {
  const [rows] = await pool.execute(
    "SELECT rol FROM grupo_miembro WHERE grupo_id=? AND usuario_id=? LIMIT 1",
    [grupoId, userId]
  );
  return rows.length ? rows[0].rol : null;
}

async function isGrupoAdmin(userId, grupoId) {
  const role = await getGrupoRole(userId, grupoId);
  return role === "admin";
}

async function isTerrenoOwner(userId, terrenoId) {
  const [rows] = await pool.execute(
    "SELECT propietario_id FROM terreno WHERE id = ? LIMIT 1",
    [terrenoId]
  );
  return rows.length && rows[0].propietario_id === userId;
}

async function userIsDirectTerrenoMemberWritable(userId, terrenoId) {
  const [rows] = await pool.execute(
    "SELECT rol FROM terreno_miembro WHERE terreno_id = ? AND usuario_id = ? LIMIT 1",
    [terrenoId, userId]
  );
  if (!rows.length) return false;
  return rows[0].rol === "admin" || rows[0].rol === "editor";
}

async function userHasTerrenoWriteAccess(userId, terrenoId) {
  if (await isTerrenoOwner(userId, terrenoId)) return true;

  if (await userIsDirectTerrenoMemberWritable(userId, terrenoId)) return true;

  const [rows] = await pool.execute(
    `SELECT gm.rol
     FROM grupo_terreno gt
     JOIN grupo_miembro gm ON gt.grupo_id = gm.grupo_id
     WHERE gt.terreno_id = ? AND gm.usuario_id = ? AND gt.permiso = 'lectura_escritura'
     LIMIT 1`,
    [terrenoId, userId]
  );
  if (rows.length && (rows[0].rol === "admin" || rows[0].rol === "editor"))
    return true;

  return false;
}

app.get("/api/alertas", authenticateToken, async (req, res) => {
  try {
    const { terrenoId, sensorId } = req.query;

    let sql = `
      SELECT a.id, a.tipo, a.valor, a.valor_minimo, a.valor_maximo, a.fecha,
             s.id as sensor_id, s.nombre as sensor_nombre, s.terreno_id, t.nombre as terreno_nombre
      FROM alerta a
      JOIN sensor s ON a.sensor_id = s.id
      JOIN terreno t ON s.terreno_id = t.id
      WHERE 1=1
    `;
    const params = [];

    if (terrenoId) {
      sql += " AND s.terreno_id = ?";
      params.push(terrenoId);
    }
    if (sensorId) {
      sql += " AND s.id = ?";
      params.push(sensorId);
    }

    const [rows] = await pool.query(sql, params);
    res.json({ success: true, alertas: rows });
  } catch (err) {
    console.error("❌ Error obteniendo alertas:", err.message);
    res.status(500).json({ success: false, message: "Error en el servidor" });
  }
});

app.get("/api/mis-terrenos", authenticateToken, async (req, res) => {
  try {
    const userId = req.user.id;

    const [rows] = await pool.query(
      `SELECT t.id, t.nombre, t.ubicacion, t.area_m2, t.descripcion
       FROM terreno t
       JOIN terreno_miembro tm ON t.id = tm.terreno_id
       WHERE tm.usuario_id = ?`,
      [userId]
    );

    res.json({ success: true, terrenos: rows });
  } catch (err) {
    console.error("❌ Error obteniendo terrenos:", err.message);
    res.status(500).json({ success: false, message: "Error en el servidor" });
  }
});

io.use((socket, next) => {
  const token = socket.handshake.auth?.token;
  if (!token) {
    console.warn("❌ Socket rechazado: no hay token");
    return next(new Error("Token requerido"));
  }

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      console.warn("❌ Socket rechazado: token inválido");
      return next(new Error("Token inválido"));
    }
    socket.user = user;
    next();
  });
});

app.post("/api/chat/rooms", authenticateToken, async (req, res) => {
  try {
    const {
      tipo,
      titulo,
      participantes = [],
      grupo_id = null,
      terreno_id = null,
    } = req.body;
    const creado_por = req.user.id;
    const [r] = await pool.execute(
      "INSERT INTO chat_room (tipo, grupo_id, terreno_id, creado_por, titulo, fecha_creacion) VALUES (?, ?, ?, ?, ?, NOW())",
      [tipo, grupo_id || null, terreno_id || null, creado_por, titulo || null]
    );
    const roomId = r.insertId;

    const vals = [];
    for (const u of participantes) {
      vals.push([roomId, u, "viewer"]);
    }
    vals.push([roomId, creado_por, "admin"]);
    if (vals.length) {
      await pool.query(
        "INSERT INTO chat_participante (room_id, usuario_id, rol) VALUES ?",
        [vals]
      );
    }

    res.json({ success: true, id: roomId });
  } catch (err) {
    console.error("Error crear sala:", err);
    res.status(500).json({ success: false, message: "Error interno" });
  }
});

app.get("/api/chat/rooms", authenticateToken, async (req, res) => {
  try {
    const userId = req.user.id;
    const [rows] = await pool.execute(
      `SELECT cr.*, cp.rol
       FROM chat_room cr
       JOIN chat_participante cp ON cr.id = cp.room_id
       WHERE cp.usuario_id = ?
       ORDER BY cr.fecha_creacion DESC`,
      [userId]
    );
    res.json({ success: true, rooms: rows });
  } catch (err) {
    console.error("Error listar salas:", err);
    res.status(500).json({ success: false, message: "Error interno" });
  }
});

app.get("/api/chat/rooms/:id/messages", authenticateToken, async (req, res) => {
  try {
    const roomId = req.params.id;
    const limit = parseInt(req.query.limit || "50");
    const offset = parseInt(req.query.offset || "0");

    const [ok] = await pool.execute(
      "SELECT id FROM chat_participante WHERE room_id = ? AND usuario_id = ? LIMIT 1",
      [roomId, req.user.id]
    );
    if (!ok.length)
      return res.status(403).json({ success: false, message: "No autorizado" });

    const [msgs] = await pool.execute(
      `SELECT cm.id, cm.room_id, cm.autor_id, cm.contenido, cm.leido, cm.fecha_envio, u.nombre, u.apellido
       FROM chat_mensaje cm
       LEFT JOIN usuario u ON cm.autor_id = u.id
       WHERE cm.room_id = ?
       ORDER BY cm.fecha_envio DESC
       LIMIT ? OFFSET ?`,
      [roomId, limit, offset]
    );
    res.json({ success: true, mensajes: msgs.reverse() });
  } catch (err) {
    console.error("Error obtener mensajes:", err);
    res.status(500).json({ success: false, message: "Error interno" });
  }
});

app.post(
  "/api/chat/rooms/:id/messages",
  authenticateToken,
  async (req, res) => {
    try {
      const roomId = req.params.id;
      const { contenido } = req.body;
      if (!contenido)
        return res
          .status(400)
          .json({ success: false, message: "Contenido requerido" });

      const [ok] = await pool.execute(
        "SELECT rol FROM chat_participante WHERE room_id = ? AND usuario_id = ? LIMIT 1",
        [roomId, req.user.id]
      );
      if (!ok.length)
        return res
          .status(403)
          .json({ success: false, message: "No autorizado" });

      const [r] = await pool.execute(
        "INSERT INTO chat_mensaje (room_id, autor_id, contenido, leido, fecha_envio) VALUES (?, ?, ?, 0, NOW())",
        [roomId, req.user.id, contenido]
      );
      const id = r.insertId;

      const [[mensaje]] = await pool.execute(
        `SELECT cm.id, cm.room_id, cm.autor_id, cm.contenido, cm.leido, cm.fecha_envio, u.nombre, u.apellido
       FROM chat_mensaje cm LEFT JOIN usuario u ON cm.autor_id = u.id
       WHERE cm.id = ? LIMIT 1`,
        [id]
      );

      io.to(String(roomId)).emit("nuevoMensaje", mensaje);

      res.json({ success: true, mensaje });
    } catch (err) {
      console.error("Error enviar mensaje:", err);
      res.status(500).json({ success: false, message: "Error interno" });
    }
  }
);

app.post(
  "/api/chat/rooms/:id/participants",
  authenticateToken,
  async (req, res) => {
    try {
      const roomId = req.params.id;
      const { usuario_id, rol = "viewer" } = req.body;
      const [r] = await pool.execute(
        "SELECT rol FROM chat_participante WHERE room_id = ? AND usuario_id = ? LIMIT 1",
        [roomId, req.user.id]
      );
      if (!r.length || r[0].rol !== "admin")
        return res
          .status(403)
          .json({ success: false, message: "Solo admin puede agregar" });

      await pool.execute(
        "INSERT INTO chat_participante (room_id, usuario_id, rol) VALUES (?, ?, ?)",
        [roomId, usuario_id, rol]
      );
      res.json({ success: true });
    } catch (err) {
      console.error("Error agregar participante:", err);
      if (err && err.code === "ER_DUP_ENTRY")
        return res
          .status(400)
          .json({ success: false, message: "Usuario ya es participante" });
      res.status(500).json({ success: false, message: "Error interno" });
    }
  }
);

app.put(
  "/api/chat/rooms/:id/participants/:usuarioId",
  authenticateToken,
  async (req, res) => {
    try {
      const roomId = req.params.id;
      const usuarioId = req.params.usuarioId;
      const { rol } = req.body;

      const [r] = await pool.execute(
        "SELECT rol FROM chat_participante WHERE room_id = ? AND usuario_id = ? LIMIT 1",
        [roomId, req.user.id]
      );
      if (!r.length || r[0].rol !== "admin")
        return res
          .status(403)
          .json({ success: false, message: "Solo admin puede cambiar roles" });

      await pool.execute(
        "UPDATE chat_participante SET rol = ? WHERE room_id = ? AND usuario_id = ?",
        [rol, roomId, usuarioId]
      );
      res.json({ success: true });
    } catch (err) {
      console.error("Error cambiar rol:", err);
      res.status(500).json({ success: false, message: "Error interno" });
    }
  }
);

app.delete(
  "/api/chat/rooms/:id/participants/:usuarioId",
  authenticateToken,
  async (req, res) => {
    try {
      const roomId = req.params.id;
      const usuarioId = req.params.usuarioId;

      const [r] = await pool.execute(
        "SELECT rol FROM chat_participante WHERE room_id = ? AND usuario_id = ? LIMIT 1",
        [roomId, req.user.id]
      );
      if (!r.length || r[0].rol !== "admin")
        return res
          .status(403)
          .json({ success: false, message: "Solo admin puede eliminar" });

      await pool.execute(
        "DELETE FROM chat_participante WHERE room_id = ? AND usuario_id = ?",
        [roomId, usuarioId]
      );
      res.json({ success: true });
    } catch (err) {
      console.error("Error eliminar participante:", err);
      res.status(500).json({ success: false, message: "Error interno" });
    }
  }
);

app.delete("/api/chat/rooms/:id", authenticateToken, async (req, res) => {
  try {
    const roomId = req.params.id;
    const [r] = await pool.execute(
      "SELECT rol FROM chat_participante WHERE room_id = ? AND usuario_id = ? LIMIT 1",
      [roomId, req.user.id]
    );
    if (!r.length || r[0].rol !== "admin")
      return res
        .status(403)
        .json({ success: false, message: "Solo admin puede eliminar la sala" });

    await pool.execute("DELETE FROM chat_room WHERE id = ?", [roomId]);
    res.json({ success: true });
  } catch (err) {
    console.error("Error eliminar sala:", err);
    res.status(500).json({ success: false, message: "Error interno" });
  }
});

app.get("/api/agenda", authenticateToken, async (req, res) => {
  try {
    const [rows] = await pool.query(
      `SELECT id, titulo, descripcion, fecha_inicio, fecha_fin, creado_por, terreno_id, grupo_id 
       FROM agenda_evento 
       WHERE creado_por = ? OR grupo_id IN (
          SELECT grupo_id FROM grupo_miembro WHERE usuario_id = ?
       ) OR terreno_id IN (
          SELECT terreno_id FROM terreno_miembro WHERE usuario_id = ?
       )`,
      [req.user.id, req.user.id, req.user.id]
    );
    res.json({ success: true, eventos: rows });
  } catch (err) {
    console.error("❌ Error obteniendo eventos:", err.message);
    res.status(500).json({ success: false, message: "Error en el servidor" });
  }
});

app.post("/api/agenda", authenticateToken, async (req, res) => {
  try {
    const {
      titulo,
      descripcion,
      fecha_inicio,
      fecha_fin,
      terreno_id,
      grupo_id,
    } = req.body;
    if (!titulo || !fecha_inicio || !fecha_fin) {
      return res.status(400).json({ success: false, message: "Faltan datos" });
    }
    const [result] = await pool.query(
      "INSERT INTO agenda_evento (titulo, descripcion, fecha_inicio, fecha_fin, creado_por, terreno_id, grupo_id) VALUES (?,?,?,?,?,?,?)",
      [
        titulo,
        descripcion || null,
        fecha_inicio,
        fecha_fin,
        req.user.id,
        terreno_id || null,
        grupo_id || null,
      ]
    );
    res.json({ success: true, id: result.insertId });
  } catch (err) {
    console.error("❌ Error creando evento:", err.message);
    res.status(500).json({ success: false, message: "Error en el servidor" });
  }
});

app.delete("/api/agenda/:id", authenticateToken, async (req, res) => {
  try {
    const eventoId = req.params.id;
    await pool.query("DELETE FROM agenda_evento WHERE id=? AND creado_por=?", [
      eventoId,
      req.user.id,
    ]);
    res.json({ success: true });
  } catch (err) {
    console.error("❌ Error eliminando evento:", err.message);
    res.status(500).json({ success: false, message: "Error en el servidor" });
  }
});

function authenticateToken(req, res, next) {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];
  if (!token) return res.status(403).json({ message: "Token requerido" });
  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err)
      return res.status(403).json({ message: "Token inválido o expirado" });
    req.user = user;
    next();
  });
}

app.post("/api/registro", async (req, res) => {
  const { nombre, apellido, email, password } = req.body;
  if (!nombre || !apellido || !email || !password) {
    return res
      .status(400)
      .json({ message: "Todos los campos son obligatorios" });
  }
  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    const sql = `INSERT INTO usuario (nombre, apellido, email, clave, fotouser) 
                 VALUES (?, ?, ?, ?, NULL)`;
    await pool.execute(sql, [nombre, apellido, email, hashedPassword]);
    res.status(201).json({ message: "Usuario registrado correctamente" });
  } catch (error) {
    console.error("❌ Error al registrar usuario:", error);
    res.status(500).json({ message: "Error interno del servidor" });
  }
});

app.post("/api/login", async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) {
    return res
      .status(400)
      .json({ success: false, message: "Correo y contraseña requeridos" });
  }
  try {
    const [rows] = await pool.query(
      "SELECT id, nombre, apellido, email, clave FROM usuario WHERE email = ? LIMIT 1",
      [email]
    );
    if (rows.length === 0) {
      return res
        .status(401)
        .json({ success: false, message: "Correo o contraseña incorrectos" });
    }
    const user = rows[0];
    const isMatch = await bcrypt.compare(password, user.clave);
    if (!isMatch) {
      return res
        .status(401)
        .json({ success: false, message: "Correo o contraseña incorrectos" });
    }
    const token = jwt.sign(
      { id: user.id, email: user.email, nombre: user.nombre },
      JWT_SECRET,
      { expiresIn: JWT_EXPIRES }
    );
    res.json({
      success: true,
      message: "Inicio de sesión exitoso",
      token,
      user: {
        id: user.id,
        nombre: user.nombre,
        apellido: user.apellido,
        email: user.email,
      },
    });
  } catch (error) {
    console.error("❌ Error en login:", error.message);
    res
      .status(500)
      .json({ success: false, message: "Error interno del servidor" });
  }
});

app.get("/api/perfil", authenticateToken, async (req, res) => {
  try {
    const [rows] = await pool.query(
      "SELECT id, nombre, apellido, email FROM usuario WHERE id = ?",
      [req.user.id]
    );
    if (rows.length === 0) {
      return res.status(404).json({ error: "Usuario no encontrado" });
    }
    res.json({ success: true, usuario: rows[0] });
  } catch (err) {
    console.error("❌ Error al obtener perfil:", err);
    res.status(500).json({ error: "Error en el servidor" });
  }
});

app.put("/api/perfil", authenticateToken, async (req, res) => {
  try {
    const { nombre, apellido, email } = req.body;
    await pool.execute(
      "UPDATE usuario SET nombre=?, apellido=?, email=? WHERE id=?",
      [nombre, apellido, email, req.user.id]
    );
    res.json({ success: true, message: "Perfil actualizado" });
  } catch (error) {
    console.error("Error actualizando perfil:", error);
    res.status(500).json({ success: false, message: "Error en el servidor" });
  }
});

app.get("/api/terrenos", authenticateToken, async (req, res) => {
  try {
    const userId = req.user.id;

    const [rows] = await pool.execute(
      `
      SELECT DISTINCT t.id, t.nombre, t.descripcion, t.ubicacion, t.area_m2, 
             t.propietario_id, t.fecha_creacion,
             CASE
               WHEN t.propietario_id = ? THEN 'propietario'
               WHEN tm.rol IS NOT NULL THEN tm.rol
               WHEN gm.rol IS NOT NULL THEN gm.rol
               ELSE 'viewer'
             END as rol
      FROM terreno t
      LEFT JOIN terreno_miembro tm 
             ON t.id = tm.terreno_id AND tm.usuario_id = ?
      LEFT JOIN grupo_terreno gt 
             ON t.id = gt.terreno_id
      LEFT JOIN grupo_miembro gm 
             ON gt.grupo_id = gm.grupo_id AND gm.usuario_id = ?
      WHERE t.propietario_id = ?
         OR tm.usuario_id = ?
         OR gm.usuario_id = ?`,
      [userId, userId, userId, userId, userId, userId]
    );

    res.json({ success: true, terrenos: rows });
  } catch (error) {
    console.error("❌ Error obteniendo terrenos:", error.message);
    res
      .status(500)
      .json({ success: false, message: "Error interno del servidor" });
  }
});

app.post("/api/terrenos", authenticateToken, async (req, res) => {
  try {
    const { nombre, descripcion, ubicacion, area_m2 } = req.body;
    if (!nombre)
      return res
        .status(400)
        .json({ success: false, message: "Nombre requerido" });

    const [result] = await pool.execute(
      "INSERT INTO terreno (nombre, descripcion, ubicacion, area_m2, propietario_id, fecha_creacion) VALUES (?,?,?,?,?,NOW())",
      [
        nombre,
        descripcion || null,
        ubicacion || null,
        area_m2 || null,
        req.user.id,
      ]
    );

    res.json({ success: true, id: result.insertId });
  } catch (error) {
    console.error("❌ Error creando terreno:", error.message);
    res
      .status(500)
      .json({ success: false, message: "Error interno del servidor" });
  }
});

app.put("/api/terrenos/:id", authenticateToken, async (req, res) => {
  try {
    const terrenoId = req.params.id;
    if (!(await isTerrenoOwner(req.user.id, terrenoId))) {
      return res.status(403).json({ success: false, message: "No autorizado" });
    }
    const { nombre, descripcion, ubicacion, area_m2 } = req.body;
    await pool.execute(
      "UPDATE terreno SET nombre=?, descripcion=?, ubicacion=?, area_m2=? WHERE id=?",
      [nombre, descripcion, ubicacion, area_m2, terrenoId]
    );
    res.json({ success: true, message: "Terreno actualizado" });
  } catch (error) {
    console.error("❌ Error actualizando terreno:", error.message);
    res
      .status(500)
      .json({ success: false, message: "Error interno del servidor" });
  }
});

app.delete("/api/terrenos/:id", authenticateToken, async (req, res) => {
  try {
    const terrenoId = req.params.id;
    if (!(await isTerrenoOwner(req.user.id, terrenoId))) {
      return res.status(403).json({ success: false, message: "No autorizado" });
    }
    const [result] = await pool.execute("DELETE FROM terreno WHERE id = ?", [
      terrenoId,
    ]);
    if (result.affectedRows === 0)
      return res.status(404).json({ success: false, message: "No encontrado" });

    res.json({ success: true, message: "Terreno eliminado" });
  } catch (error) {
    console.error("❌ Error eliminando terreno:", error.message);
    res
      .status(500)
      .json({ success: false, message: "Error interno del servidor" });
  }
});

app.get("/api/terrenos/:id/miembros", authenticateToken, async (req, res) => {
  try {
    const terrenoId = req.params.id;

    const [direct] = await pool.execute(
      `SELECT tm.usuario_id, tm.rol, u.nombre, u.apellido, tm.fecha_union
       FROM terreno_miembro tm
       LEFT JOIN usuario u ON tm.usuario_id = u.id
       WHERE tm.terreno_id = ?`,
      [terrenoId]
    );

    const [grupoRows] = await pool.execute(
      `SELECT gt.grupo_id, gt.permiso, g.nombre as grupo_nombre
       FROM grupo_terreno gt
       LEFT JOIN grupo g ON gt.grupo_id = g.id
       WHERE gt.terreno_id = ?`,
      [terrenoId]
    );

    const grupos = [];
    for (const gr of grupoRows) {
      const [m] = await pool.execute(
        `SELECT gm.usuario_id, gm.rol, u.nombre, u.apellido
         FROM grupo_miembro gm
         LEFT JOIN usuario u ON gm.usuario_id = u.id
         WHERE gm.grupo_id = ?`,
        [gr.grupo_id]
      );
      grupos.push({
        grupo_id: gr.grupo_id,
        grupo_nombre: gr.grupo_nombre,
        permiso: gr.permiso,
        miembros: m,
      });
    }

    res.json({
      success: true,
      miembros_directos: direct,
      grupos_vinculados: grupos,
    });
  } catch (error) {
    console.error("❌ Error listando miembros de terreno:", error.message);
    res
      .status(500)
      .json({ success: false, message: "Error interno del servidor" });
  }
});

app.post("/api/terrenos/:id/miembros", authenticateToken, async (req, res) => {
  try {
    const terrenoId = req.params.id;
    const { usuario_id, rol } = req.body;

    if (
      !(await isTerrenoOwner(req.user.id, terrenoId)) &&
      !(await userHasTerrenoWriteAccess(req.user.id, terrenoId))
    ) {
      return res.status(403).json({
        success: false,
        message: "No autorizado para agregar miembros al terreno",
      });
    }
    await pool.execute(
      "INSERT INTO terreno_miembro (terreno_id, usuario_id, rol) VALUES (?,?,?)",
      [terrenoId, usuario_id, rol || "viewer"]
    );
    res.json({ success: true });
  } catch (error) {
    console.error(
      "❌ Error agregando miembro directo al terreno:",
      error.message
    );
    if (error && error.code === "ER_DUP_ENTRY") {
      return res
        .status(400)
        .json({ success: false, message: "Usuario ya es miembro del terreno" });
    }
    res
      .status(500)
      .json({ success: false, message: "Error interno del servidor" });
  }
});

app.put(
  "/api/terrenos/:id/miembros/:usuarioId",
  authenticateToken,
  async (req, res) => {
    try {
      const terrenoId = req.params.id;
      const usuarioId = req.params.usuarioId;
      const { rol } = req.body;
      if (
        !(await isTerrenoOwner(req.user.id, terrenoId)) &&
        !(await userHasTerrenoWriteAccess(req.user.id, terrenoId))
      ) {
        return res
          .status(403)
          .json({ success: false, message: "No autorizado" });
      }
      await pool.execute(
        "UPDATE terreno_miembro SET rol=? WHERE terreno_id=? AND usuario_id=?",
        [rol, terrenoId, usuarioId]
      );
      res.json({ success: true });
    } catch (error) {
      console.error(
        "❌ Error actualizando rol de miembro directo:",
        error.message
      );
      res
        .status(500)
        .json({ success: false, message: "Error interno del servidor" });
    }
  }
);

app.delete(
  "/api/terrenos/:id/miembros/:usuarioId",
  authenticateToken,
  async (req, res) => {
    try {
      const terrenoId = req.params.id;
      const usuarioId = req.params.usuarioId;
      if (
        !(await isTerrenoOwner(req.user.id, terrenoId)) &&
        !(await userHasTerrenoWriteAccess(req.user.id, terrenoId))
      ) {
        return res
          .status(403)
          .json({ success: false, message: "No autorizado" });
      }
      await pool.execute(
        "DELETE FROM terreno_miembro WHERE terreno_id=? AND usuario_id=?",
        [terrenoId, usuarioId]
      );
      res.json({ success: true });
    } catch (error) {
      console.error("❌ Error eliminando miembro directo:", error.message);
      res
        .status(500)
        .json({ success: false, message: "Error interno del servidor" });
    }
  }
);

app.get("/api/grupos", authenticateToken, async (req, res) => {
  try {
    const [rows] = await pool.execute(
      `SELECT g.id, g.nombre, g.descripcion, g.creado_por, g.fecha_creacion, gm.rol
       FROM grupo g
       INNER JOIN grupo_miembro gm ON g.id = gm.grupo_id
       WHERE gm.usuario_id = ?`,
      [req.user.id]
    );
    res.json({ success: true, grupos: rows });
  } catch (error) {
    console.error("❌ Error obteniendo grupos:", error.message);
    res
      .status(500)
      .json({ success: false, message: "Error interno del servidor" });
  }
});

app.post("/api/grupos", authenticateToken, async (req, res) => {
  try {
    const { nombre, descripcion } = req.body;
    const [result] = await pool.execute(
      "INSERT INTO grupo (nombre, descripcion, creado_por, fecha_creacion) VALUES (?,?,?,NOW())",
      [nombre, descripcion || null, req.user.id]
    );
    await pool.execute(
      "INSERT INTO grupo_miembro (grupo_id, usuario_id, rol) VALUES (?,?,?)",
      [result.insertId, req.user.id, "admin"]
    );
    res.json({ success: true, id: result.insertId });
  } catch (error) {
    console.error("❌ Error creando grupo:", error.message);
    res
      .status(500)
      .json({ success: false, message: "Error interno del servidor" });
  }
});

app.get("/api/grupos/:id/miembros", authenticateToken, async (req, res) => {
  try {
    const grupoId = req.params.id;
    const [rows] = await pool.execute(
      `SELECT gm.usuario_id, gm.rol, u.nombre, u.apellido, gm.fecha_union
       FROM grupo_miembro gm
       LEFT JOIN usuario u ON gm.usuario_id = u.id
       WHERE gm.grupo_id = ?`,
      [grupoId]
    );
    res.json({ success: true, miembros: rows });
  } catch (error) {
    console.error("❌ Error listando miembros de grupo:", error.message);
    res
      .status(500)
      .json({ success: false, message: "Error interno del servidor" });
  }
});
app.post("/api/grupos/:id/miembros", authenticateToken, async (req, res) => {
  try {
    const grupoId = req.params.id;
    if (!(await isGrupoAdmin(req.user.id, grupoId))) {
      return res.status(403).json({
        success: false,
        message: "No autorizado (solo admin puede agregar miembros)",
      });
    }
    const { usuario_id, rol } = req.body;
    await pool.execute(
      "INSERT INTO grupo_miembro (grupo_id, usuario_id, rol) VALUES (?,?,?)",
      [grupoId, usuario_id, rol || "viewer"]
    );
    res.json({ success: true });
  } catch (error) {
    console.error("❌ Error agregando miembro al grupo:", error.message);
    if (error && error.code === "ER_DUP_ENTRY") {
      return res
        .status(400)
        .json({ success: false, message: "Usuario ya es miembro del grupo" });
    }
    res
      .status(500)
      .json({ success: false, message: "Error interno del servidor" });
  }
});

app.put(
  "/api/grupos/:id/miembros/:usuarioId",
  authenticateToken,
  async (req, res) => {
    try {
      const grupoId = req.params.id;
      if (!(await isGrupoAdmin(req.user.id, grupoId))) {
        return res
          .status(403)
          .json({ success: false, message: "No autorizado" });
      }
      const { rol } = req.body;
      await pool.execute(
        "UPDATE grupo_miembro SET rol=? WHERE grupo_id=? AND usuario_id=?",
        [rol, grupoId, req.params.usuarioId]
      );
      res.json({ success: true });
    } catch (error) {
      console.error("❌ Error actualizando rol en grupo:", error.message);
      res
        .status(500)
        .json({ success: false, message: "Error interno del servidor" });
    }
  }
);

app.delete(
  "/api/grupos/:id/miembros/:usuarioId",
  authenticateToken,
  async (req, res) => {
    try {
      const grupoId = req.params.id;
      if (!(await isGrupoAdmin(req.user.id, grupoId))) {
        return res
          .status(403)
          .json({ success: false, message: "No autorizado" });
      }
      await pool.execute(
        "DELETE FROM grupo_miembro WHERE grupo_id=? AND usuario_id=?",
        [grupoId, req.params.usuarioId]
      );
      res.json({ success: true });
    } catch (error) {
      console.error("❌ Error eliminando miembro de grupo:", error.message);
      res
        .status(500)
        .json({ success: false, message: "Error interno del servidor" });
    }
  }
);

app.get("/api/grupos/:id/terrenos", authenticateToken, async (req, res) => {
  try {
    const grupoId = req.params.id;
    const [rows] = await pool.execute(
      `SELECT gt.id, gt.terreno_id, gt.permiso, t.nombre AS terreno_nombre
       FROM grupo_terreno gt
       LEFT JOIN terreno t ON gt.terreno_id = t.id
       WHERE gt.grupo_id = ?`,
      [grupoId]
    );
    res.json({ success: true, terrenos: rows });
  } catch (error) {
    console.error("❌ Error listando terrenos vinculados:", error.message);
    res
      .status(500)
      .json({ success: false, message: "Error interno del servidor" });
  }
});

app.post("/api/grupos/:id/terrenos", authenticateToken, async (req, res) => {
  try {
    const grupoId = req.params.id;
    if (!(await isGrupoAdmin(req.user.id, grupoId))) {
      return res.status(403).json({ success: false, message: "No autorizado" });
    }
    const { terreno_id, permiso } = req.body;
    await pool.execute(
      "INSERT INTO grupo_terreno (grupo_id, terreno_id, permiso) VALUES (?,?,?)",
      [grupoId, terreno_id, permiso || "lectura"]
    );
    res.json({ success: true });
  } catch (error) {
    console.error("❌ Error vinculando terreno al grupo:", error.message);
    if (error && error.code === "ER_DUP_ENTRY") {
      return res
        .status(400)
        .json({ success: false, message: "Grupo ya vinculado a ese terreno" });
    }
    res
      .status(500)
      .json({ success: false, message: "Error interno del servidor" });
  }
});

app.delete(
  "/api/grupos/:id/terrenos/:terrenoId",
  authenticateToken,
  async (req, res) => {
    try {
      const grupoId = req.params.id;
      if (!(await isGrupoAdmin(req.user.id, grupoId))) {
        return res
          .status(403)
          .json({ success: false, message: "No autorizado" });
      }
      await pool.execute(
        "DELETE FROM grupo_terreno WHERE grupo_id=? AND terreno_id=?",
        [grupoId, req.params.terrenoId]
      );
      res.json({ success: true });
    } catch (error) {
      console.error("❌ Error desvinculando terreno:", error.message);
      res
        .status(500)
        .json({ success: false, message: "Error interno del servidor" });
    }
  }
);

app.get("/api/usuarios/buscar", authenticateToken, async (req, res) => {
  try {
    const q = (req.query.q || "").trim();
    if (!q) return res.json({ success: true, usuarios: [] });

    const like = `%${q}%`;
    const [rows] = await pool.query(
      `SELECT id, nombre, apellido, email 
       FROM usuario 
       WHERE (LOWER(email) LIKE LOWER(?) 
           OR LOWER(nombre) LIKE LOWER(?) 
           OR LOWER(apellido) LIKE LOWER(?))
         AND id <> ?
       LIMIT 30`,
      [like, like, like, req.user.id]
    );

    res.json({ success: true, usuarios: rows });
  } catch (err) {
    console.error("❌ Error en searchUsuario:", err.message);
    res
      .status(500)
      .json({ success: false, error: "Error interno del servidor" });
  }
});

app.get("/api/terrenos/:id/usuarios", authenticateToken, async (req, res) => {
  const { id } = req.params;
  try {
    const [rows] = await pool.query(
      `SELECT u.id, u.nombre, u.apellido, u.email, tm.rol, tm.fecha_union
       FROM terreno_miembro tm
       JOIN usuario u ON u.id = tm.usuario_id
       WHERE tm.terreno_id = ?`,
      [id]
    );
    res.json({ success: true, usuarios: rows });
  } catch (err) {
    console.error("❌ Error obteniendo usuarios del terreno:", err.message);
    res.status(500).json({ success: false, error: "Error en el servidor" });
  }
});
app.post("/api/terrenos/:id/usuarios", authenticateToken, async (req, res) => {
  const { id } = req.params;
  const { usuario_id, rol } = req.body;
  try {
    await pool.query(
      `INSERT INTO terreno_miembro (terreno_id, usuario_id, rol) VALUES (?, ?, ?)`,
      [id, usuario_id, rol || "viewer"]
    );
    res.json({ success: true, message: "Usuario agregado al terreno" });
  } catch (err) {
    console.error("❌ Error agregando usuario al terreno:", err.message);
    res.status(500).json({ success: false, error: "Error en el servidor" });
  }
});
app.put(
  "/api/terrenos/:id/usuarios/:usuarioId",
  authenticateToken,
  async (req, res) => {
    const { id, usuarioId } = req.params;
    const { rol } = req.body;
    try {
      await pool.query(
        `UPDATE terreno_miembro SET rol = ? WHERE terreno_id = ? AND usuario_id = ?`,
        [rol, id, usuarioId]
      );
      res.json({ success: true, message: "Rol actualizado" });
    } catch (err) {
      console.error("❌ Error actualizando rol:", err.message);
      res.status(500).json({ success: false, error: "Error en el servidor" });
    }
  }
);
app.delete(
  "/api/terrenos/:id/usuarios/:usuarioId",
  authenticateToken,
  async (req, res) => {
    const { id, usuarioId } = req.params;
    try {
      await pool.query(
        `DELETE FROM terreno_miembro WHERE terreno_id = ? AND usuario_id = ?`,
        [id, usuarioId]
      );
      res.json({ success: true, message: "Usuario eliminado del terreno" });
    } catch (err) {
      console.error("❌ Error eliminando usuario del terreno:", err.message);
      res.status(500).json({ success: false, error: "Error en el servidor" });
    }
  }
);

app.get("/api/sensores", authenticateToken, async (req, res) => {
  try {
    const userId = req.user.id;
    const query = `
      SELECT s.id, s.nombre, s.estado, s.tipo_sensor, s.valor_minimo, s.valor_maximo, s.fecha_creacion, s.terreno_id
      FROM sensor s
      INNER JOIN terreno t ON s.terreno_id = t.id
      WHERE t.propietario_id = ?
    `;
    const [rows] = await pool.execute(query, [userId]);
    res.json({ success: true, sensores: rows });
  } catch (error) {
    console.error("❌ Error obteniendo sensores:", error.message);
    res
      .status(500)
      .json({ success: false, message: "Error interno del servidor" });
  }
});

app.get("/api/sensores/:id/datos", authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;
    const { desde, hasta, limite } = req.query;
    let query = `SELECT d.id, d.fecha_hora, d.valor FROM datos_sensores d WHERE d.sensor_id = ?`;
    const params = [id];
    if (desde) {
      query += " AND d.fecha_hora >= ?";
      params.push(desde);
    }
    if (hasta) {
      query += " AND d.fecha_hora <= ?";
      params.push(hasta);
    }
    query += " ORDER BY d.fecha_hora DESC";
    const limitValue = limite ? parseInt(limite) : 100;
    query += " LIMIT ?";
    params.push(limitValue);
    const [rows] = await pool.execute(query, params);
    res.json({ success: true, datos: rows });
  } catch (error) {
    console.error("❌ Error obteniendo datos del sensor:", error.message);
    res
      .status(500)
      .json({ success: false, message: "Error interno del servidor" });
  }
});

app.post("/api/sensores", authenticateToken, async (req, res) => {
  try {
    const userId = req.user.id;
    const { nombre, tipo_sensor, terreno_id, valor_minimo, valor_maximo } =
      req.body;
    if (!nombre || !tipo_sensor || !terreno_id) {
      return res
        .status(400)
        .json({ success: false, message: "Nombre, tipo y terreno requeridos" });
    }
    if (!(await userHasTerrenoWriteAccess(userId, terreno_id))) {
      return res.status(403).json({
        success: false,
        message: "No autorizado para agregar sensores en este terreno",
      });
    }
    const sql = `INSERT INTO sensor (nombre, tipo_sensor, terreno_id, valor_minimo, valor_maximo, estado, fecha_creacion) 
                 VALUES (?, ?, ?, ?, ?, 'inactivo', NOW())`;
    await pool.execute(sql, [
      nombre,
      tipo_sensor,
      terreno_id,
      valor_minimo || null,
      valor_maximo || null,
    ]);
    res.json({ success: true, message: "Sensor agregado correctamente" });
  } catch (error) {
    console.error("❌ Error agregando sensor:", error.message);
    res
      .status(500)
      .json({ success: false, message: "Error interno del servidor" });
  }
});

app.put("/api/sensores/:id", authenticateToken, async (req, res) => {
  try {
    const sensorId = req.params.id;
    const {
      nombre,
      tipo_sensor,
      terreno_id,
      valor_minimo,
      valor_maximo,
      estado,
    } = req.body;
    const [srows] = await pool.execute(
      "SELECT terreno_id FROM sensor WHERE id = ? LIMIT 1",
      [sensorId]
    );
    if (!srows.length)
      return res
        .status(404)
        .json({ success: false, message: "Sensor no encontrado" });
    const currentTerreno = srows[0].terreno_id;
    const checkTerreno = terreno_id || currentTerreno;
    if (!(await userHasTerrenoWriteAccess(req.user.id, checkTerreno))) {
      return res.status(403).json({
        success: false,
        message: "No autorizado para editar este sensor",
      });
    }
    const updates = [];
    const params = [];
    if (nombre !== undefined) {
      updates.push("nombre = ?");
      params.push(nombre);
    }
    if (tipo_sensor !== undefined) {
      updates.push("tipo_sensor = ?");
      params.push(tipo_sensor);
    }
    if (terreno_id !== undefined) {
      updates.push("terreno_id = ?");
      params.push(terreno_id);
    }
    if (valor_minimo !== undefined) {
      updates.push("valor_minimo = ?");
      params.push(valor_minimo);
    }
    if (valor_maximo !== undefined) {
      updates.push("valor_maximo = ?");
      params.push(valor_maximo);
    }
    if (estado !== undefined) {
      updates.push("estado = ?");
      params.push(estado);
    }
    if (updates.length === 0)
      return res.status(400).json({
        success: false,
        message: "No se enviaron campos para actualizar",
      });
    const sql = `UPDATE sensor SET ${updates.join(", ")} WHERE id = ?`;
    params.push(sensorId);
    const [result] = await pool.execute(sql, params);
    if (result.affectedRows === 0)
      return res
        .status(404)
        .json({ success: false, message: "Sensor no encontrado" });
    res.json({ success: true, message: "Sensor modificado correctamente" });
  } catch (error) {
    console.error("❌ Error modificando sensor:", error.message);
    res
      .status(500)
      .json({ success: false, message: "Error interno del servidor" });
  }
});

app.delete("/api/sensores/:id", authenticateToken, async (req, res) => {
  try {
    const sensorId = req.params.id;
    const [rows] = await pool.execute(
      "SELECT terreno_id FROM sensor WHERE id = ? LIMIT 1",
      [sensorId]
    );
    if (!rows.length)
      return res
        .status(404)
        .json({ success: false, message: "Sensor no encontrado" });
    const terrenoId = rows[0].terreno_id;
    if (!(await userHasTerrenoWriteAccess(req.user.id, terrenoId))) {
      return res.status(403).json({
        success: false,
        message: "No autorizado para eliminar este sensor",
      });
    }
    const [result] = await pool.execute("DELETE FROM sensor WHERE id = ?", [
      sensorId,
    ]);
    if (result.affectedRows === 0)
      return res
        .status(404)
        .json({ success: false, message: "Sensor no encontrado" });
    res.json({ success: true, message: "Sensor eliminado correctamente" });
  } catch (error) {
    console.error("❌ Error eliminando sensor:", error.message);
    res
      .status(500)
      .json({ success: false, message: "Error interno del servidor" });
  }
});

app.post("/api/sensores/:id/datos", async (req, res) => {
  try {
    const { id } = req.params;
    const { valor } = req.body;
    if (valor === undefined)
      return res
        .status(400)
        .json({ success: false, message: "Valor requerido" });

    const [last] = await pool.execute(
      "SELECT valor FROM datos_sensores WHERE sensor_id = ? ORDER BY fecha_hora DESC LIMIT 1",
      [id]
    );
    if (last.length > 0 && parseFloat(last[0].valor) === parseFloat(valor)) {
      console.log(`ℹ️ Sensor ${id}: valor repetido (${valor}), no insertado`);
      return res.json({
        success: true,
        message: "Dato idéntico al último, no se insertó",
      });
    }

    const [result] = await pool.execute(
      "INSERT INTO datos_sensores (fecha_hora, valor, sensor_id) VALUES (NOW(), ?, ?)",
      [valor, id]
    );

    await pool.execute("UPDATE sensor SET estado = 'activo' WHERE id = ?", [
      id,
    ]);

    console.log(`✅ Sensor ${id}: dato insertado (${valor})`);
    res.json({
      success: true,
      message: "Dato insertado correctamente",
      id: result.insertId,
    });
  } catch (error) {
    console.error("❌ Error insertando dato de sensor:", error.message);
    res
      .status(500)
      .json({ success: false, message: "Error interno del servidor" });
  }
});

app.get("/api/usuario/sensores-datos", authenticateToken, async (req, res) => {
  try {
    const userId = req.user.id;
    const query = `
      SELECT s.id AS sensor_id, s.nombre AS sensor, s.estado, s.tipo_sensor,
             d.id AS dato_id, d.valor, d.fecha_hora,
             t.id AS terreno_id, t.nombre AS terreno
      FROM sensor s
      INNER JOIN terreno t ON s.terreno_id = t.id
      LEFT JOIN datos_sensores d ON s.id = d.sensor_id
      WHERE t.propietario_id = ?
      ORDER BY s.id, d.fecha_hora DESC
    `;
    const [rows] = await pool.execute(query, [userId]);
    res.json({ success: true, sensores: rows });
  } catch (error) {
    console.error("❌ Error obteniendo sensores con datos:", error.message);
    res
      .status(500)
      .json({ success: false, message: "Error interno del servidor" });
  }
});

app.post("/api/chats", authenticateToken, async (req, res) => {
  const { userId, nombre, tipo, participantes = [] } = req.body;
  const userActualId = req.user.id;

  console.log("🆕 POST /api/chats - Datos:", {
    userId,
    nombre,
    tipo,
    participantes,
    userActualId,
  });

  try {
    if (userId) {
      console.log(
        "🔍 Verificando chat directo existente entre",
        userActualId,
        "y",
        userId
      );

      const [existente] = await pool.query(
        `SELECT cr.id, cr.tipo, cr.titulo, cr.creado_por, cr.fecha_creacion
         FROM chat_room cr
         JOIN chat_participante cp1 ON cp1.room_id = cr.id
         JOIN chat_participante cp2 ON cp2.room_id = cr.id
         WHERE cp1.usuario_id = ? AND cp2.usuario_id = ? AND cr.tipo = 'directo'
         LIMIT 1`,
        [userActualId, userId]
      );

      if (existente.length > 0) {
        console.log("✅ Chat directo ya existe:", existente[0].id);

        const [[otroUsuario]] = await pool.query(
          "SELECT id, nombre, apellido FROM usuario WHERE id = ?",
          [userId]
        );

        return res.json({
          chat: {
            id: existente[0].id,
            nombre: existente[0].titulo || "Chat Directo",
            titulo: existente[0].titulo || "Chat Directo",
            tipo: existente[0].tipo,
            creado_por: existente[0].creado_por,
            fecha_creacion: existente[0].fecha_creacion,
            otro_usuario: otroUsuario,
          },
          yaExistia: true,
        });
      }

      console.log("➡️ No existe, creando nuevo chat directo");
    }

    const tipoChat = tipo || (userId ? "directo" : "grupo");
    const nombreChat = nombre || (userId ? "Chat Directo" : "Nuevo Grupo");

    console.log("📝 Insertando chat_room:", {
      tipoChat,
      userActualId,
      nombreChat,
    });

    const [result] = await pool.query(
      "INSERT INTO chat_room (tipo, creado_por, titulo, fecha_creacion) VALUES (?, ?, ?, NOW())",
      [tipoChat, userActualId, nombreChat]
    );
    const roomId = result.insertId;

    console.log("✅ chat_room creado con ID:", roomId);

    console.log("➕ Agregando usuario actual como admin");
    await pool.query(
      "INSERT INTO chat_participante (room_id, usuario_id, rol, fecha_union) VALUES (?, ?, 'admin', NOW())",
      [roomId, userActualId]
    );

    if (userId) {
      console.log("➕ Agregando usuario destino:", userId);
      await pool.query(
        "INSERT INTO chat_participante (room_id, usuario_id, rol, fecha_union) VALUES (?, ?, 'miembro', NOW())",
        [roomId, userId]
      );

      const [[otroUsuario]] = await pool.query(
        "SELECT id, nombre, apellido FROM usuario WHERE id = ?",
        [userId]
      );

      const chatCreado = {
        id: roomId,
        nombre: nombreChat,
        titulo: nombreChat,
        tipo: tipoChat,
        creado_por: userActualId,
        fecha_creacion: new Date(),
        otro_usuario: otroUsuario,
      };

      console.log("✅ Chat directo creado:", chatCreado);
      return res.json({ chat: chatCreado });
    }

    if (tipoChat === "grupo" && participantes.length > 0) {
      console.log(
        "➕ Agregando",
        participantes.length,
        "participantes al grupo"
      );
      for (const pId of participantes) {
        await pool.query(
          "INSERT INTO chat_participante (room_id, usuario_id, rol, fecha_union) VALUES (?, ?, 'miembro', NOW())",
          [roomId, pId]
        );
      }
    }

    const chatCreado = {
      id: roomId,
      nombre: nombreChat,
      titulo: nombreChat,
      tipo: tipoChat,
      creado_por: userActualId,
      fecha_creacion: new Date(),
    };

    console.log("✅ Chat creado exitosamente:", chatCreado);
    res.json({ chat: chatCreado });
  } catch (err) {
    console.error("❌ Error al crear chat:", err);
    console.error("❌ Stack:", err.stack);
    res.status(500).json({
      error: "Error al crear chat",
      details: err.message,
    });
  }
});

app.get("/api/chats", authenticateToken, async (req, res) => {
  const userActualId = req.user.id;

  console.log("📋 GET /api/chats - Usuario:", userActualId);

  try {
    const [chats] = await pool.query(
      `SELECT cr.id, cr.tipo, cr.titulo as nombre, cr.creado_por, cr.fecha_creacion
       FROM chat_room cr
       JOIN chat_participante cp ON cp.room_id = cr.id
       WHERE cp.usuario_id = ?
       ORDER BY cr.id DESC`,
      [userActualId]
    );

    for (let chat of chats) {
      if (chat.tipo === "directo") {
        const [participantes] = await pool.query(
          `SELECT u.id, u.nombre, u.apellido 
           FROM chat_participante cp
           JOIN usuario u ON cp.usuario_id = u.id
           WHERE cp.room_id = ? AND cp.usuario_id != ?`,
          [chat.id, userActualId]
        );

        if (participantes.length > 0) {
          chat.otro_usuario = participantes[0];
        }
      }
    }

    console.log(`✅ ${chats.length} chats encontrados`);
    res.json({ chats });
  } catch (err) {
    console.error("❌ Error al obtener chats:", err);
    res
      .status(500)
      .json({ error: "Error al obtener chats", details: err.message });
  }
});

app.put("/api/chats/:id", authenticateToken, async (req, res) => {
  const { nombre } = req.body;
  const { id } = req.params;
  const userActualId = req.user.id;

  console.log("✏️ PUT /api/chats/:id - Editando:", {
    id,
    nombre,
    userActualId,
  });

  try {
    const [check] = await pool.query(
      "SELECT * FROM chat_room WHERE id = ? AND creado_por = ?",
      [id, userActualId]
    );

    if (check.length === 0) {
      console.log("⚠️ Sin permisos");
      return res.status(403).json({ error: "Sin permisos" });
    }

    await pool.query("UPDATE chat_room SET titulo = ? WHERE id = ?", [
      nombre,
      id,
    ]);
    console.log("✅ Chat actualizado");
    res.json({ success: true });
  } catch (err) {
    console.error("❌ Error al editar chat:", err);
    res.status(500).json({ error: "Error al editar chat" });
  }
});

app.delete("/api/chats/:id", authenticateToken, async (req, res) => {
  const { id } = req.params;
  const userActualId = req.user.id;

  console.log("🗑️ DELETE /api/chats/:id - Eliminando:", { id, userActualId });

  try {
    const [chatInfo] = await pool.query(
      "SELECT tipo, creado_por FROM chat_room WHERE id = ?",
      [id]
    );

    if (chatInfo.length === 0) {
      return res.status(404).json({ error: "Chat no encontrado" });
    }

    const chat = chatInfo[0];

    if (chat.tipo === "grupo" && chat.creado_por !== userActualId) {
      console.log("⚠️ Sin permisos - Solo el creador puede eliminar el grupo");
      return res
        .status(403)
        .json({ error: "Solo el creador puede eliminar el grupo" });
    }

    if (chat.tipo === "directo") {
      const [permiso] = await pool.query(
        "SELECT * FROM chat_participante WHERE room_id = ? AND usuario_id = ?",
        [id, userActualId]
      );

      if (permiso.length === 0) {
        return res.status(403).json({ error: "No eres parte de este chat" });
      }

      await pool.query(
        "DELETE FROM chat_participante WHERE room_id = ? AND usuario_id = ?",
        [id, userActualId]
      );

      const [remaining] = await pool.query(
        "SELECT COUNT(*) as count FROM chat_participante WHERE room_id = ?",
        [id]
      );

      if (remaining[0].count === 0) {
        await pool.query("DELETE FROM chat_room WHERE id = ?", [id]);
      }

      console.log("✅ Participación eliminada del chat directo");
      return res.json({ success: true, message: "Chat eliminado para ti" });
    }

    await pool.query("DELETE FROM chat_room WHERE id = ?", [id]);
    console.log("✅ Grupo eliminado completamente");
    res.json({ success: true, message: "Grupo eliminado" });
  } catch (err) {
    console.error("❌ Error al eliminar chat:", err);
    res.status(500).json({ error: "Error al eliminar chat" });
  }
});

app.get("/api/chats/:id/mensajes", authenticateToken, async (req, res) => {
  const { id } = req.params;
  const userActualId = req.user.id;

  console.log(
    "📩 GET /api/chats/:id/mensajes - Chat:",
    id,
    "Usuario:",
    userActualId
  );

  try {
    const [permiso] = await pool.query(
      "SELECT * FROM chat_participante WHERE room_id = ? AND usuario_id = ?",
      [id, userActualId]
    );

    if (permiso.length === 0) {
      console.log("⚠️ No autorizado");
      return res.status(403).json({ error: "No autorizado" });
    }

    const [mensajes] = await pool.query(
      `SELECT cm.id, cm.room_id as chat_id, cm.autor_id as remitente_id, 
              cm.contenido, cm.leido, cm.fecha_envio,
              u.nombre AS remitente_nombre, u.apellido AS remitente_apellido
       FROM chat_mensaje cm
       LEFT JOIN usuario u ON u.id = cm.autor_id
       WHERE cm.room_id = ?
       ORDER BY cm.fecha_envio ASC`,
      [id]
    );

    console.log(`✅ ${mensajes.length} mensajes encontrados`);
    res.json({ mensajes });
  } catch (err) {
    console.error("❌ Error al obtener mensajes:", err);
    res.status(500).json({ error: "Error al obtener mensajes" });
  }
});

app.get("/api/chats/:id/participantes", authenticateToken, async (req, res) => {
  const { id } = req.params;
  const userActualId = req.user.id;

  console.log(
    "👥 GET /api/chats/:id/participantes - Chat:",
    id,
    "Usuario:",
    userActualId
  );

  try {
    const [permiso] = await pool.query(
      "SELECT * FROM chat_participante WHERE room_id = ? AND usuario_id = ?",
      [id, userActualId]
    );

    if (permiso.length === 0) {
      console.log("⚠️ No autorizado - Usuario no es parte del chat");
      return res.status(403).json({ error: "No autorizado" });
    }

    console.log("✅ Usuario autorizado, buscando participantes...");

    const [participantes] = await pool.query(
      `SELECT cp.usuario_id, cp.rol, cp.fecha_union,
              u.nombre, u.apellido, u.email
       FROM chat_participante cp
       LEFT JOIN usuario u ON cp.usuario_id = u.id
       WHERE cp.room_id = ?
       ORDER BY cp.rol DESC, u.nombre ASC`,
      [id]
    );

    console.log(
      `✅ ${participantes.length} participantes encontrados:`,
      participantes
    );
    res.json({ success: true, participantes });
  } catch (err) {
    console.error("❌ Error al obtener participantes:", err);
    console.error("❌ Stack:", err.stack);
    res
      .status(500)
      .json({ error: "Error al obtener participantes", details: err.message });
  }
});

app.post(
  "/api/chats/:id/participantes",
  authenticateToken,
  async (req, res) => {
    const { id } = req.params;
    const { usuario_id } = req.body;
    const userActualId = req.user.id;

    console.log("➕ POST /api/chats/:id/participantes:", {
      id,
      usuario_id,
      userActualId,
    });

    try {
      const [checkAdmin] = await pool.query(
        "SELECT rol FROM chat_participante WHERE room_id = ? AND usuario_id = ?",
        [id, userActualId]
      );

      if (checkAdmin.length === 0 || checkAdmin[0].rol !== "admin") {
        console.log("⚠️ Sin permisos - Solo admins pueden agregar");
        return res
          .status(403)
          .json({ error: "Solo admins pueden agregar participantes" });
      }

      const [existe] = await pool.query(
        "SELECT id FROM chat_participante WHERE room_id = ? AND usuario_id = ?",
        [id, usuario_id]
      );

      if (existe.length > 0) {
        return res.status(400).json({ error: "El usuario ya es participante" });
      }

      await pool.query(
        "INSERT INTO chat_participante (room_id, usuario_id, rol, fecha_union) VALUES (?, ?, 'miembro', NOW())",
        [id, usuario_id]
      );

      console.log("✅ Participante agregado");
      res.json({ success: true });
    } catch (err) {
      console.error("❌ Error al agregar participante:", err);
      if (err.code === "ER_DUP_ENTRY") {
        return res.status(400).json({ error: "El usuario ya es participante" });
      }
      res.status(500).json({ error: "Error al agregar participante" });
    }
  }
);

app.put(
  "/api/chats/:id/participantes/:usuarioId",
  authenticateToken,
  async (req, res) => {
    const { id, usuarioId } = req.params;
    const { rol } = req.body;
    const userActualId = req.user.id;

    console.log("🔄 PUT /api/chats/:id/participantes/:usuarioId:", {
      id,
      usuarioId,
      rol,
      userActualId,
    });

    try {
      const [checkAdmin] = await pool.query(
        "SELECT rol FROM chat_participante WHERE room_id = ? AND usuario_id = ?",
        [id, userActualId]
      );

      if (checkAdmin.length === 0 || checkAdmin[0].rol !== "admin") {
        console.log("⚠️ Sin permisos - Solo admins pueden cambiar roles");
        return res
          .status(403)
          .json({ error: "Solo admins pueden cambiar roles" });
      }

      const [checkCreador] = await pool.query(
        "SELECT creado_por FROM chat_room WHERE id = ?",
        [id]
      );

      if (checkCreador.length > 0 && checkCreador[0].creado_por == usuarioId) {
        return res
          .status(400)
          .json({ error: "No puedes cambiar el rol del creador del grupo" });
      }

      await pool.query(
        "UPDATE chat_participante SET rol = ? WHERE room_id = ? AND usuario_id = ?",
        [rol, id, usuarioId]
      );

      console.log("✅ Rol actualizado");
      res.json({ success: true });
    } catch (err) {
      console.error("❌ Error al cambiar rol:", err);
      res.status(500).json({ error: "Error al cambiar rol" });
    }
  }
);

app.delete(
  "/api/chats/:id/mensajes/:messageId",
  authenticateToken,
  async (req, res) => {
    const { id, messageId } = req.params;
    const userActualId = req.user.id;

    console.log("🗑️ DELETE /api/chats/:id/mensajes/:messageId:", {
      id,
      messageId,
      userActualId,
    });

    try {
      const [mensaje] = await pool.query(
        "SELECT autor_id FROM chat_mensaje WHERE id = ? AND room_id = ?",
        [messageId, id]
      );

      if (mensaje.length === 0) {
        return res.status(404).json({ error: "Mensaje no encontrado" });
      }

      if (mensaje[0].autor_id !== userActualId) {
        return res
          .status(403)
          .json({ error: "Solo puedes eliminar tus propios mensajes" });
      }

      await pool.query("DELETE FROM chat_mensaje WHERE id = ?", [messageId]);

      console.log("✅ Mensaje eliminado");

      io.emit("messageDeleted", {
        chat_id: parseInt(id),
        message_id: parseInt(messageId),
      });

      res.json({ success: true });
    } catch (err) {
      console.error("❌ Error al eliminar mensaje:", err);
      res.status(500).json({ error: "Error al eliminar mensaje" });
    }
  }
);

app.delete(
  "/api/chats/:id/participantes/:usuarioId",
  authenticateToken,
  async (req, res) => {
    const { id, usuarioId } = req.params;
    const userActualId = req.user.id;

    console.log("➖ DELETE /api/chats/:id/participantes/:usuarioId:", {
      id,
      usuarioId,
      userActualId,
    });

    try {
      const [checkAdmin] = await pool.query(
        "SELECT rol FROM chat_participante WHERE room_id = ? AND usuario_id = ?",
        [id, userActualId]
      );

      if (checkAdmin.length === 0 || checkAdmin[0].rol !== "admin") {
        console.log("⚠️ Sin permisos - Solo admins pueden eliminar");
        return res
          .status(403)
          .json({ error: "Solo admins pueden eliminar participantes" });
      }

      const [checkCreador] = await pool.query(
        "SELECT creado_por FROM chat_room WHERE id = ?",
        [id]
      );

      if (checkCreador.length > 0 && checkCreador[0].creado_por == usuarioId) {
        return res
          .status(400)
          .json({ error: "No puedes eliminar al creador del grupo" });
      }

      await pool.query(
        "DELETE FROM chat_participante WHERE room_id = ? AND usuario_id = ?",
        [id, usuarioId]
      );

      console.log("✅ Participante eliminado");
      res.json({ success: true });
    } catch (err) {
      console.error("❌ Error al eliminar participante:", err);
      res.status(500).json({ error: "Error al eliminar participante" });
    }
  }
);

io.on("connection", (socket) => {
  console.log(
    "🟢 Cliente conectado - Socket:",
    socket.id,
    "Usuario:",
    socket.user?.id
  );

  socket.on("sendMessage", async (data) => {
    try {
      const { chat_id, content } = data;
      const remitente_id = socket.user?.id;

      console.log("📤 sendMessage:", { chat_id, content, remitente_id });

      if (!remitente_id || !chat_id || !content) {
        console.log("⚠️ Datos incompletos");
        return;
      }

      const [permiso] = await pool.query(
        "SELECT * FROM chat_participante WHERE room_id = ? AND usuario_id = ?",
        [chat_id, remitente_id]
      );

      if (permiso.length === 0) {
        console.log("⚠️ No autorizado");
        return;
      }

      const [result] = await pool.query(
        "INSERT INTO chat_mensaje (room_id, autor_id, contenido, leido, fecha_envio) VALUES (?, ?, ?, 0, NOW())",
        [chat_id, remitente_id, content]
      );

      console.log("✅ Mensaje insertado ID:", result.insertId);

      const [[usuario]] = await pool.query(
        "SELECT nombre, apellido FROM usuario WHERE id = ?",
        [remitente_id]
      );

      const nuevoMensaje = {
        id: result.insertId,
        chat_id: parseInt(chat_id),
        remitente_id: parseInt(remitente_id),
        contenido: content,
        content: content,
        fecha_envio: new Date(),
        remitente_nombre: usuario?.nombre || "Usuario",
        remitente_apellido: usuario?.apellido || "",
      };

      console.log("📡 Emitiendo mensaje:", nuevoMensaje.id);
      io.emit("receiveMessage", nuevoMensaje);
    } catch (err) {
      console.error("❌ Error en sendMessage:", err);
      console.error("❌ Stack:", err.stack);
    }
  });

  socket.on("typing", async (data) => {
    try {
      const { chatId } = data;
      const userId = socket.user?.id;

      if (chatId && userId) {
        socket.broadcast.emit("userTyping", { chatId, userId });
      }
    } catch (err) {
      console.error("❌ Error en typing:", err);
    }
  });

  socket.on("disconnect", () => {
    console.log("🔴 Cliente desconectado - Socket:", socket.id);
  });
});

setInterval(async () => {
  try {
    await pool.execute(`
      UPDATE sensor s
      LEFT JOIN (
        SELECT sensor_id, MAX(fecha_hora) AS ultima
        FROM datos_sensores
        GROUP BY sensor_id
      ) d ON s.id = d.sensor_id
      SET s.estado = 'inactivo'
      WHERE (d.ultima IS NULL OR d.ultima < (NOW() - INTERVAL 2 MINUTE));
    `);

    await pool.execute(`
      UPDATE sensor s
      INNER JOIN (
        SELECT sensor_id, MAX(fecha_hora) AS ultima
        FROM datos_sensores
        GROUP BY sensor_id
      ) d ON s.id = d.sensor_id
      SET s.estado = 'activo'
      WHERE d.ultima >= (NOW() - INTERVAL 2 MINUTE);
    `);
  } catch (error) {
    console.error("❌ Error actualizando estado de sensores:", error.message);
  }
}, 60000);

export { pool };

const PORT = process.env.PORT || 5000;
server.listen(PORT, "0.0.0.0", () => {
  console.log(`✅ Servidor corriendo en http://localhost:${PORT}`);
});

process.on("SIGINT", async () => {
  console.log("\n Cerrando servidor...");
  await pool.end();
  console.log("✅ Conexiones cerradas");
  process.exit(0);
});
