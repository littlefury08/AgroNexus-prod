import express from "express";
import mysql from "mysql2/promise";
import cors from "cors";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import dotenv from "dotenv";
import chatRoutes from "./routes/chat.js";
import { Server } from "socket.io";
import http from "http";
import path from "path";
import multer from "multer";

dotenv.config();

const app = express();
app.use(cors());
app.use(express.json());

app.use("/api", chatRoutes);

const JWT_SECRET = process.env.JWT_SECRET || "claveultrasecreeta123";
const JWT_EXPIRES = process.env.JWT_EXPIRES || "2h";

const dbConfig = {
  host: "localhost",
  user: "root",
  password: "",
  database: "agronexus",
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
    origin: "http://localhost:3000",
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

async function getChatRoom(chatId) {
  const [rows] = await pool.execute(
    "SELECT * FROM chat_room WHERE id = ? LIMIT 1",
    [chatId]
  );
  return rows.length ? rows[0] : null;
}

async function isChatAdmin(userId, chatId) {
  const room = await getChatRoom(chatId);
  if (!room) return false;
  if (room.creado_por === userId) return true;
  if (room.tipo === "grupo" && room.grupo_id) {
    return await isGrupoAdmin(userId, room.grupo_id);
  }
  if (room.tipo === "terreno" && room.terreno_id) {
    return await isTerrenoOwner(userId, room.terreno_id);
  }
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

app.post("/api/chats", authenticateToken, async (req, res) => {
  try {
    console.log("📥 Body recibido en /api/chats:", req.body);

    const { tipo, participantes, titulo } = req.body;

    if (!tipo) {
      return res.status(400).json({
        success: false,
        error: "El campo 'tipo' es obligatorio (directo o grupo)",
      });
    }

    if (!Array.isArray(participantes)) {
      return res.status(400).json({
        success: false,
        error: "El campo 'participantes' debe ser un array con IDs de usuarios",
      });
    }

    if (participantes.length < 1) {
      return res.status(400).json({
        success: false,
        error: "Debe incluir al menos un participante",
      });
    }

    if (tipo === "directo" && participantes.includes(req.user.id)) {
      return res.status(400).json({
        success: false,
        error: "No puedes crear un chat directo contigo mismo",
      });
    }

    if (tipo === "directo" && participantes.length === 1) {
      const otroId = participantes[0];

      const [rows] = await pool.query(
        `SELECT c.id 
         FROM chat c
         JOIN chat_miembro cm1 ON c.id = cm1.chat_id
         JOIN chat_miembro cm2 ON c.id = cm2.chat_id
         WHERE c.tipo = 'directo'
           AND cm1.usuario_id = ?
           AND cm2.usuario_id = ?`,
        [req.user.id, otroId]
      );

      if (rows.length > 0) {
        return res.json({
          success: true,
          chat: { id: rows[0].id, tipo: "directo" },
          duplicated: true,
        });
      }
    }

    const [result] = await pool.query(
      "INSERT INTO chat (tipo, titulo, creado_por) VALUES (?, ?, ?)",
      [tipo, titulo || null, req.user.id]
    );

    const chatId = result.insertId;

    const miembros = [req.user.id, ...participantes];
    for (const uid of miembros) {
      await pool.query(
        "INSERT INTO chat_miembro (chat_id, usuario_id) VALUES (?, ?)",
        [chatId, uid]
      );
    }

    res.json({
      success: true,
      chat: { id: chatId, tipo, titulo },
      duplicated: false,
    });
  } catch (err) {
    console.error("❌ Error creando chat:", err.message);
    res
      .status(500)
      .json({ success: false, error: "Error interno del servidor" });
  }
});

app.post("/api/chats", authenticateToken, async (req, res) => {
  try {
    const { tipo, titulo, grupo_id, terreno_id, participantes } = req.body;
    const [result] = await pool.execute(
      "INSERT INTO chat_room (tipo, grupo_id, terreno_id, creado_por, titulo, fecha_creacion) VALUES (?,?,?,?,?,NOW())",
      [tipo, grupo_id || null, terreno_id || null, req.user.id, titulo || null]
    );
    const roomId = result.insertId;

    const toInsert = new Set();

    toInsert.add(req.user.id);

    if (tipo === "grupo" && grupo_id) {
      const [members] = await pool.execute(
        "SELECT usuario_id FROM grupo_miembro WHERE grupo_id = ?",
        [grupo_id]
      );
      members.forEach((m) => toInsert.add(m.usuario_id));
    } else if (tipo === "terreno" && terreno_id) {
      const [t] = await pool.execute(
        "SELECT propietario_id FROM terreno WHERE id = ? LIMIT 1",
        [terreno_id]
      );
      if (t.length) toInsert.add(t[0].propietario_id);

      const [direct] = await pool.execute(
        "SELECT usuario_id FROM terreno_miembro WHERE terreno_id = ?",
        [terreno_id]
      );
      direct.forEach((d) => toInsert.add(d.usuario_id));

      const [grupos] = await pool.execute(
        "SELECT grupo_id FROM grupo_terreno WHERE terreno_id = ?",
        [terreno_id]
      );
      for (const g of grupos) {
        const [m] = await pool.execute(
          "SELECT usuario_id FROM grupo_miembro WHERE grupo_id = ?",
          [g.grupo_id]
        );
        m.forEach((x) => toInsert.add(x.usuario_id));
      }
    } else if (tipo === "directo" && Array.isArray(participantes)) {
      participantes.forEach((p) => toInsert.add(p));
    }

    const inserts = [];
    for (const uid of toInsert) inserts.push([roomId, uid, new Date()]);
    if (inserts.length) {
      await pool.query(
        "INSERT INTO chat_participante (room_id, usuario_id, fecha_union) VALUES ?",
        [inserts]
      );
    }
  } catch (error) {
    console.error("❌ Error creando chat:", error.message);
    try {
      res
        .status(500)
        .json({ success: false, message: "Error interno creando chat" });
    } catch (e) {
      console.error(e);
      res
        .status(500)
        .json({ success: false, message: "Error interno creando chat" });
    }
  }
});

app.get("/api/chats/:id/participantes", authenticateToken, async (req, res) => {
  try {
    const roomId = req.params.id;
    const [rows] = await pool.execute(
      `SELECT cp.usuario_id, u.nombre, u.apellido, cp.fecha_union
       FROM chat_participante cp
       LEFT JOIN usuario u ON cp.usuario_id = u.id
       WHERE cp.room_id = ?`,
      [roomId]
    );
    res.json({ success: true, participantes: rows });
  } catch (error) {
    console.error("❌ Error listando participantes:", error.message);
    res
      .status(500)
      .json({ success: false, message: "Error interno del servidor" });
  }
});

app.post(
  "/api/chats/:id/participantes",
  authenticateToken,
  async (req, res) => {
    try {
      const roomId = req.params.id;
      if (!(await isChatAdmin(req.user.id, roomId)))
        return res
          .status(403)
          .json({ success: false, message: "No autorizado" });
      const { usuario_id } = req.body;
      await pool.execute(
        "INSERT INTO chat_participante (room_id, usuario_id, fecha_union) VALUES (?,?,NOW())",
        [roomId, usuario_id]
      );
      res.json({ success: true });
    } catch (error) {
      console.error("❌ Error agregando participante:", error.message);
      if (error && error.code === "ER_DUP_ENTRY")
        return res
          .status(400)
          .json({ success: false, message: "Usuario ya es participante" });
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
app.delete(
  "/api/chats/:id/participantes/:usuarioId",
  authenticateToken,
  async (req, res) => {
    try {
      const roomId = req.params.id;
      if (!(await isChatAdmin(req.user.id, roomId)))
        return res
          .status(403)
          .json({ success: false, message: "No autorizado" });
      await pool.execute(
        "DELETE FROM chat_participante WHERE room_id=? AND usuario_id=?",
        [roomId, req.params.usuarioId]
      );
      res.json({ success: true });
    } catch (error) {
      console.error(
        "❌ Error eliminando participante del chat:",
        error.message
      );
      res
        .status(500)
        .json({ success: false, message: "Error interno del servidor" });
    }
  }
);
app.get("/api/chats/:id/mensajes", authenticateToken, async (req, res) => {
  try {
    const [rows] = await pool.execute(
      `SELECT cm.id, cm.contenido, cm.fecha_envio, u.id as autor_id, u.nombre, u.apellido
       FROM chat_mensaje cm
       LEFT JOIN usuario u ON cm.autor_id = u.id
       WHERE cm.room_id = ?
       ORDER BY cm.fecha_envio ASC`,
      [req.params.id]
    );
    res.json({ success: true, mensajes: rows });
  } catch (error) {
    console.error("❌ Error obteniendo mensajes:", error.message);
    res
      .status(500)
      .json({ success: false, message: "Error interno del servidor" });
  }
});

app.post(
  "/api/chats/:id/mensajes",
  authenticateToken,
  upload.single("archivo"),
  async (req, res) => {
    try {
      const { contenido } = req.body;
      const chatId = req.params.id;
      const archivo = req.file ? req.file.filename : null;

      if (!contenido && !archivo) {
        return res
          .status(400)
          .json({ success: false, message: "Debe enviar contenido o archivo" });
      }

      const [result] = await pool.query(
        "INSERT INTO mensajes (chat_id, remitente_id, contenido, archivo) VALUES (?,?,?,?)",
        [chatId, req.user.id, contenido || null, archivo]
      );

      res.json({
        success: true,
        id: result.insertId,
        contenido,
        archivo,
      });
    } catch (err) {
      console.error("❌ Error enviando mensaje:", err);
      res
        .status(500)
        .json({ success: false, message: "Error enviando mensaje" });
    }
  }
);
app.post(
  "/api/chats/:id/mensajes/archivo",
  authenticateToken,
  upload.single("archivo"),
  async (req, res) => {
    try {
      const roomId = req.params.id;
      const [p] = await pool.execute(
        "SELECT 1 FROM chat_participante WHERE room_id=? AND usuario_id=? LIMIT 1",
        [roomId, req.user.id]
      );
      if (!p.length) {
        if (req.file) {
        }
        return res.status(403).json({
          success: false,
          message: "No eres participante de este chat",
        });
      }

      if (!req.file) {
        return res
          .status(400)
          .json({ success: false, message: "Archivo requerido" });
      }

      const filename = req.file.filename;

      await pool.execute(
        "INSERT INTO chat_mensaje (room_id, autor_id, contenido, fecha_envio, tipo, archivo) VALUES (?,?,?,?,?,?)",
        [roomId, req.user.id, null, new Date(), "archivo", filename]
      );

      const [rows] = await pool.execute(
        `SELECT cm.id, cm.tipo, cm.archivo, cm.fecha_envio as fecha, u.id as autor_id, u.nombre as usuario_nombre, u.apellido
       FROM chat_mensaje cm
       LEFT JOIN usuario u ON cm.autor_id = u.id
       WHERE cm.id = LAST_INSERT_ID() LIMIT 1`
      );

      const mensaje = rows.length
        ? {
            id: rows[0].id,
            tipo: rows[0].tipo,
            archivo: rows[0].archivo,
            fecha: rows[0].fecha,
            autor_id: rows[0].autor_id,
            usuario_nombre: `${rows[0].usuario_nombre} ${
              rows[0].apellido || ""
            }`.trim(),
            esMio: req.user.id === rows[0].autor_id,
          }
        : null;

      if (mensaje) {
        io.to(roomId.toString()).emit("nuevoMensaje", mensaje);
      }

      res.json({ success: true, mensaje });
    } catch (error) {
      console.error("❌ Error subiendo archivo:", error);
      res
        .status(500)
        .json({ success: false, message: "Error subiendo archivo" });
    }
  }
);

app.post("/api/chats", authenticateToken, async (req, res) => {
  try {
    const { tipo, titulo, grupo_id, terreno_id, participantes } = req.body;

    if (
      tipo === "directo" &&
      Array.isArray(participantes) &&
      participantes.length === 1
    ) {
      const otroUsuarioId = participantes[0];

      const [rows] = await pool.execute(
        `SELECT cr.id
         FROM chat_room cr
         INNER JOIN chat_participante cp1 ON cr.id = cp1.room_id
         INNER JOIN chat_participante cp2 ON cr.id = cp2.room_id
         WHERE cr.tipo = 'directo'
           AND cp1.usuario_id = ?
           AND cp2.usuario_id = ?
         LIMIT 1`,
        [req.user.id, otroUsuarioId]
      );

      if (rows.length > 0) {
        return res.json({ success: true, chatId: rows[0].id, existente: true });
      }
    }

    const [result] = await pool.execute(
      "INSERT INTO chat_room (tipo, grupo_id, terreno_id, creado_por, titulo, fecha_creacion) VALUES (?,?,?,?,?,NOW())",
      [tipo, grupo_id || null, terreno_id || null, req.user.id, titulo || null]
    );
    const roomId = result.insertId;

    const toInsert = new Set();
    toInsert.add(req.user.id);

    if (tipo === "grupo" && grupo_id) {
      const [members] = await pool.execute(
        "SELECT usuario_id FROM grupo_miembro WHERE grupo_id = ?",
        [grupo_id]
      );
      members.forEach((m) => toInsert.add(m.usuario_id));
    } else if (tipo === "terreno" && terreno_id) {
      const [t] = await pool.execute(
        "SELECT propietario_id FROM terreno WHERE id = ? LIMIT 1",
        [terreno_id]
      );
      if (t.length) toInsert.add(t[0].propietario_id);

      const [direct] = await pool.execute(
        "SELECT usuario_id FROM terreno_miembro WHERE terreno_id = ?",
        [terreno_id]
      );
      direct.forEach((d) => toInsert.add(d.usuario_id));

      const [grupos] = await pool.execute(
        "SELECT grupo_id FROM grupo_terreno WHERE terreno_id = ?",
        [terreno_id]
      );
      for (const g of grupos) {
        const [m] = await pool.execute(
          "SELECT usuario_id FROM grupo_miembro WHERE grupo_id = ?",
          [g.grupo_id]
        );
        m.forEach((x) => toInsert.add(x.usuario_id));
      }
    } else if (tipo === "directo" && Array.isArray(participantes)) {
      participantes.forEach((p) => toInsert.add(p));
    }

    const inserts = [];
    for (const uid of toInsert) inserts.push([roomId, uid, new Date()]);
    if (inserts.length) {
      await pool.query(
        "INSERT INTO chat_participante (room_id, usuario_id, fecha_union) VALUES ?",
        [inserts]
      );
    }

    res.json({ success: true, chatId: roomId, existente: false });
  } catch (error) {
    console.error("❌ Error creando chat:", error.message);
    res
      .status(500)
      .json({ success: false, message: "Error interno creando chat" });
  }
});

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
