import express from "express";
import { pool } from "../index.js";
import { authenticateToken } from "../middleware/auth.js";

const router = express.Router();

router.get("/chats", authenticateToken, async (req, res) => {
  try {
    const userId = req.user.id;

    const [rows] = await pool.query(
      `SELECT cr.id, cr.titulo, cr.tipo
       FROM chat_room cr
       JOIN chat_participante cp ON cp.room_id = cr.id
       WHERE cp.usuario_id = ?`,
      [userId]
    );

    res.json({ success: true, chats: rows });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

router.get("/chats/:id/mensajes", authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;

    const [rows] = await pool.query(
      `SELECT cm.id, cm.contenido, cm.fecha_envio, u.nombre
       FROM chat_mensaje cm
       LEFT JOIN usuario u ON u.id = cm.autor_id
       WHERE cm.room_id = ?
       ORDER BY cm.fecha_envio ASC`,
      [id]
    );

    res.json({ success: true, mensajes: rows });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

router.post("/chats/:id/mensajes", authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;
    const { contenido } = req.body;
    const userId = req.user.id;

    if (!contenido || !contenido.trim()) {
      return res.status(400).json({ success: false, error: "Mensaje vacío" });
    }

    await pool.query(
      "INSERT INTO chat_mensaje (room_id, autor_id, contenido) VALUES (?, ?, ?)",
      [id, userId, contenido]
    );

    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

router.post("/chats", authenticateToken, async (req, res) => {
  try {
    const { destinatarioId } = req.body;
    const userId = req.user.id;

    if (!destinatarioId) {
      return res
        .status(400)
        .json({ success: false, error: "Falta destinatario" });
    }

    const [rows] = await pool.query(
      `SELECT cr.id
       FROM chat_room cr
       JOIN chat_participante cp1 ON cp1.room_id = cr.id
       JOIN chat_participante cp2 ON cp2.room_id = cr.id
       WHERE cr.tipo = 'directo' 
         AND cp1.usuario_id = ? AND cp2.usuario_id = ?`,
      [userId, destinatarioId]
    );

    if (rows.length > 0) {
      return res.json({ success: true, chatId: rows[0].id });
    }

    const [result] = await pool.query(
      "INSERT INTO chat_room (tipo, creado_por) VALUES ('directo', ?)",
      [userId]
    );
    const chatId = result.insertId;

    await pool.query(
      "INSERT INTO chat_participante (room_id, usuario_id) VALUES (?, ?), (?, ?)",
      [chatId, userId, chatId, destinatarioId]
    );

    res.json({ success: true, chatId });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

export default router;
