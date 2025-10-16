import jwt from "jsonwebtoken";
import dotenv from "dotenv";
dotenv.config();

const JWT_SECRET = process.env.JWT_SECRET || "claveultrasecreeta123";

export function authenticateToken(req, res, next) {
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
