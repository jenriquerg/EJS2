const express = require("express");
const bcrypt = require("bcrypt");
const admin = require("firebase-admin");
const speakereasy = require("speakeasy");
const jwt = require("jsonwebtoken");

const router = express.Router();
const db = admin.firestore();


router.get("/getInfo", async (req, res) => {
  const alumnoInfo = {
    nombre: "Jesus Enrique Rojas Guerrero",
    grupo: "IDGS11",
  };
  res.json({
    nodeVersion: process.version,
    alumnoInfo,
  });
});

router.post("/register", async (req, res) => {
  const { email, username, password, grado, grupo } = req.body;

  if (!email || !username || !password || !grado || !grupo) {
    return res.status(400).json({ message: "Todos los campos son requeridos" });
  }

  if (typeof grado !== "string" || typeof grupo !== "string") {
    return res.status(400).json({ message: "Grado y grupo deben ser cadenas de texto" });
  }

  const normalizedEmail = email.toLowerCase();
  const usersRef = db.collection("users");

  try {
    const existingUser = await usersRef.where("email", "==", normalizedEmail).get();
    if (!existingUser.empty) {
      return res.status(400).json({ message: "El usuario ya existe" });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const secret = speakereasy.generateSecret({ length: 20 });

    await usersRef.add({
      username,
      email: normalizedEmail,
      password: hashedPassword,
      grado,
      grupo,
      mfaSecret: secret.base32,
      createdAt: admin.firestore.FieldValue.serverTimestamp(),
    });

    res.status(201).json({
      message: "Usuario registrado exitosamente",
      secret: secret.otpauth_url,
    });
  } catch (error) {
    console.error("Error en el registro:", error);
    res.status(500).json({ message: "Error interno del servidor", error: error.message });
  }
});

router.post("/login", async (req, res) => {
  const { email, password, token } = req.body;

  if (!email || (!password && !token)) {
    return res.status(400).json({ message: "Email y al menos una credencial (contraseña o token) son requeridos" });
  }

  try {
    const usersRef = db.collection("users");
    const userSnapshot = await usersRef.where("email", "==", email).get();
    if (userSnapshot.empty) {
      return res.status(401).json({ message: "Usuario no encontrado" });
    }

    const userData = userSnapshot.docs[0].data();
    let authenticated = false;

    if (password) {
      authenticated = await bcrypt.compare(password, userData.password);
    }

    if (token && !authenticated) {
      authenticated = speakereasy.totp.verify({
        secret: userData.mfaSecret,
        encoding: "base32",
        token,
        window: 1,
      });
    }

    if (!authenticated) {
      return res.status(401).json({ message: "Credenciales inválidas" });
    }

    const jwtToken = jwt.sign(
      { id: userSnapshot.docs[0].id, username: userData.username, email: userData.email },
      process.env.JWT_SECRET || "SECRET_KEY",
      { expiresIn: "2h" }
    );

    res.json({ success: true, token: jwtToken });
  } catch (error) {
    console.error("Error en el login:", error);
    res.status(500).json({ message: "Error interno del servidor" });
  }
});

router.post("/verify-otp", async (req, res) => {
  const { email, token } = req.body;

  if (!email || !token) {
    return res.status(400).json({ message: "Email y token son requeridos" });
  }

  try {
    const userSnapshot = await db.collection("users").where("email", "==", email).get();
    if (userSnapshot.empty) {
      return res.status(404).json({ message: "Usuario no encontrado" });
    }

    const user = userSnapshot.docs[0].data();

    const verified = speakereasy.totp.verify({
      secret: user.mfaSecret,
      encoding: "base32",
      token,
      window: 1,
    });

    if (!verified) {
      return res.status(401).json({ success: false, message: "Código OTP inválido" });
    }

    const jwtToken = jwt.sign(
      { id: userSnapshot.docs[0].id, username: user.username, email: user.email },
      process.env.JWT_SECRET || "SECRET_KEY",
      { expiresIn: "2h" }
    );

    res.json({ success: true, token: jwtToken });
  } catch (error) {
    console.error("Error en la verificación OTP:", error);
    res.status(500).json({ message: "Error interno del servidor" });
  }
});

router.get("/logs", async (req, res) => {
  try {
    const logsRef = db.collection("logs2");
    const snapshot = await logsRef.get();

    if (snapshot.empty) {
      return res.status(404).json({ message: "No se encontraron logs de nivel info" });
    }

    const logs = snapshot.docs.map(doc => ({ id: doc.id, ...doc.data() }));
    return res.json(logs);
  } catch (error) {
    console.error("Error al obtener logs de nivel info:", error);
    return res.status(500).json({ error: "Error interno del servidor" });
  }
});

router.get("/logs-error", async (req, res) => {
  try {
    const logsRef = db.collection("logs2");
    const snapshot = await logsRef.where("logLevel", "==", "error").get();

    if (snapshot.empty) {
      return res.status(404).json({ message: "No se encontraron logs de nivel info" });
    }

    const logs = snapshot.docs.map(doc => ({ id: doc.id, ...doc.data() }));
    return res.json(logs);
  } catch (error) {
    console.error("Error al obtener logs de nivel info:", error);
    return res.status(500).json({ error: "Error interno del servidor" });
  }
});

router.get("/logs-warning", async (req, res) => {
  try {
    const logsRef = db.collection("logs2");
    const snapshot = await logsRef.where("logLevel", "==", "warning").get();

    if (snapshot.empty) {
      return res.status(404).json({ message: "No se encontraron logs de nivel info" });
    }

    const logs = snapshot.docs.map(doc => ({ id: doc.id, ...doc.data() }));
    return res.json(logs);
  } catch (error) {
    console.error("Error al obtener logs de nivel info:", error);
    return res.status(500).json({ error: "Error interno del servidor" });
  }
});


module.exports = router;
