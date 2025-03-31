const express = require('express');
const admin = require('firebase-admin');
const cors = require('cors');
const bodyParser = require('body-parser');
const winston = require('winston');
require('dotenv').config();

const port = process.env.PORT || 5002;

// Cargar la configuración desde las variables de entorno
let serviceAccount = JSON.parse(process.env.FIREBASE_CREDENTIALS);

// Inicializar Firebase
admin.initializeApp({
  credential: admin.credential.cert(serviceAccount),
});

// Importar rutas después de la conexión a Firebase para evitar fallos
const routes = require("./routes");

// Inicializar Express
const server = express();

server.use(cors({
  origin: "*",
  credentials: true
}));

server.use(bodyParser.json());

// Configuración de Winston para logs
const logger = winston.createLogger({
  level: 'info',
  format: winston.format.json(),
  transports: [
      new winston.transports.File({ filename: 'logs/error.log', level: 'error' }),
      new winston.transports.File({ filename: 'logs/all.log', level: 'info'  }),
      new winston.transports.File({ filename: 'logs/combined.log' })
  ]
});

const db = admin.firestore();

// Middleware de logging
server.use((req, res, next) => {
  const startTime = Date.now();
  let statusCode;
  
  const originalSend = res.send;
  res.send = function (body) {
    statusCode = res.statusCode;
    originalSend.call(this, body);
  };

  res.on("finish", async () => {
    const responseTime = Date.now() - startTime;
    const logData = {
      logLevel: statusCode >= 400 ? "error" : "info",
      timestamp: new Date(),
      method: req.method,
      url: req.url,
      path: req.path,
      query: req.query,
      params: req.params,
      status: statusCode || res.statusCode,
      responseTime,
      ip: req.ip,
      userAgent: req.get("User-Agent"),
      protocol: req.protocol,
      host: req.hostname,
      system: {
        nodeVersion: process.version,
        environment: process.env.NODE_ENV || "development",
        pid: process.pid,
      },
    };

    logger.log({ level: logData.logLevel, message: "Request completed", ...logData });
    try {
      await db.collection("logs2").add(logData);
    } catch (error) {
      logger.error("Error al guardar log en Firestore:", error);
    }
  });
  next();
});

// Rutas protegidas
server.use("/api", routes);

server.listen(port, () => {
  console.log(`Servidor corriendo en http://localhost:${port}`);
});