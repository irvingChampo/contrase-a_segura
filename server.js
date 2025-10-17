// 1. Importaciones
const express = require('express');
const { loadCommonPasswords, check_password_strength } = require('./src/passwordStrength');

// ---  Importaciones para Swagger ---
const swaggerJsdoc = require('swagger-jsdoc');
const swaggerUi = require('swagger-ui-express');

// 2. Inicialización de la aplicación
const app = express();
const PORT = process.env.PORT || 3000;

// 3. Middleware
app.use(express.json());

// ---  Configuración de Swagger/OpenAPI ---
const swaggerOptions = {
  definition: {
    openapi: '3.0.0',
    info: {
      title: 'API de Evaluación de Contraseñas',
      version: '1.0.0',
      description: 'Una API RESTful para evaluar la fortaleza de una contraseña basándose en su entropía y en una lista de contraseñas comunes.',
    },
    servers: [
      {
        url: `http://localhost:${PORT}`,
        description: 'Servidor de desarrollo local',
      },
    ],
  },
  // La ruta a los archivos que contienen las anotaciones de la API
  apis: ['./server.js'],
};

const swaggerSpec = swaggerJsdoc(swaggerOptions);

// --- Ruta para servir la documentación de Swagger UI ---
app.use('/api-docs', swaggerUi.serve, swaggerUi.setup(swaggerSpec));


// 4. Carga de datos al inicio
let commonPasswordsSet;

(async () => {
  try {
    commonPasswordsSet = await loadCommonPasswords();
    app.listen(PORT, () => {
      console.log(`Servidor escuchando en http://localhost:${PORT}`);
      console.log(`Documentación interactiva de la API disponible en http://localhost:${PORT}/api-docs`);
    });
  } catch (error) {
    console.error('ERROR FATAL: No se pudo iniciar el servidor.', error);
    process.exit(1);
  }
})();


// 5. Definición del Endpoint de la API (con anotaciones Swagger)

/**
 * @swagger
 * /api/v1/password/evaluate:
 *   post:
 *     summary: Evalúa la fortaleza de una contraseña
 *     description: Recibe una contraseña y devuelve un análisis completo que incluye su longitud, tamaño del alfabeto (keyspace), entropía en bits, categoría de fuerza, si es una contraseña común, y el tiempo estimado para ser crackeada por fuerza bruta.
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               password:
 *                 type: string
 *                 description: La contraseña que se va a evaluar.
 *                 example: "MiContraseñaSegura123!"
 *             required:
 *               - password
 *     responses:
 *       '200':
 *         description: Análisis completado con éxito.
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 password_length:
 *                   type: integer
 *                   example: 22
 *                 keyspace_size:
 *                   type: integer
 *                   example: 94
 *                 entropy_bits:
 *                   type: number
 *                   format: float
 *                   example: 144.29
 *                 strength_category:
 *                   type: string
 *                   example: "Muy Fuerte"
 *                 is_in_common_list:
 *                   type: boolean
 *                   example: false
 *                 estimated_crack_time:
 *                   type: string
 *                   example: "Más de mil años"
 *       '400':
 *         description: Solicitud incorrecta. Falta la clave 'password' o no es un string.
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 error:
 *                   type: string
 *                   example: "La solicitud debe incluir un cuerpo JSON con una clave 'password' de tipo string."
 */
app.post('/api/v1/password/evaluate', (req, res) => {
  const { password } = req.body;

  if (!password || typeof password !== 'string') {
    return res.status(400).json({ 
      error: "La solicitud debe incluir un cuerpo JSON con una clave 'password' de tipo string." 
    });
  }

  const result = check_password_strength(password, commonPasswordsSet);
  return res.status(200).json(result);
});

app.get('/', (req, res) => {
  res.send('API de Evaluación de Contraseñas está en funcionamiento. Ve a /api-docs para la documentación interactiva.');
});