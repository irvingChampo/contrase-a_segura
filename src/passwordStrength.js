const fs = require('fs');
const path = require('path');
const csv = require('csv-parser');

/**
 * Carga las contraseñas comunes desde un archivo CSV.
 * Lee el archivo línea por línea para no agotar la memoria.
 * Asume que las contraseñas están en la SEGUNDA COLUMNA.
 * @returns {Promise<Set<string>>} Una promesa que se resuelve con un Set que contiene todas las contraseñas comunes.
 */
function loadCommonPasswords() {
  // promesa para poder manejar la naturaleza asíncrona de la lectura de archivos.
  return new Promise((resolve, reject) => {
    console.log('Iniciando la carga de contraseñas comunes...');
    const commonPasswords = new Set();
    const filePath = path.join(__dirname, '..', 'data', 'common-passwords.csv');

    fs.createReadStream(filePath)
      .pipe(csv({ headers: false })) // Le decimos que el CSV no tiene encabezados
      .on('data', (row) => {
        // 'row' es un objeto donde la clave es el índice de la columna.
        // Para la segunda columna, accedemos a row['1'].
        const password = row['1'];
        if (password) {
          commonPasswords.add(password.trim());
        }
      })
      .on('end', () => {
        // Cuando la lectura termina, la promesa se resuelve exitosamente.
        console.log(`${commonPasswords.size} contraseñas comunes cargadas en memoria.`);
        resolve(commonPasswords);
      })
      .on('error', (error) => {
        // Si hay un error, la promesa se rechaza.
        console.error('Error al cargar el archivo de contraseñas comunes:', error);
        reject(error);
      });
  });
}

/**
 * Calcula la entropía (E) de la contraseña usando la fórmula E = L * log2(N).
 * @param {string} password La contraseña a evaluar.
 * @returns {number} El valor de entropía en bits.
 */
function calculate_entropy(password) {
  const L = calculate_L(password);
  const N = calculate_N(password);

  // Si no hay longitud o alfabeto, la entropía es 0.
  if (L === 0 || N === 0) {
    return 0;
  }

  // Math.log2() calcula el logaritmo en base 2.
  const entropy = L * Math.log2(N);
  return entropy;
}

/**
 * Evalúa la contraseña y retorna un objeto con el análisis completo.
 * @param {string} password La contraseña a evaluar.
 * @param {Set<string>} commonPasswords El set de contraseñas comunes para la comprobación de diccionario.
 * @returns {object} Un objeto con el análisis completo.
 */
function check_password_strength(password, commonPasswords) {
  const entropy = calculate_entropy(password);
  
  // 1. Asignar categoría de fuerza basada en la entropía
  let strengthCategory;
  if (entropy < 60) {
    strengthCategory = "Débil o Aceptable";
  } else if (entropy >= 60 && entropy < 80) {
    strengthCategory = "Fuerte";
  } else { // 80+
    strengthCategory = "Muy Fuerte";
  }

  // 2. Lógica de diccionario: si la contraseña es común, es débil sin importar la entropía.
  const isInCommonList = commonPasswords.has(password);
  if (isInCommonList) {
    // Penalizamos.
    strengthCategory = "Muy Débil (Esta es una Contraseña Común)";
  }
  
  // 3. Calcular tiempo estimado de crackeo
  const ATTACK_RATE_PER_SECOND = 10**11; // 100 mil millones de intentos por segundo
  let secondsToCrack = 0;
  if (entropy > 0) {
    const totalCombinations = Math.pow(2, entropy);
    secondsToCrack = totalCombinations / ATTACK_RATE_PER_SECOND;
  }

  // Función auxiliar para convertir segundos a un formato legible
  function formatTime(seconds) {
    if (seconds < 1) return "Al instante";
    const years = seconds / (365.25 * 24 * 60 * 60);
    if (years > 1000) return `Más de mil años`;
    if (years >= 1) return `Aproximadamente ${Math.floor(years)} años`;
    const days = seconds / (24 * 60 * 60);
    if (days >= 1) return `Aproximadamente ${Math.floor(days)} días`;
    const hours = seconds / (60 * 60);
    if (hours >= 1) return `Aproximadamente ${Math.floor(hours)} horas`;
    const minutes = seconds / 60;
    if (minutes >= 1) return `Aproximadamente ${Math.floor(minutes)} minutos`;
    return `Aproximadamente ${seconds.toFixed(2)} segundos`;
  }

  // Construir el objeto de respuesta final
  const evaluation = {
    password_length: calculate_L(password),
    keyspace_size: calculate_N(password),
    entropy_bits: parseFloat(entropy.toFixed(2)),
    strength_category: strengthCategory,
    is_in_common_list: isInCommonList,
    estimated_crack_time: formatTime(secondsToCrack),
  };
  
  return evaluation;
}

/**
 * Calcula la longitud (L) de la contraseña.
 * Simplemente cuenta el número de caracteres.
 *
 * @param {string} password La contraseña a evaluar.
 * @returns {number} El número de caracteres de la contraseña.
 */
function calculate_L(password) {
  return password.length;
}
/**
 * Calcula el tamaño del alfabeto (N) de la contraseña.
 * Identifica los conjuntos de caracteres únicos presentes (keyspace).
 *
 * @param {string} password La contraseña a evaluar.
 * @returns {number} La suma de los tamaños de los conjuntos de caracteres encontrados.
 */
function calculate_N(password) {
  let keyspaceSize = 0;

  // Si no hay contraseña, el keyspace es 0.
  if (!password) {
    return 0;
  }
  // El método .test() devuelve true si encuentra una coincidencia.

  // 1. ¿Contiene letras minúsculas? (a-z)
  if (/[a-z]/.test(password)) {
    keyspaceSize += 26;
  }

  // 2. ¿Contiene letras mayúsculas? (A-Z)
  if (/[A-Z]/.test(password)) {
    keyspaceSize += 26;
  }

  // 3. ¿Contiene números? (0-9)
  if (/[0-9]/.test(password)) {
    keyspaceSize += 10;
  }

  // 4. ¿Contiene símbolos?
  // La expresión regular /[^a-zA-Z0-9]/ coincide con cualquier caracter
  // que NO sea una letra (mayúscula o minúscula) ni un número.
  if (/[^a-zA-Z0-9]/.test(password)) {
    // Asumimos un conjunto estándar de 32 símbolos comunes para el cálculo.
    // (!@#$%^&*()_+-=[]{}|;':",./<>?`~)
    keyspaceSize += 32;
  }

  return keyspaceSize;
}

module.exports = {
  calculate_L,
  calculate_N,
  calculate_entropy,
  loadCommonPasswords,
  check_password_strength,
};