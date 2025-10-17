# API de Evaluación de Fortaleza de Contraseñas

Esta API proporciona un endpoint para evaluar la fortaleza de una contraseña basándose en su entropía, complejidad y si se encuentra en una lista de contraseñas comunes.

## Cómo Ejecutar el Proyecto

1.  Clonar el repositorio.
2.  Instalar las dependencias: `npm install`
3.  Colocar el archivo de contraseñas comunes en `data/common-passwords.csv`.
4.  Iniciar el servidor: `node server.js`

La API estará disponible en `http://localhost:3000`.

---

## Endpoint: `/api/v1/password/evaluate`

### Descripción

Evalúa una contraseña y devuelve un análisis completo de su fortaleza.

-   **Método HTTP:** `POST`
-   **Content-Type:** `application/json`

### Cuerpo de la Solicitud (Request Body)

| Clave      | Tipo     | Descripción                      | Requerido |
| :--------- | :------- | :------------------------------- | :-------- |
| `password` | `string` | La contraseña que se va a evaluar. | Sí        |

**Ejemplo de Solicitud:**

```json
{
    "password": "MySecurePassword123!"
}
```

### Respuesta Exitosa (Código `200 OK`)

**Ejemplo de Cuerpo de Respuesta:**

```json
{
    "password_length": 20,
    "keyspace_size": 94,
    "entropy_bits": 131.17,
    "strength_category": "Muy Fuerte",
    "is_in_common_list": false,
    "estimated_crack_time": "Más de mil años"
}
```

### Respuesta de Error (Código `400 Bad Request`)

Ocurre si el cuerpo de la solicitud es incorrecto o no contiene la clave `password`.

**Ejemplo de Cuerpo de Respuesta:**

```json
{
    "error": "La solicitud debe incluir un cuerpo JSON con una clave 'password' de tipo string."
}
```