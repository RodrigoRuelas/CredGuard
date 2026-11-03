import re
import math

# Lista local simulada de contraseñas filtradas comunes (en un proyecto real, puedes cargar un archivo .txt grande)
COMMON_PASSWORDS = {"123456", "password", "123456789", "qwerty", "abc12345", "admin", "welcome", "letmein"}

def evaluar_contrasena(password):
    score = 0
    reasons = []
    
    # 1. Validación de Lista Local de Filtradas (Requisito 4)
    if password.lower() in COMMON_PASSWORDS:
        return {
            "score": 0,
            "level": "Muy débil",
            "reasons": ["La contraseña se encuentra en la lista de credenciales filtradas más comunes."],
            "time_to_crack": "Instantáneo"
        }

    # 2. Evaluación de Longitud (Requisito 1)
    length = len(password)
    if length < 8:
        reasons.append("La longitud es menor a 8 caracteres (muy vulnerable).")
        score += 10
    elif 8 <= length < 12:
        reasons.append("Longitud aceptable, pero se recomiendan 12 o más caracteres.")
        score += 25
    else:
        reasons.append("Excelente longitud (12+ caracteres).")
        score += 40

    # 3. Variedad de Caracteres (Requisito 1 y 5)
    has_lower = bool(re.search(r'[a-z]', password))
    has_upper = bool(re.search(r'[A-Z]', password))
    has_digit = bool(re.search(r'\d', password))
    has_symbol = bool(re.search(r'[!@#$%^&*(),.?":{}|<>]', password))

    charset_size = 0
    if has_lower: 
        charset_size += 26
        score += 10
    else:
        reasons.append("Faltan letras minúsculas.")
        
    if has_upper: 
        charset_size += 26
        score += 10
    else:
        reasons.append("Faltan letras mayúsculas.")
        
    if has_digit: 
        charset_size += 10
        score += 10
    else:
        reasons.append("Faltan números.")
        
    if has_symbol: 
        charset_size += 32
        score += 15
    else:
        reasons.append("Faltan símbolos especiales.")

    # 4. Detección de Patrones, Secuencias y Repeticiones (Requisito 5)
    # Patrones secuenciales de teclado comunes o secuencias numéricas
    if re.search(r'(123|abc|qwe|asd|zxc)', password.lower()):
        score -= 15
        reasons.append("Contiene secuencias de teclado o numéricas comunes.")
        
    # Caracteres repetidos consecutivamente (ej: 'aaa', '111')
    if re.search(r'(.)\1{2,}', password):
        score -= 15
        reasons.append("Contiene secuencias de caracteres repetidos consecutivamente.")

    # Asegurar que el puntaje se mantenga entre 0 y 100
    score = max(0, min(100, score))

    # 5. Clasificación Cualitativa (Requisito 2)
    if score < 20:
        level = "Muy débil"
    elif score < 40:
        level = "Débil"
    elif score < 70:
        level = "Aceptable"
    elif score < 85:
        level = "Fuerte"
    else:
        level = "Muy fuerte"

    # 6. Estimación de Tiempo de Ruptura por Fuerza Bruta (Requisito 3)
    # Espacio de búsqueda = (Tamaño del conjunto de caracteres) ^ (Longitud)
    if charset_size == 0:
        combinations = 0
    else:
        combinations = charset_size ** length
    
    # Asumiendo una velocidad estándar de ataque por fuerza bruta en GPU moderna (~1 mil millones de intentos por segundo)
    guesses_per_sec = 1e9 
    seconds = combinations / guesses_per_sec if combinations > 0 else 0
    
    time_to_crack = formatear_tiempo(seconds)

    return {
        "score": score,
        "level": level,
        "reasons": reasons,
        "time_to_crack": time_to_crack
    }

def formatear_tiempo(seconds):
    if seconds < 1:
        return "Instantáneo"
    elif seconds < 60:
        return f"{int(seconds)} segundos"
    elif seconds < 3600:
        return f"{int(seconds / 60)} minutos"
    elif seconds < 86400:
        return f"{int(seconds / 3600)} horas"
    elif seconds < 31536000:
        return f"{int(seconds / 86400)} días"
    else:
        years = seconds / 31536000
        if years > 1e12:
            return "Billones de años"
        return f"{int(years):,} años"