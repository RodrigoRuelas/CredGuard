from flask import Flask, render_template, request
from analyzer import evaluar_contrasena

app = Flask(__name__)

@app.route('/', methods=['GET', 'POST'])
def index():
    resultado = None
    password_ingresada = ""
    
    if request.method == 'POST':
        password_ingresada = request.form.get('password', '')
        if password_ingresada:
            # Llamamos a nuestra función del Bloque 1
            resultado = evaluar_contrasena(password_ingresada)
            
    return render_template('index.html', resultado=resultado, password=password_ingresada)

if __name__ == '__main__':
    # Ejecutamos el servidor de desarrollo en modo debug
    app.run(debug=True, host='0.0.0.0', port=5000)