import pymem
import win32gui
import win32process
import ctypes
import struct
import sys

WDA_MONITOR = 0x01


def inject_notepad_plus():
    # Notepad++ всегда имеет этот класс окна, берем его для избежания конфликта архитектур arm64 и x64
    TARGET_CLASS = "Notepad++"

    print(f"[*] Ищу окно программы {TARGET_CLASS}...")
    hwnd = win32gui.FindWindow(TARGET_CLASS, None)

    if not hwnd:
        print(f"[-] Notepad++ не найден! Убедись, что ты скачал x64 версию и запустил её.")
        return

    try:
        # Получаем PID процесса
        _, pid = win32process.GetWindowThreadProcessId(hwnd)
        print(f"[+] Цель найдена! PID: {pid}")

        # 1. Подключаемся к памяти (x64 Python -> x64 Notepad++)
        pm = pymem.Pymem(pid)
        print(f"[+] Подключение к процессу успешно.")

        # 2. Ищем адрес системной функции
        user32 = ctypes.windll.user32
        func_addr = ctypes.cast(user32.SetWindowDisplayAffinity, ctypes.c_void_p).value

        # 3. Готовим шелл-код (x64)
        shellcode = b'\x48\xB9' + struct.pack('<Q', hwnd)  # MOV RCX, hwnd
        shellcode += b'\xBA\x01\x00\x00\x00'  # MOV EDX, 1
        shellcode += b'\x48\xB8' + struct.pack('<Q', func_addr)  # MOV RAX, func_addr
        shellcode += b'\x48\x83\xEC\x28'  # SUB RSP, 40
        shellcode += b'\xFF\xD0'  # CALL RAX
        shellcode += b'\x48\x83\xC4\x28'  # ADD RSP, 40
        shellcode += b'\xC3'  # RET

        # 4. Внедряем "Вакцину"
        print("[*] Выделение памяти...")
        mem = pm.allocate(len(shellcode))

        if not mem:
            print("[ERROR] Память не выделена. Проверь архитектуры!")
            return

        pm.write_bytes(mem, shellcode, len(shellcode))
        print("[*] Запуск потока защиты...")
        pm.start_thread(mem)

        print("\n[SUCCESS] Notepad++ защищен! Делай скриншот.")

    except Exception as e:
        print(f"[CRITICAL ERROR] {e}")



if __name__ == "__main__":
    inject_notepad_plus()

# Результат: программой распознается открытое окно Notepad++ и при попытке сделать скриншот (было проверено 3 разных программы для скриншотов, все дают одинаковый результат) замазывает окно черным
