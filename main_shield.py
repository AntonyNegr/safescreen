import ctypes
from ctypes import wintypes
import time
import threading
import numpy as np
import cv2
import mss
import pytesseract
from pytesseract import Output
import sys
import win32gui
import win32ui
import win32con
import win32api

from vuln_words_dict import SynchronizedOCRDLP

# --- КОНФИГУРАЦИЯ ---
pytesseract.pytesseract.tesseract_cmd = r'C:\Program Files\Tesseract-OCR\tesseract.exe'

# --- НАСТРОЙКИ ---
SHIELD_PADDING = 30
MEMORY_DURATION = 60.0
RECHECK_INTERVAL = 55.0
MAX_WINDOWS_TO_CHECK = 10

# --- WINAPI ---
user32 = ctypes.windll.user32
dwmapi = ctypes.windll.dwmapi

# Типизация для x64
WPARAM = ctypes.c_ulonglong
LPARAM = ctypes.c_longlong
HWND = ctypes.c_void_p
LRESULT = ctypes.c_longlong

WNDPROCTYPE = ctypes.WINFUNCTYPE(LRESULT, HWND, ctypes.c_uint, WPARAM, LPARAM)

user32.DefWindowProcW.argtypes = [HWND, ctypes.c_uint, WPARAM, LPARAM]
user32.DefWindowProcW.restype = LRESULT
user32.SetWindowPos.argtypes = [HWND, HWND, ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_uint]
user32.SetLayeredWindowAttributes.argtypes = [HWND, ctypes.c_uint, ctypes.c_byte, ctypes.c_uint]
user32.SetWindowDisplayAffinity.argtypes = [HWND, ctypes.c_uint]
user32.DestroyWindow.argtypes = [HWND]
user32.DestroyWindow.restype = ctypes.c_bool


class WNDCLASSEX(ctypes.Structure):
    _fields_ = [("cbSize", ctypes.c_uint), ("style", ctypes.c_uint), ("lpfnWndProc", WNDPROCTYPE),
                ("cbClsExtra", ctypes.c_int), ("cbWndExtra", ctypes.c_int), ("hInstance", ctypes.c_void_p),
                ("hIcon", ctypes.c_void_p), ("hCursor", ctypes.c_void_p), ("hbrBackground", ctypes.c_void_p),
                ("lpszMenuName", ctypes.c_wchar_p), ("lpszClassName", ctypes.c_wchar_p), ("hIconSm", ctypes.c_void_p)]


# Константы
WS_POPUP = 0x80000000
WS_EX_LAYERED = 0x00080000
WS_EX_TRANSPARENT = 0x00000020
WS_EX_TOPMOST = 0x00000008
WS_EX_TOOLWINDOW = 0x00000080
LWA_ALPHA = 0x00000002
WDA_MONITOR = 0x00000001
SWP_NOACTIVATE = 0x0010
SWP_SHOWWINDOW = 0x0040

try:
    ctypes.windll.shcore.SetProcessDpiAwareness(1)
except:
    pass

# --- ЗАГРУЗКА DLP ЯДРА ---
dlp_engine = SynchronizedOCRDLP()

ACTIVE_THREATS = {}  # {hwnd: timestamp}
RUNNING = True
SHIELD_POOL_REF = []


# --- КЛАСС ЩИТА ---
class WinApiShield:
    def __init__(self, id_num):
        self.hwnd = self._create_window(id_num)
        self.covering_hwnd = None
        if self.hwnd:
            user32.SetLayeredWindowAttributes(self.hwnd, 0, 1, LWA_ALPHA)
            try:
                user32.SetWindowDisplayAffinity(self.hwnd, WDA_MONITOR)
            except:
                pass

    def _create_window(self, id_num):
        # ОБЕРТКА TRY-EXCEPT В CALLBACK ФУНКЦИИ
        def wnd_proc(hwnd, msg, wParam, lParam):
            try:
                return user32.DefWindowProcW(hwnd, msg, wParam, lParam)
            except:
                return 0

        self.wnd_proc = WNDPROCTYPE(wnd_proc)
        class_name = f"ShieldHyb_{id_num}"
        h_inst = ctypes.windll.kernel32.GetModuleHandleW(None)
        wnd_class = WNDCLASSEX()
        wnd_class.cbSize = ctypes.sizeof(WNDCLASSEX)
        wnd_class.style = 0
        wnd_class.lpfnWndProc = self.wnd_proc
        wnd_class.hInstance = h_inst
        wnd_class.lpszClassName = class_name
        user32.RegisterClassExW(ctypes.byref(wnd_class))
        return user32.CreateWindowExW(WS_EX_LAYERED | WS_EX_TRANSPARENT | WS_EX_TOPMOST | WS_EX_TOOLWINDOW, class_name,
                                      "Shield", WS_POPUP, -1000, -1000, 10, 10, None, None, h_inst, None)

    def move(self, rect):
        if not self.hwnd: return
        x, y, w, h = rect
        safe_x = x - SHIELD_PADDING
        safe_y = y - SHIELD_PADDING
        safe_w = w + (SHIELD_PADDING * 2)
        safe_h = h + (SHIELD_PADDING * 2)
        user32.SetWindowPos(self.hwnd, ctypes.c_void_p(-1), int(safe_x), int(safe_y), int(safe_w), int(safe_h),
                            SWP_NOACTIVATE | SWP_SHOWWINDOW)

    def set_transparent(self, transparent=True):
        if not self.hwnd: return
        if transparent:
            user32.SetLayeredWindowAttributes(self.hwnd, 0, 0, LWA_ALPHA)
        else:
            user32.SetLayeredWindowAttributes(self.hwnd, 0, 1, LWA_ALPHA)

    def hide(self):
        self.covering_hwnd = None
        if self.hwnd: user32.SetWindowPos(self.hwnd, 0, -5000, -5000, 0, 0, SWP_NOACTIVATE)

    def destroy(self):
        if self.hwnd:
            try:
                user32.DestroyWindow(self.hwnd)
            except:
                pass
            self.hwnd = None


# --- ЛОГИКА ПРОВЕРКИ ОКОН, ДАЖЕ ЕСЛИ ОНИ ЗАКРАШЕНЫ ЧЕРНЫМ (X-RAY) ---
def capture_window_xray(hwnd):
    try:
        left, top, right, bottom = win32gui.GetWindowRect(hwnd)
        w = right - left
        h = bottom - top
        if w <= 0 or h <= 0: return None

        hwndDC = win32gui.GetWindowDC(hwnd)
        mfcDC = win32ui.CreateDCFromHandle(hwndDC)
        saveDC = mfcDC.CreateCompatibleDC()
        saveBitMap = win32ui.CreateBitmap()
        saveBitMap.CreateCompatibleBitmap(mfcDC, w, h)
        saveDC.SelectObject(saveBitMap)

        result = ctypes.windll.user32.PrintWindow(hwnd, saveDC.GetSafeHdc(), 2)
        if result == 0:
            ctypes.windll.user32.PrintWindow(hwnd, saveDC.GetSafeHdc(), 0)

        bmpinfo = saveBitMap.GetInfo()
        bmpstr = saveBitMap.GetBitmapBits(True)

        win32gui.DeleteObject(saveBitMap.GetHandle())
        saveDC.DeleteDC()
        mfcDC.DeleteDC()
        win32gui.ReleaseDC(hwnd, hwndDC)

        img = np.frombuffer(bmpstr, dtype=np.uint8).reshape((bmpinfo['bmHeight'], bmpinfo['bmWidth'], 4))

        if np.sum(img) < 1000: return None
        return img[:, :, :3]

    except Exception:
        return None


# --- ЛОГИКА ---
def is_valid_window(hwnd):
    if not win32gui.IsWindowVisible(hwnd): return False
    if win32gui.IsIconic(hwnd): return False

    try:
        title = win32gui.GetWindowText(hwnd).lower()
    except:
        return False

    if not title: return False

    bad_titles = ["program manager", "shield", "cmd", "python", "powershell", "task switching", "пуск"]
    if any(bt in title for bt in bad_titles): return False

    try:
        class_name = win32gui.GetClassName(hwnd).lower()
    except:
        return False

    bad_classes = ["shell_traywnd", "progman", "workerw"]
    if any(bc in class_name for bc in bad_classes): return False

    try:
        rect = win32gui.GetWindowRect(hwnd)
        w = rect[2] - rect[0]
        h = rect[3] - rect[1]
        if w < 20 or h < 20: return False
    except:
        return False
    return True


def get_smart_windows():
    windows = []

    def enum_cb(hwnd, ctx):
        if len(windows) < MAX_WINDOWS_TO_CHECK and is_valid_window(hwnd):
            windows.append(hwnd)

    try:
        win32gui.EnumWindows(enum_cb, None)
    except:
        pass
    return windows


def check_window_hybrid(hwnd, sct):
    img = capture_window_xray(hwnd)

    if img is None:
        shield = None
        for s in SHIELD_POOL_REF:
            if s.covering_hwnd == hwnd:
                shield = s
                break

        if shield:
            shield.set_transparent(True)
            time.sleep(0.02)

        try:
            rect = win32gui.GetWindowRect(hwnd)
            w = rect[2] - rect[0]
            h = rect[3] - rect[1]
            monitor = {"top": rect[1], "left": rect[0], "width": w, "height": h}
            raw = np.array(sct.grab(monitor))
            img = cv2.cvtColor(raw, cv2.COLOR_BGRA2BGR)
        except:
            if shield: shield.set_transparent(False)
            return False

        if shield: shield.set_transparent(False)

    try:
        gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
        thresh = cv2.threshold(gray, 0, 255, cv2.THRESH_BINARY | cv2.THRESH_OTSU)[1]
        text = pytesseract.image_to_string(thresh, lang='rus+eng', config='--psm 6')
        hits = dlp_engine.scan_text(text)
        return any(h['level'] >= 3 for h in hits)
    except:
        return False


def scanner_loop():
    global ACTIVE_THREATS
    sct = mss.mss()
    print("--- СКАНЕР ЗАПУЩЕН ---")

    while RUNNING:
        try:
            targets = get_smart_windows()
            current_time = time.time()

            for hwnd in targets:
                is_known_threat = hwnd in ACTIVE_THREATS
                time_elapsed = current_time - ACTIVE_THREATS.get(hwnd, 0)

                should_scan = not is_known_threat or (time_elapsed > RECHECK_INTERVAL)

                if should_scan:
                    is_threat = check_window_hybrid(hwnd, sct)

                    if is_threat:
                        ACTIVE_THREATS[hwnd] = time.time()
                    elif is_known_threat and time_elapsed > MEMORY_DURATION:
                        del ACTIVE_THREATS[hwnd]

            for h in list(ACTIVE_THREATS.keys()):
                if h not in targets and (current_time - ACTIVE_THREATS[h] > MEMORY_DURATION + 10):
                    del ACTIVE_THREATS[h]

        except Exception:
            pass


# --- MAIN ---
if __name__ == "__main__":
    shield_pool = [WinApiShield(i) for i in range(MAX_WINDOWS_TO_CHECK)]
    SHIELD_POOL_REF = shield_pool

    t = threading.Thread(target=scanner_loop, daemon=True)
    t.start()

    print("--- ЗАЩИТА АКТИВНА ---")
    print("Нажмите Ctrl+C для выхода.")

    try:
        while True:
            threat_hwnds = list(ACTIVE_THREATS.keys())

            for i in range(len(shield_pool)):
                shield = shield_pool[i]
                if i < len(threat_hwnds):
                    hwnd = threat_hwnds[i]
                    try:
                        if win32gui.IsWindow(hwnd):
                            rect = win32gui.GetWindowRect(hwnd)
                            w = rect[2] - rect[0]
                            h = rect[3] - rect[1]
                            shield.covering_hwnd = hwnd
                            shield.move((rect[0], rect[1], w, h))
                        else:
                            shield.hide()
                    except:
                        shield.hide()
                else:
                    shield.hide()

            msg = wintypes.MSG()
            if user32.PeekMessageW(ctypes.byref(msg), None, 0, 0, 1):
                user32.TranslateMessage(ctypes.byref(msg))
                user32.DispatchMessageW(ctypes.byref(msg))

            time.sleep(0.02)

    except KeyboardInterrupt:
        RUNNING = False
        print("\nВыход...")
        for s in shield_pool:
            s.destroy()
        sys.exit(0)
