import re


class SynchronizedOCRDLP:
    def __init__(self):
        self.dictionary = {
            "ru": {1: [], 2: [], 3: [], 4: [], 5: []},
            "en": {1: [], 2: [], 3: [], 4: [], 5: []}
        }

        # Единая точка входа для заполнения баз
        self._populate_synchronized_db()

        # Расширение вариациями (падежи, опечатки)
        self.expand_dictionary()

    def _add_sync_concept(self, level, ru_synonyms, en_synonyms):
        # Добавляем в сырые списки (морфология применится позже)
        self.dictionary["ru"][level].extend(ru_synonyms)
        self.dictionary["en"][level].extend(en_synonyms)

    def _populate_synchronized_db(self):
        # ================= LEVEL 5: CRITICAL (ACCESS & SECRETS) =================

        # 1. Аутентификация
        self._add_sync_concept(5,
                               ["пароль", "логин", "аутентификация", "токен", "креды", "учетка"],
                               ["password", "login", "authentication", "token", "credentials", "account"])

        # 2. Супер-права
        self._add_sync_concept(5,
                               ["админ", "администратор", "рут", "суперпользователь", "доступ"],
                               ["admin", "administrator", "root", "superuser", "access"])

        # 3. Криптография и ключи
        self._add_sync_concept(5,
                               ["ключ", "шифр", "шифрование", "приватный", "сид", "мнемоника", "фраза"],
                               ["key", "cipher", "encryption", "private", "seed", "mnemonic", "phrase"])

        # 4. Грифы секретности
        self._add_sync_concept(5,
                               ["секретно", "конфиденциально", "тайна", "неразглашение", "компромат"],
                               ["secret", "confidential", "classified", "disclosure", "compromat"])

        # 5. Криптовалюты и Финансы (Критика)
        self._add_sync_concept(5,
                               ["биткоин", "крипта", "кошелек", "эфириум", "cvv", "код", "пин"],
                               ["bitcoin", "crypto", "wallet", "ethereum", "cvv", "code", "pin"])

        # 6. Удостоверения личности (Hard PII)
        self._add_sync_concept(5,
                               ["паспорт", "загранпаспорт", "биометрия", "отпечаток", "виза", "снилс"],
                               ["passport", "id-card", "biometric", "fingerprint", "visa", "ssn"])

        # ================= LEVEL 4: HIGH (LEGAL & MONEY) =================

        # 1. Договорная база
        self._add_sync_concept(4,
                               ["договор", "контракт", "соглашение", "оферта", "сделка", "меморандум"],
                               ["contract", "agreement", "deal", "offer", "transaction", "memorandum"])

        # 2. Официальные приказы
        self._add_sync_concept(4,
                               ["приказ", "указ", "постановление", "распоряжение", "устав", "лицензия"],
                               ["order", "decree", "resolution", "directive", "charter", "license"])

        # 3. Финансовые документы
        self._add_sync_concept(4,
                               ["счет", "фактура", "накладная", "смета", "акт", "ведомость"],
                               ["invoice", "bill", "waybill", "estimate", "act", "statement"])

        # 4. Деньги и Налоги
        self._add_sync_concept(4,
                               ["зарплата", "премия", "налог", "штраф", "неустойка", "бюджет"],
                               ["salary", "bonus", "tax", "fine", "penalty", "budget"])

        # 5. Судебные дела
        self._add_sync_concept(4,
                               ["иск", "суд", "арбитраж", "адвокат", "доверенность", "претензия"],
                               ["lawsuit", "court", "arbitration", "lawyer", "proxy", "claim"])

        # ================= LEVEL 3: MEDIUM (INFRA & BIZ) =================

        # 1. IT Инфраструктура
        self._add_sync_concept(3,
                               ["сервер", "база", "бэкап", "лог", "конфиг", "дамп", "хост"],
                               ["server", "database", "backup", "log", "config", "dump", "host"])

        # 2. Сеть и Безопасность
        self._add_sync_concept(3,
                               ["сеть", "ip-адрес", "впн", "прокси", "уязвимость", "эксплойт", "баг", "инцидент"],
                               ["network", "ip-address", "vpn", "proxy", "vulnerability", "exploit", "bug", "incident"])

        # 3. Коммерция
        self._add_sync_concept(3,
                               ["клиент", "партнер", "поставщик", "тендер", "закупка", "конкурс"],
                               ["client", "partner", "vendor", "tender", "procurement", "contest"])

        # 4. Планирование
        self._add_sync_concept(3,
                               ["стратегия", "план", "отчет", "презентация", "аналитика", "прогноз"],
                               ["strategy", "plan", "report", "presentation", "analytics", "forecast"])

        # ================= LEVEL 2: LOW (ROUTINE) =================

        # 1. Рабочий график
        self._add_sync_concept(2,
                               ["график", "табель", "расписание", "смена", "дежурство"],
                               ["schedule", "timesheet", "timetable", "shift", "duty"])

        # 2. Доступ в офис
        self._add_sync_concept(2,
                               ["пропуск", "бейдж", "вахта", "кабинет", "ключ-карта"],
                               ["pass", "badge", "watch", "office", "keycard"])

        # 3. Кадровые движения
        self._add_sync_concept(2,
                               ["отпуск", "отгул", "командировка", "больничный", "заявление"],
                               ["vacation", "time-off", "trip", "sick-leave", "application"])

        # 4. Внутренняя коммуникация
        self._add_sync_concept(2,
                               ["совещание", "планерка", "статус", "задача", "записка", "объяснительная"],
                               ["meeting", "briefing", "status", "task", "note", "explanation"])

        # ================= LEVEL 1: INFO (LISTS & AGGREGATION) =================

        # 1. Списки (Маркеры выгрузок)
        self._add_sync_concept(1,
                               ["список", "реестр", "справочник", "каталог", "картотека"],
                               ["list", "registry", "directory", "catalog", "file-cabinet"])

        # 2. Данные массивами
        self._add_sync_concept(1,
                               ["выгрузка", "таблица", "архив", "подборка", "сводка"],
                               ["export", "table", "archive", "selection", "summary"])

        # 3. Профили людей
        self._add_sync_concept(1,
                               ["анкета", "резюме", "профиль", "досье", "кандидат", "сотрудник"],
                               ["form", "resume", "profile", "dossier", "candidate", "employee"])

        # 4. Контакты
        self._add_sync_concept(1,
                               ["контакт", "адрес", "телефон", "почта", "email", "абонент"],
                               ["contact", "address", "phone", "mail", "email", "subscriber"])

    def _generate_russian_morphology(self, word):
        forms = {word}
        root = word

        # --- СУЩЕСТВИТЕЛЬНЫЕ ---
        if word.endswith("а"):  # Виза
            root = word[:-1]
            forms.update(
                [root + "ы", root + "е", root + "у", root + "ой", root + "ою", root + "ам", root + "ами", root + "ах"])
        elif word.endswith("я"):  # Копия
            root = word[:-1]
            forms.update([root + "и", root + "е", root + "ю", root + "ей", root + "ям", root + "ями", root + "ях"])
        elif word.endswith("ь"):  # Пароль
            root = word[:-1]
            forms.update(
                [root + "я", root + "ю", root + "ем", root + "е", root + "и", root + "ей", root + "ям", root + "ями",
                 root + "ях"])
        elif word.endswith("о") or word.endswith("е"):  # Сальдо
            root = word[:-1]
            forms.update([root + "а", root + "у", root + "ом", root + "а", root + "ам", root + "ами", root + "ах"])

        # --- ПРИЛАГАТЕЛЬНЫЕ ---
        elif word.endswith("ый") or word.endswith("ий"):  # Секретный
            root = word[:-2]
            forms.update([root + "ого", root + "ому", root + "ым", root + "ом", root + "ые", root + "ых", root + "ыми"])
        elif word.endswith("ая"):  # Служебная
            root = word[:-2]
            forms.update([root + "ой", root + "ую", root + "ые", root + "ых", root + "ым", root + "ыми"])

        # --- МУЖСКОЙ РОД ---
        else:  # Договор
            forms.update(
                [word + "а", word + "у", word + "ом", word + "е", word + "ы", word + "ов", word + "ам", word + "ами",
                 word + "ах"])

        return list(forms)

    def expand_dictionary(self):
        print("Building Synchronized Dictionary...")
        for lang in ["ru", "en"]:
            for level in range(1, 6):
                base_words = list(self.dictionary[lang][level])
                expanded_set = set()

                for word in base_words:
                    word = word.lower()

                    # 1. Морфология
                    variants = []
                    if lang == "ru":
                        variants = self._generate_russian_morphology(word)
                    else:
                        variants = [word, word + "s"]
                        if word.endswith("y"): variants.append(word[:-1] + "ies")
                        if word.endswith("ss"): variants.append(word + "es")

                    # 2. Пост-обработка (Регистр + OCR)
                    for v in variants:
                        expanded_set.add(v)
                        expanded_set.add(v.upper())
                        expanded_set.add(v.capitalize())

                        # OCR Обфускация для уровней 3-5
                        if level >= 3:
                            ocr = v
                            replacements = [
                                ('о', '0'), ('a', '@'), ('l', '1'),
                                ('e', '3'), ('з', '3'), ('ч', '4'),
                                ('s', '$'), ('i', '1')
                            ]
                            for char, repl in replacements:
                                if char in ocr: ocr = ocr.replace(char, repl)
                            if ocr != v: expanded_set.add(ocr)

                self.dictionary[lang][level] = list(expanded_set)

    def get_stats(self):
        stats = []
        total = 0
        for level in range(5, 0, -1):
            ru_c = len(self.dictionary["ru"][level])
            en_c = len(self.dictionary["en"][level])
            total += ru_c + en_c
            stats.append(f"Level {level}: RU={ru_c}, EN={en_c}")
        return f"Total: {total}\n" + "\n".join(stats)

    def scan_text(self, text, language="ru"):
        results = []
        clean_text = re.sub(r'[^\w\s-]', ' ', text).lower()
        words_in_text = set(clean_text.split())

        for level in range(5, 0, -1):
            target_words = set(self.dictionary[language][level])
            found_words = words_in_text.intersection(target_words)
            for word in found_words:
                results.append({
                    "word": word,
                    "level": level,
                    "desc": f"Level {level} Risk"
                })
        return sorted(results, key=lambda x: x['level'], reverse=True)
