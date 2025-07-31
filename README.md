# 🔍 Laravel Scanner

**Laravel Scanner** is an automated tool to identify publicly exposed Laravel-based websites. It scans for `.env` leaks, debug mode exposure, accessible file managers, database credentials, and open phpMyAdmin panels.

---

## 🚀 Features

- ✅ Detects `XSRF-TOKEN` cookies to confirm Laravel usage
- 🛡️ Checks for publicly accessible `.env` files
- 🐛 Detects active Laravel debug pages (e.g., Facade\Ignition)
- 🗂️ Scans for known file manager paths:
  - elFinder
  - laravel-filemanager
  - Voyager admin assets
- 🧠 Extracts DB credentials and attempts remote login
- 🕵️ Searches for publicly accessible phpMyAdmin panels
- ⚡ Uses multithreaded scanning via `ThreadPoolExecutor`

---

## 📂 Output Files

| File Name                   | Description                                      |
|----------------------------|--------------------------------------------------|
| `laravel_websites2025.txt` | Sites identified as using Laravel                |
| `result_env2025.txt`       | Exposed `.env` file URLs                         |
| `result_debuglaravel2025.txt` | Debug pages leaking `APP_KEY`                  |
| `result_database_remote.txt` | Remote-accessible DBs: `domain|user|password`  |
| `result_phpmyadmin.txt`    | phpMyAdmin access detected with credentials      |
| `result_elfinder2025.txt`  | Publicly accessible elFinder instances           |
| `result_filemanager2025.txt` | Detected laravel-filemanager paths             |
| `result_voyager2025.txt`   | Voyager admin panel found                        |

---

## 📦 Requirements

Install Python dependencies:

```bash
pip install -r requirements.txt
```

---

## 🧠 How It Works

1. Loads targets from `list.txt`
2. Verifies if each site is Laravel-powered:
   - Checks for `XSRF-TOKEN` cookie
3. If Laravel is detected:
   - Tries to access `.env` file and debug mode
   - If DB credentials are leaked → attempts remote login
   - If remote DB fails → scans for phpMyAdmin
4. Searches known file manager paths

---

## 🚀 Usage

```bash
python3 lara.py
```

---

## 📘 Input Format

Create a file named `list.txt` with one domain per line:

```
example.com
site.test
mytarget.org
```

---

## ⚠️ Important Notes

- The tool is passive/read-only and does not modify target data.
- For ethical use only. Intended for security auditing and research.

---

## 👨‍💻 Author

> Built by Laravel security enthusiasts.  
> Forks, pull requests, and suggestions are welcome! 🔥

---


> 🔄 **Note:** Feature additions may be implemented at any time.

## 📢 Disclaimer

> ❗ Use this tool **only for legal, authorized penetration testing or educational purposes.**  
> The author assumes no responsibility for misuse or illegal activities.
