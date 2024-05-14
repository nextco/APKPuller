import os
import sys
import subprocess
import argparse
from hashlib import sha256
from colorama import Fore


def print_error(msg):
    print(f'{Fore.RED}[-] {msg}{Fore.RESET}')


def print_success(msg):
    print(f'{Fore.GREEN}[+] {msg}{Fore.RESET}')


def print_info(msg):
    print(f'{Fore.YELLOW}[+] {msg}{Fore.RESET}')


# Check connected devices
def adb_devices():
    cmd = 'adb devices'
    try:
        result = subprocess.check_output(cmd.split(), universal_newlines=True)
        print_success(result)
    except subprocess.CalledProcessError as e:
        print_error('[Error] No se encuentra adb instalado. La aplicación se cerrará.')
        sys.exit(1)


# Exclude internal list based on substring
# Input: app.name
def filter_app(app):
    bad_apps = ['com.android','com.google', 'com.huawei', 'org.chromium', 'android']
    for f in bad_apps:
        if f in app:
            return None
    return app


# Get the path of apk on device, and extract the most common 'base.apk'
# Input: app.name
def get_path_apk(app_name):
    try:
        result = subprocess.check_output(['adb', 'shell', 'pm', 'path', app_name], universal_newlines=True)
        package_lines = result.split('\n')
        for paths in package_lines:
            path = paths[8:].strip()
            if 'base.apk' in path:
                return path
        return False
    except subprocess.CalledProcessError as e:
        sys.exit(1)


def list_packages():
    packages = {}
    try:
        result = subprocess.check_output(['adb', 'shell', 'pm', 'list', 'packages'], universal_newlines=True)
        lines = result.split('\n')
        for line in lines:
            app = filter_app(line[8:].strip())
            if app:
                path = get_path_apk(app)
                if path:
                    # print(app, path)
                    packages[app] = path
        return packages
    except subprocess.CalledProcessError as e:
        sys.exit(1)


def dump_apk(app_name, app_path, user_directory):
    try:
        if user_directory == '.':
            destination_path = os.path.join(os.getcwd(), app_name)
        else:
            destination_path = os.path.join(user_directory, app_name)

        subprocess.run(['adb', 'pull', app_path, destination_path], check=True, stdout=subprocess.PIPE)
        print_success(f'APK downloaded successfully to directory {destination_path}')
    except subprocess.CalledProcessError as e:
        print_error(f'Error downloading APK {app_path}: {e}')
        sys.exit(1)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('-g', '--grep', help='search packet in packet list', metavar='')
    parser.add_argument('-p', '--pull', help='adb extracts APK into dir', metavar='')
    parser.add_argument('-o', '--output', help='output folder', metavar='')
    parser.add_argument('-m', '--mode', help='extract sample for malware analysis', metavar='')
    args = parser.parse_args()

    # Check connected devices
    adb_devices()

    # Default operation (list)
    apps = list_packages()
    for app in apps:
        print_success(app)

    if args.grep:
        for app, path in apps.items():
            if args.grep in app:
                print_success(f'\n\n{app} -> {path}')

    if args.pull:
        for app, path in apps.items():
            if args.pull in app:
                print_info(f'{app} downloading')
                dump_apk(f'{app}.apk', path, args.output)

    if args.mode:
        for app, path in apps.items():
            if args.mode in app:
                print_info(f'Extracting malware sample for analysis')
                sample_name = sha256(app.encode('utf-8')).hexdigest()
                dump_apk(sample_name, path, args.output)


if __name__ == '__main__':
    main()
