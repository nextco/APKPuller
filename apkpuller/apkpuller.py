import os
import sys
import subprocess
import argparse
from colorama import Fore


def print_error(msg):
    print(f'{Fore.RED}[-] {msg}{Fore.RESET}')


def print_success(msg):
    print(f'{Fore.GREEN}[+] {msg}{Fore.RESET}')


def adb_installed():
    cmd = 'adb devices'
    try:
        result = subprocess.check_output(cmd.split(), universal_newlines=True)
        print_success(result)
    except subprocess.CalledProcessError as e:
        print_error('[Error] No se encuentra adb instalado. La aplicación se cerrará.')
        sys.exit(1)


def list_packages():
    packages = []
    try:
        result = subprocess.check_output(['adb', 'shell', 'pm', 'list', 'packages'], universal_newlines=True)
        package_lines = result.split('\n')
        for line in package_lines:
            line = line[8:].strip()
            if line:
                packages.append(line)
        return packages
    except subprocess.CalledProcessError as e:
        return None


def check_package_exists(package_name):
    try:
        package_lines = list_packages()
        for line in package_lines:
            if package_name.lower() in line.lower():
                return True
        return False
    except subprocess.CalledProcessError as e:
        return False


def get_path_apk(package_name):
    try:
        packages = []
        result = subprocess.check_output(['adb', 'shell', 'pm', 'path', package_name], universal_newlines=True)
        package_lines = result.split('\n')
        for line in package_lines:
            line = line[8:].strip()
            if line:
                packages.append(line)
        return packages
    except subprocess.CalledProcessError as e:
        return None


def get_apks(apk_paths, user_directory='.'):
    for apk_path in apk_paths:
        try:
            apk_filename = os.path.basename(apk_path)

            if user_directory == '.':
                destination_path = os.path.join(os.getcwd(), apk_filename)
            else:
                destination_path = os.path.join(user_directory, apk_filename)

            subprocess.run(['adb', 'pull', apk_path, destination_path], check=True, stdout=subprocess.PIPE)
            print_success(f'APK downloaded successfully to directory {destination_path}')
        except subprocess.CalledProcessError as e:
            print_error(f'Error downloading APK {apk_path}: {e}')


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('-l', '--list', help='list packages', action='store_true')
    parser.add_argument('-c', '--check', help='check if package is on mobile', metavar='')
    parser.add_argument('-g', '--grep', help='search packet in packet list', metavar='')
    parser.add_argument('-v', '--view', help='view paths of the APKs in a package.', metavar='')
    parser.add_argument('-p', '--pull', nargs=2, help='adb extracts APK into directories <package name> <directory>',
                        metavar='')

    args = parser.parse_args()

    adb_installed()

    if args.list:
        packages = list_packages()
        if args.grep:
            packages = [package for package in packages if args.grep in package]
        for package in packages:
            print_success(package)

    if args.check:
        if check_package_exists(args.check):
            print_success(f'{args.check} - package exists')
        else:
            print_error(f'{args.check} - package does not exist')

    if args.view:
        apks = get_path_apk(args.view)
        for apk in apks:
            print_success(apk)

    if args.pull:
        packagename, directory = args.pull
        apks = get_path_apk(packagename)
        get_apks(apks, directory)


if __name__ == '__main__':
    main()
