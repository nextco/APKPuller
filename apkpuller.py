import argparse
import os
import sys
import subprocess
import shutil
import tempfile
from hashlib import sha256
from pathlib import Path


def print_paths(paths):
    for p in paths:
        print(f'  -> {p}')


# Check connected devices
def adb_devices():
    cmd = 'adb devices'
    try:
        result = subprocess.check_output(cmd.split(), universal_newlines=True)
        print(result)
    except subprocess.CalledProcessError as e:
        print('[Error] adb is not installed | in_path. The application will close.')
        sys.exit(1)


# Exclude internal list based on substring
# Input: app.name
def filter_app(app):
    bad_apps = ['com.android','com.google', 'com.huawei', 'org.chromium']
    for f in bad_apps:
        if f in app:
            return None
    return app


# Get the path of apk on device, and extract al splitted paths
# input: app.name
# return: [app.name, is_splitted, paths]
def get_path_apk(app_name):
    is_splitted = False
    paths = []

    cmd = f'adb shell pm path {app_name}'
    r = subprocess.check_output(cmd.split(), universal_newlines=True).split('\n')
    for line in r:
        path = line[8:].strip()
        if path:
            paths.append(path)

    # Check if splitted
    if len(paths) > 1:
        is_splitted = True

    return [app_name, is_splitted, paths]


def list_packages():
    cmd = 'adb shell pm list packages'
    packages = []

    try:
        r = subprocess.check_output(cmd.split(), universal_newlines=True).split('\n')
        for line in r:
            app_name = filter_app(line[8:].strip())  # Ignore filtered packages
            if app_name:
                app = get_path_apk(app_name)
                packages.append(app)
    except subprocess.CalledProcessError as e:
        print('[Error] Check if device is connected.')
        sys.exit(1)

    return packages


def pull_apk(src, dst):
    cmd = f'adb pull {src} {dst}'
    print(f'Current download -> {src}')
    subprocess.run(cmd.split(), check=True, stdout=subprocess.PIPE)


def sign_apk(path):
    cmd = f'java -jar ./utils/uber-apk-signer-1.3.0.jar --apks {path}'
    subprocess.run(cmd.split(), check=True, stdout=subprocess.PIPE)

    # Delete apk.idsig
    idsig = f'{path[:-4]}-aligned-debugSigned.apk.idsig'
    os.remove(idsig)

    # Delete unsigned apk
    os.remove(path)

    # Rename signed apk
    path_signed = f'{path[:-4]}-aligned-debugSigned.apk'
    os.rename(path_signed, path)


def merge_apk(paths, dst_path):
    tmp_dir = tempfile.mkdtemp()
    print(f'Working in: {tmp_dir}')
    for path in paths:
        pull_apk(path, tmp_dir)

    cmd = f'java -jar ./utils/APKEditor-1.3.9.jar m -i {tmp_dir} -o {dst_path}'
    subprocess.run(cmd.split(), check=True, stdout=subprocess.PIPE)
    shutil.rmtree(tmp_dir)

    print(f'Signing APK {dst_path}')
    sign_apk(dst_path)


def dump_apk(app_name, is_splitted, paths, out_path):
    if out_path == '.':
        dst_path = os.path.join(os.getcwd(), app_name)
    else:
        dst_path = os.path.join(out_path, app_name)

    dst_path = f'{dst_path}.apk'

    # Check if file exist
    if os.path.exists(dst_path):
        print(f'APK is already downloaded in {dst_path}')
        sys.exit(1)

    # if splitted -> join
    if is_splitted:
        merge_apk(paths, dst_path)
    else:
        pull_apk(paths[0], dst_path)
        print(f'APK downloaded in -> {dst_path}')

    return dst_path


def rename_apk(path):
    print(f'Preparing malware sample for analysis -> {path}')

    apk_path = Path(path)
    sample_name = sha256(apk_path.name.encode()).hexdigest()

    sample_path = apk_path.parent.joinpath(sample_name)
    os.rename(path, sample_path)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('-s', '--search', help='search packet in packet list', metavar='')
    parser.add_argument('-p', '--pull', help='adb extracts APK into dir', metavar='')
    parser.add_argument('-o', '--output', help='output must be a folder', metavar='')
    parser.add_argument('-m', '--malware', help='extract sample for malware analysis', metavar='')
    args = parser.parse_args()

    # Check connected devices
    adb_devices()

    # Default operation (list)
    apks = list_packages()

    if not (args.search or args.pull or args.malware):
        for app in apks:
            print(app[0])

    if args.search:
        for app, is_splitted, paths in apks:
            if args.search in app:
                print(f'\nApp Name: {app} | is_splitted: {is_splitted}')
                print_paths(paths)

    if args.pull and args.output:
        for app, is_splitted, paths in apks:
            if args.pull in app:                            # Some hackish way to download even if input is bad
                dst_apk = dump_apk(app, is_splitted, paths, args.output)

                if args.malware:
                    rename_apk(dst_apk)

    else:
        print('apkpuller -p <app> -o <output_dir>')


if __name__ == '__main__':
    main()
