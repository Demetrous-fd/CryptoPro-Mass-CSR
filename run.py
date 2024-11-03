#!/usr/bin/env python

from pathlib import Path
import zipfile
import sys
import os


files = [str(file) for file in Path("src").glob("*.go")]
linux_files = " ".join([filename for filename in files if "windows" not in filename])
windows_files = " ".join([filename for filename in files if "linux" not in filename])

windows_folder = "bin/windows"
linux_folder = "bin/linux"
commands = {
    "run": f"go run {files}"
}


build_commands = {
    "amd64": [
        f"windows;go build -trimpath -ldflags \"-s -w\"  -o {windows_folder}/masscsr.exe {windows_files}",
        f"linux;go build -trimpath -ldflags \"-s -w\"  -o {linux_folder}/masscsr {linux_files}",
    ],
    "386": [
        f"windows;go build -trimpath -ldflags \"-s -w\"  -o {windows_folder}/masscsr_32.exe {windows_files}",
        f"linux;go build -trimpath -ldflags \"-s -w\"  -o {linux_folder}/masscsr_32 {linux_files}",
    ],
}


def create_zip(zip_filename, folder_to_zip):
    zip_filepath = Path(zip_filename)
    folder_path = Path(folder_to_zip)

    with zipfile.ZipFile(zip_filepath, 'w') as zip_file:
        for file in folder_path.rglob('*'):
            if file.is_file() and file.name != zip_filepath.name:
                zip_file.write(file, file.relative_to(folder_path))


if len(sys.argv) >= 2:
    arg = sys.argv[1]
    if arg != "build":
        exit(1)
    
    for arch in build_commands.keys():
        os.environ["GOARCH"] = arch
        for command in build_commands[arch]:
            os_name, command = command.split(";", 1)
            os.environ["GOOS"] = os_name
            os.system(command)
    create_zip(f"{windows_folder}/masscsr_windows.zip", windows_folder)
    create_zip(f"{linux_folder}/masscsr_linux.zip", linux_folder)
else:
    os.system(commands["run"])
        