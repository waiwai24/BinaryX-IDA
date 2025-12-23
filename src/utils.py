import hashlib
from typing import Dict

import idapro
import ida_ida
import ida_loader

def compute_file_hashes(file_path: str) -> Dict[str, str]:

    sha256 = hashlib.sha256()

    with open(file_path, 'rb') as f:
        while chunk := f.read(8192):
            sha256.update(chunk)

    return {
        'sha256': sha256.hexdigest()
    }

def get_file_type_info() -> Dict[str, str]:

    return {
        'type': ida_loader.get_file_type_name(),
        'architecture': ida_ida.inf_get_procname()
    }