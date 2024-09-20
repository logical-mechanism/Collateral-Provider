import subprocess


def witness(draft_file_path: str, witnessed_file_path: str, network: str, skey_path: str, cli_path: str) -> None:
    """Witness a transaction with the skey.
    """
    func = [
        cli_path,
        'conway',
        'transaction',
        'witness',
        '--tx-body-file',
        draft_file_path,
        '--signing-key-file',
        skey_path,
        '--out-file',
        witnessed_file_path,
    ]
    func += network.split(" ")

    p = subprocess.Popen(func, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    _, _ = p.communicate()
