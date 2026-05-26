# Install

## Requirements

- Python 3.11 or newer
- Frida 17+ Python package
- Matching Frida 17+ `frida-server` on the jailbroken iOS device
- Optional SSH/SFTP access for faster bundle transfer

## Developer Install

```bash
python -m pip install -e ".[dev]"
```

## Runtime Install

```bash
python -m pip install .
```

## Verify

```bash
ios-dumpkit --help
ios-dumpkit doctor --usb
```

If your Python environment blocks global package installs, create a virtual environment first:

```bash
python -m venv .venv
. .venv/bin/activate
python -m pip install -U pip
python -m pip install -e ".[dev]"
```

