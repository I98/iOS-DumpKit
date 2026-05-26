# Examples

## List Apps Over USB

```bash
ios-dumpkit list --usb
```

## Search By Display Name

```bash
ios-dumpkit list --usb --search "Example App"
```

## Dump By Bundle ID

```bash
ios-dumpkit dump com.example.app --usb --output-dir ./dumps
```

## Dump With SSH/SFTP Transfer

```bash
ios-dumpkit dump com.example.app \
  --host 192.168.0.71 \
  --ssh-host 192.168.0.71 \
  --ssh-user root \
  --ssh-pass '<password>' \
  --output example.ipa
```

## iproxy

```bash
ios-dumpkit dump com.example.app \
  --host 127.0.0.1 \
  --ssh-host 127.0.0.1 \
  --ssh-port 2222 \
  --ssh-user root
```

## Metadata Only

```bash
ios-dumpkit metadata com.example.app --usb --output-dir ./metadata
```

## Attach To Existing PID

```bash
ios-dumpkit dump com.example.app --no-launch --attach-pid 1234 --timeout 120
```

## Verify IPA

```bash
ios-dumpkit verify ./dumps/Example.ipa
```

## Full Trace

```bash
ios-dumpkit dump com.example.app --usb --trace trace.jsonl --verbose
```

