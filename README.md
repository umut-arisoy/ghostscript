python3 ghostscript_aux_poc.py --generate --extension ps --filename test_safe --profile marker-only
python3 ghostscript_aux_poc.py --inject --filename test_safe.ps --obfuscation base64
python3 ghostscript_aux_poc.py --scan --filename test_safe.ps
python3 ghostscript_aux_poc.py --detect-net
