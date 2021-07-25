import subprocess
import sys


if len(sys.argv) > 1:
  try:
    subprocess.check_call(sys.argv[1:])
  except (subprocess.SubprocessError, FileNotFoundError) as e:
    print(e)
  finally:
    input('Press Enter to continue...')
