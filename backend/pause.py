import subprocess
import sys
import traceback


if len(sys.argv) > 1:
  try:
    subprocess.check_call(sys.argv[1:])
  except subprocess.SubprocessError as e:
    print(e)
    input('Press Enter to continue...')
