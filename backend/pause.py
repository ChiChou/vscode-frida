import subprocess
import sys
import os

def get_environ():
  environ = os.environ
  PATH = [environ['PATH']]
  for p in sys.path:
    if os.path.isdir(p):
        PATH.append(p)
  flag = ':'
  if sys.platform == 'win32':
    flag=';'
  environ['PATH'] = flag.join(PATH)


if len(sys.argv) > 1:
  env = get_environ()
  try:
    subprocess.check_call(sys.argv[1:], env=env)
  except (subprocess.SubprocessError, FileNotFoundError) as e:
    print(e)
  finally:
    input('Press Enter to continue...')
