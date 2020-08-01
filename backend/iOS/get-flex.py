import urllib.request
import json
import shutil


with urllib.request.urlopen('https://api.github.com/repos/JohnCoates/flexdecrypt/releases/latest') as response:
    info = json.loads(response.read())

url = next(asset['browser_download_url']
           for asset in info['assets'] if asset['name'] == 'flexdecrypt.deb')
print(url)

with urllib.request.urlopen(url) as response, open('flexdecrypt.deb', 'wb') as fp:
    shutil.copyfileobj(response, fp)

# todo: SSH and scp
