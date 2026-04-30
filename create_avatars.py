import base64
import sys

with open(r'C:\Users\qures\.gemini\antigravity\brain\0c118437-5809-480a-a21e-962741ef810d\media__1777527950500.jpg', 'rb') as f:
    boy = base64.b64encode(f.read()).decode('utf-8')
with open(r'c:\Users\qures\campusconnect\assets\girl.png', 'rb') as f:
    girl = base64.b64encode(f.read()).decode('utf-8')

with open(r'c:\Users\qures\campusconnect\lib\tabs\avatars.dart', 'w') as f:
    f.write(f'const String boyAvatarBase64 = "{boy}";\n')
    f.write(f'const String girlAvatarBase64 = "{girl}";\n')
