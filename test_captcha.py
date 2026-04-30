import json
import base64
import numpy as np
from PIL import Image
import io
import requests

def solve_captcha(b64_str: str) -> str:
    with open("weights.json", "r") as f:
        data = json.load(f)
    
    weights = np.array(data["weights"], dtype=np.float64)
    biases = np.array(data["biases"], dtype=np.float64)
    
    b64_data = b64_str.split(',')[1] if ',' in b64_str else b64_str
    img_bytes = base64.b64decode(b64_data)
    img = Image.open(io.BytesIO(img_bytes)).convert("RGBA")
    
    img_data = np.array(img)
    r = img_data[:, :, 0].astype(np.float32)
    g = img_data[:, :, 1].astype(np.float32)
    b = img_data[:, :, 2].astype(np.float32)
    
    max_c = np.maximum(r, np.maximum(g, b))
    min_c = np.minimum(r, np.minimum(g, b))
    
    saturate = np.zeros_like(max_c, dtype=np.uint8)
    mask = max_c > 0
    saturate[mask] = ((max_c[mask] - min_c[mask]) * 255.0 / max_c[mask]).astype(np.uint8)
    
    out = ""
    label_txt = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
    
    for i in range(6):
        x1 = (i + 1) * 25 + 2
        y1 = 7 + 5 * (i % 2) + 1
        x2 = (i + 2) * 25 + 1
        y2 = 35 - 5 * ((i + 1) % 2)
        
        char_img = saturate[y1:y2, x1:x2]
        avg = np.mean(char_img)
        bits = (char_img > avg).astype(np.float64)
        
        flattened = bits.flatten()
        
        add_result = np.dot(flattened, weights) + biases
        max_idx = np.argmax(add_result)
        out += label_txt[max_idx]
        
    return out

if __name__ == "__main__":
    r = requests.post("https://vtop.vitap.ac.in/vtop/captcha", verify=False)
    print(solve_captcha(r.text))
