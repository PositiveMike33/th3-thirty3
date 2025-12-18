from PIL import Image
import os

input_path = r"C:/Users/th3th/.gemini/antigravity/brain/4fb424dd-12ca-4bb0-a83e-4c2175c5c88e/app_icon_raven_1764338042496.png"
output_path = r"C:/Users/th3th/.Th3Thirty3/thethirty3/icon.ico"

try:
    img = Image.open(input_path)
    # Resize to standard icon sizes
    icon_sizes = [(256, 256), (128, 128), (64, 64), (48, 48), (32, 32), (16, 16)]
    img.save(output_path, format='ICO', sizes=icon_sizes)
    print(f"Successfully created icon at: {output_path}")
except Exception as e:
    print(f"Error converting icon: {e}")
