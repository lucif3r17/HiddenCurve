# HiddenCurve
A steg tool for math nerds using Elliptic Curve.
# ECC-based Steganography for Embedding and Extracting Messages in Images

This project implements elliptic curve cryptography (ECC) for secure message embedding and extraction in images. It uses a simple elliptic curve for public-key cryptography and embeds encrypted messages into images using the least significant bit (LSB) steganography technique.


Install the required libraries using pip:
```bash
pip install pillow numpy
```
## Usage

### 1. Generate ECC Keys

Keys are generated on the fly when embedding a message. Both the private and public keys are displayed during the embedding process.

### 2. Embed Message in an Image

To embed a message in an image, use the following command:

```bash
python hiddencurve.py embed <image_path> <message> <output_path>
```
### 3. Extract Message from an Image

To extract and decrypt the embedded message from an image, use the following command:

```bash
python hiddencurve.py extract <image_path> <private_key>
```
