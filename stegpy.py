import cv2
import numpy as np
from bitarray import bitarray
from argparse import ArgumentParser
from os.path import exists

from helpers import compress_algo_to_int, int_to_compress_algo
from helpers.crypt import Chiffrement
from helpers.errors import StegPyException

import lzma
import gzip
import bz2

parser = ArgumentParser()

group = parser.add_mutually_exclusive_group(required=True)
group.add_argument("-x", "--extract", help="Extract the secret message from image into file", action="store_true")
group.add_argument("-a", "--add", help="Add/Hide the content of file into the image and create output", action="store_true")

parser.add_argument("file", help="File to read / extract")
parser.add_argument("image", help="Image")
parser.add_argument("-o", "--output", default="imageWithSecret.png", help="New image containing secret")
parser.add_argument("-m", "--max-lsb", default=5, type=int, help="Maximum LSB used")
parser.add_argument("-e", "--encrypt", default=True, action="store_true", help="Encrypt")
parser.add_argument('-c', "--compress", choices=['bz2', 'lzma', 'gzip'])

args = parser.parse_args()


class Data:
    def __init__(self, b):
        self._data = b

    @staticmethod
    def from_file(filename):
        with open(filename, "rb") as file:
            return Data(file.read())

    def compress(self, algo):
        compress = getattr(globals()[algo], "compress")
        self._data = compress(self._data)

    def decompress(self, algo):
        decompress = getattr(globals()[algo], "decompress")
        self._data = decompress(self._data)

    def encrypt(self, algo: Chiffrement):
        self._data = algo.encrypt(self._data)

    def decrypt(self, algo: Chiffrement):
        self._data = algo.encrypt(self._data)

    def __bytes__(self):
        return self._data

    def export(self, filename):
        with open(filename, "wb") as file:
            file.write(self._data)


class Image:
    ENDIAN = 'big'

    def __init__(self, file):
        image = cv2.imread(file)
        self._shape = image.shape
        self._image = image.flatten()
        self._data = None
        self._headers = Header(image=self)

    def set_data(self, data):
        self._data = data

    def is_stegpy_image(self):
        return self._headers.has_magic()

    def calculate_nbits(self):
        nbits = (8 * len(self._data)) // (len(self._image) - 8 * Header.HEADER_LEN) + 1
        if nbits > args.max_lsb:
            nbits = args.max_lsb
            raise StegPyException(f"Data is too large using a maximum of {args.max_lsb} bits.")
        return nbits

    def is_compressed(self):
        return self._headers.compress

    def get_compression(self):
        return self._headers.compress

    def is_encrypted(self):
        return self._headers.is_encrypted

    def create_headers(self):
        self._headers.write_magic()
        self._headers.has_magic()
        self._headers.nbits = self.calculate_nbits()
        self._headers.compress = args.compress
        self._headers.is_encrypted = args.encrypt
        self._headers.data_length = len(self._data)

    def read_lsb(self, start, length, pos_in_bytes=True, n=1):
        if pos_in_bytes:
            start *= 8
            length *= 8

        end = start + (length // n)
        if end > len(self._image):
            raise StegPyException(f'Image.read_lsb : {end} too big')

        groups = np.array([[1 & x >> i for i in range(n - 1, -1, -1)] for x in self._image[start:end]])
        data = bitarray(groups.flatten().tolist()[:length]).tobytes()
        return data

    def write_lsb(self, data, position, pos_in_bytes=True, n=1):
        if pos_in_bytes:
            position *= 8

        bit_data = bitarray()
        bit_data.frombytes(data)
        nbit_data = [int(bit_data[idx:(idx + n)].to01(), 2) for idx in range(0, len(bit_data), n)]

        if position + len(nbit_data) > len(self._image):
            raise StegPyException(f'Image.write_lsb : Write data too big ({position} + {len(nbit_data)} = {position + len(nbit_data)} > {len(self._image)}')

        selection = slice(position, position + len(nbit_data))

        mask = 255 - 2 ** n + 1
        self._image[selection] = self._image[selection] & mask | nbit_data

    def read_int(self, position):
        data = self.read_lsb(position, 4)
        return int.from_bytes(data, Image.ENDIAN)

    def write_int(self, integer, position):
        self.write_lsb(integer.to_bytes(4, Image.ENDIAN), position)

    def export(self, filename):
        img = self._image.reshape(self._shape)
        self._headers.has_magic()
        cv2.imwrite(filename, img)

    def create_payload(self):
        nbits = self._headers.nbits
        print(f"Using {nbits} bits")
        self.write_lsb(self._data, Header.HEADER_LEN, n=nbits)

    def extract_payload(self):
        nbits = self._headers.nbits
        print(f"Using {nbits} bits")
        self._data = self.read_lsb(Header.HEADER_LEN, self._headers.data_length, n=nbits)
        return Data(self._data)


class Header:
    MAGIC = b'STEGPY'   # [0; 6[
    POS_DATALEN = 6     # [6; 10[
    POS_NBIT = 10       # [10; 14[
    POS_COMPRESS = 14   # [14; 18[
    POS_ENCRYPT = 18    # [18; 22[
    HEADER_LEN = 22

    def __init__(self, image: Image):
        self._image = image

    def has_magic(self): return self._image.read_lsb(0, len(Header.MAGIC)) == Header.MAGIC
    def write_magic(self): self._image.write_lsb(Header.MAGIC, 0)

    def get_nbits(self): return self._image.read_int(self.POS_NBIT)
    def set_nbits(self, n): self._image.write_int(n, Header.POS_NBIT)

    def get_compressed(self): return int_to_compress_algo(self._image.read_int(self.POS_COMPRESS))
    def set_compressed(self, compressed): self._image.write_int(compress_algo_to_int(compressed), Header.POS_COMPRESS)

    def get_is_encrypted(self): return self._image.read_int(self.POS_ENCRYPT)
    def set_is_encrypted(self, encrypted): self._image.write_int(int(encrypted), Header.POS_ENCRYPT)

    def get_data_length(self): return self._image.read_int(self.POS_DATALEN)
    def set_data_length(self, data_len): self._image.write_int(data_len, Header.POS_DATALEN)

    nbits = property(get_nbits, set_nbits)
    compress = property(get_compressed, set_compressed)
    is_encrypted = property(get_is_encrypted, set_is_encrypted)
    data_length = property(get_data_length, set_data_length)

    def __repr__(self):
        return f"Header(nbits={self.nbits}, data_length={self.data_length}, compressed={self.compressed}, is_encrypted={self.is_encrypted})"


def add(fn_img, fn_message, fn_output):
    image = Image(fn_img)
    data = Data.from_file(fn_message)
    if args.compress:
        data.compress(args.compress)

    image.set_data(bytes(data))
    image.create_headers()
    image.create_payload()
    image.export(fn_output)


def extract(fn_img, fn_secret):
    image = Image(fn_img)
    if not image.is_stegpy_image():
        raise StegPyException("Not a stegpy image")

    data = image.extract_payload()

    if image.is_compressed():
        data.decompress(image.get_compression())

    data.export(fn_secret)


def main():
    if not exists(args.image):
        raise StegPyException("Image", args.image, "does not exists.")

    if args.add and not exists(args.file):
        raise StegPyException("Secret file does not exists.")

    if args.add:
        add(args.image, args.file, args.output)

    elif args.extract:
        extract(args.image, args.file)


main()

