# Package
from bitarray import bitarray
from numpy import array


compress_algos = {
    "lzma": 1,
    "gzip": 2,
    "bz2": 3
}


def compress_algo_to_int(algo):
    return compress_algos.get(algo, 0)


def int_to_compress_algo(num):
    algo = [k for k, v in compress_algos.items() if v == num]
    return algo[0] if algo else 0


def array_to_bits(a):
    return bitarray(array([[1 & x >> i for i in range(4, -1, -1)] for x in a]).flatten().tolist())
