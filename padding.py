import numpy as np


def padding_encode(input_str, block_size):
    n = block_size - len(input_str) % block_size
    if n == block_size:
        return input_str + '0' * n
    last_block = '1' * n + '0' * (block_size - n)
    return input_str + '0' * n + last_block


def padding_decode(input_str, block_size):
    last_block = input_str[-block_size:]
    zeros_to_remove = len(last_block.rstrip('0'))
    return input_str[:-(block_size + zeros_to_remove)]
