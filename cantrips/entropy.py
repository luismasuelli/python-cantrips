import datetime
from cantrips.iteration import labeled_accumulate
import random
from hashlib import sha1, sha224, sha256, sha384, sha512
from base64 import b64encode


_HASHES = {
    'sha1': sha1,
    'sha224': sha224,
    'sha256': sha256,
    'sha384': sha384,
    'sha512': sha512,
}


random.seed()


def weighted_random(sequence):
    """
    Given a sequence of pairs (element, weight) where weight is an addable/total-order-comparable (e.g. a number),
      it returns a random element (first item in each pair) given in a non-uniform way given by the weight of the
      element (second item in each pair)
    :param sequence: sequence/iterator of pairs (element, weight)
    :return: any value in the first element of each pair
    """

    if isinstance(sequence, dict):
        sequence = sequence.items()

    accumulated = list(labeled_accumulate(sequence))
    r = random.random() * accumulated[-1][1]
    for k, v in accumulated:
        if r < v:
            return k
    #punto inalcanzable a priori
    return None


def nonce(algorithm='sha1', to_hex=True):
    """
    Generates a nonce (a pseudo-random token). It is seeded with the current date/time.
    :param algorithm: a string being any of the SHA hash algorithms.
    :param to_hex: a boolean describing whether we want a base64 digest or a hexadecimal digest
    :return:
    """
    if algorithm not in _HASHES:
        return None
    result = _HASHES['sha1'](datetime.datetime.now().isoformat())
    return result.hexdigest() if to_hex else b64encode(result.digest())