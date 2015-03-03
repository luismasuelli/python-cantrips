from cantrips.iteration import labeled_accumulate
import random

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