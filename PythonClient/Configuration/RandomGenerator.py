import math
from decimal import Decimal, ROUND_DOWN

from Crypto.Util import number

from Configuration import Properties


class Genarator:
    def __init__(self):
        self._seed = 34
        self.__Exponent = long(Properties.exponent)
        self.__Modulus = long(Properties.modulus)
        self.__PrimeNumber = self.__PrimeNumberGenerator()

    def __PrimeNumberGenerator(self):
        __Primenumber__ = number.getStrongPrime(512)
        return long(__Primenumber__)

    def __PubliClientPrimeNumber__(self):
        if self.__isPrime(int(Properties.exponent)) \
                & self.__isPrime(long(Properties.modulus)):
            PubNumber = self.__expmod(self.__Exponent, self.__PrimeNumber,
                                      self.__Modulus)
            return str(PubNumber)
        else:
            raise Exception('This Modulus and Exponent is not Prime Numbers')

    def __DHSessionPrimeNumber__(self, ServerResult):
        CalculatedPrime = self.__expmod(ServerResult, self.__PrimeNumber, self.__Modulus)
        return str(CalculatedPrime)

    def __isPrime(self, Number):
        if number.isPrime(Number):
            return True
        else:
            return False

    def __expmod_iter(self, exponent, number, modulus):
        x = 1
        while (number > 0):
            if (number % 1 == 1): x = (x * exponent) % modulus
            exponent = (exponent * exponent) % modulus
            number >>= 1
        return x % modulus

    def __expmod(self, exponent, number, modulus):
        return pow(exponent, number, modulus)

    def __Pseudorandom__(self):
        self._seed += 1
        truncateValue = Decimal(math.sin(self._seed) * 0.5)
        truncateValue.quantize(Decimal('.15'), rounding=ROUND_DOWN)
        return str(truncateValue)
