"""
*** Author: Laurent Hayez
*** Date: 13 october 2015
*** Course: Security
*** Objective:
"""

import random

class RSAencryption(object):

    def __init__(self):
        self.p = self.random_search(8, 100)
        self.q = self.random_search(8, 100)
        while (self.q == self.p):
            self.q = self.random_search(8, 100)
            # print(self.q, self.p)

        self.n = self.p * self.q
        self.phi_n = (self.p-1)*(self.q-1)

        self.e = self.choose_e(self.phi_n)

        self.d = self.modInverse(self.e, self.phi_n)

        self.private_key = (self.e, self.n) #int(str(self.e)+str(self.n))
        self.public_key = (self.d, self.n) #int(str(self.d)+str(self.n))

        #print("p: ", self.p, "q: ", self.q, "n ", self.n)
        #print("phi(n): ", self.phi_n, "e: ", self.e)
        #print("d: ", self.d)
        #print("Private key: ", self.private_key)
        print("Public key: ", self.public_key)


    # We simply generate random integers until we find a coprime
    def choose_e(self, phi_n):
        e = random.randint(3, self.q if self.q>self.p else self.p)
        while self.extended_gcd(e, phi_n)[0] != 1:
            e = random.randint(3, self.q if self.q>self.p else self.p)
        return e

    # Bezout: there exists integers s,t such that as + bt = gcd(a,b)
    # input: a, b integers with gcd to be computed
    # output: r in N and u, v in Z such that r = gcd(a,b) and r = a*u+b*v
    # source of algorithm: https://fr.wikipedia.org/wiki/Algorithme_d'Euclide_%C3%A9tendu
    def extended_gcd(self, a, b):
        r, u, v, old_r, old_u, old_v = a, 1, 0, b, 0, 1
        while old_r != 0:
            quotient = r // old_r
            r, old_r = old_r, r - quotient * old_r
            u, old_u = old_u, u - quotient * old_u
            v, old_v = old_v, v - quotient * old_v
        # print("1=gcd("+str(a)+", "+str(b)+") = as+bt where s = ", str(u), "and t = ", str(v))
        # print("Control: "+str(a)+"*"+str(u)+"+"+str(b)+"*"+str(v)+"=", str(a*u+b*v))
        return r, u, v

    # By Bezout's relation, we have that e^{-1}mod phi(n) is simply u (1 = eu+phi(n)v).
    # Ref: http://www.labri.fr/perso/betrema/deug/poly/crypto.html
    def modInverse(self, a, b):
        return self.extended_gcd(a, b)[1] % self.phi_n


    def encrypt(self, message, public_key):
        #print("Original message: ", message)
        chars = []
        for car in message:
            encrypted_car = chr(pow(ord(car), public_key[0], public_key[1]))
            chars.append(encrypted_car)
        enc_mess = ''.join(chars)

        #print("Encrypted message: ", enc_mess)
        return enc_mess

    def decrypt(self, message, private_key):
        #print("Encrypted message: ", message)
        chars = []
        for car in message:
            decrypted_car = chr(pow(ord(car), private_key[0], private_key[1]))
            chars.append(decrypted_car)
        dec_mess = ''.join(chars)
        #print("Decrypted message: ", dec_mess)
        return dec_mess

    # factorize to get the right power of 2 in Miller-Rabin test.
    # we have a number n to factorize, and n=2^k*m (eg. 24=2^3*3)
    # we output power = k, n = m (according to the previous comment line)
    def factorize(self, n):
        power = 0
        while n % 2 == 0:
            n = n/2
            power += 1
        return power, n

    # Miller Rabin probabilistic primality test
    # pseudo-code: http://cacr.uwaterloo.ca/hac/about/chap4.pdf, p. 139
    # input: odd integer n >= 3 and security parameter t >= 1
    # output: True if n is prime, False if n is composite.
    def miller_rabin(self, n, t):
        if n == 2 or n == 3 :
            return True
        if n < 2 :
            return False

        power, rest = self.factorize(n-1)

        for i in range(t) :
            a = random.randint(2, n-2)
            y = pow(a, int(rest), n)
            if y != 1 and y != n-1 :
                j = 1
                while j <= power-1 and y != n-1 :
                    y = pow(y, 2, n)
                    if y == 1:
                        return False
                    j += 1
                if y != n-1 :
                    return False
        return True


    def random_odd_k_bit_int(self,k):
        n = random.getrandbits(k)
        return n if n%2 == 1 else n-1

    # Random search for a prime using the Miller-Rabin test
    # Pseudo-code: http://cacr.uwaterloo.ca/hac/about/chap4.pdf, p. 146
    # input: integer k and security parameter t
    # output: random k-bit probable prime
    def random_search(self, k, t):
        # In http://cacr.uwaterloo.ca/hac/about/chap4.pdf, p.146 , it says "If a random k-bit odd integer n is divisible by a small prime,
        # it is less computationally expensive to rule out the candidate n by trial division than by using the Miller-Rabin test."
        # That's why we have the list of the primes <= 100.
        list_primes = [3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97]

        miller_rabin = False
        divisible_by_prime = False

        while not miller_rabin:
            n = self.random_odd_k_bit_int(k)
            for i in list_primes:
                if n % i == 0 and n == i:
                    return n
                elif n % i == 0 and n != i:
                    divisible_by_prime = True
                    break
            if not divisible_by_prime:
                if self.miller_rabin(n, t):
                    miller_rabin = True
                    return n


#rsa = RSAencryption()
#rsa2 = RSAencryption()

#b = rsa.encrypt('Hello World!', rsa2.public_key)
#rsa2.decrypt(b, rsa2.private_key)




#bool = rsa.miller_rabin(123, 100)
#print(bool)


