module Crypto ( gcd, smallestCoPrimeOf, phi, computeCoeffs, inverse
              , modPow, genKeys, rsaEncrypt, rsaDecrypt, toInt, toChar
              , add, subtract, ecbEncrypt, ecbDecrypt
              , cbcEncrypt, cbcDecrypt ) where

import Data.Char

import Prelude hiding (gcd, subtract)

{-
The advantage of symmetric encryption schemes like AES is that they are efficient
and we can encrypt data of arbitrary size. The problem is how to share the key.
The flaw of the RSA is that it is slow and we can only encrypt data of size lower
than the RSA modulus n, usually around 1024 bits (64 bits for this exercise!).

We usually encrypt messages with a private encryption scheme like AES-256 with
a symmetric key k. The key k of fixed size 256 bits for example is then exchanged
via the aymmetric RSA.
-}

-------------------------------------------------------------------------------
-- PART 1 : asymmetric encryption

-- | Returns the greatest common divisor of its two arguments
gcd :: Int -> Int -> Int
gcd m n
        | n == 0 = abs m
        | otherwise = gcd n (m `mod` n)

-- | Euler Totient function
phi :: Int -> Int
phi m = length [1 | n <- [1..m], gcd m n == 1]

{-|
Calculates (u, v, d) the gcd (d) and Bezout coefficients (u and v)
such that au + bv = d
-}
computeCoeffs :: Int -> Int -> (Int, Int)
computeCoeffs a b 
        | b == 0 = (1, 0)
        | otherwise = (v, u - q * v)
        where 
                (q, r) = quotRem a b
                (u, v) = computeCoeffs b r

-- | Inverse of a modulo m
inverse :: Int -> Int -> Int
inverse a m 
        | a /= 0 = ((1 - m * v) `div` a) `mod` m
        | otherwise = 0
        where
                (_, v) = computeCoeffs a m

-- | Calculates (a^k mod m)
modPow :: Int -> Int -> Int -> Int
modPow a k m
        | k < 3 = a^k `mod` m
        | even k = ak
        | otherwise = (a * ak) `mod` m
        where 
                ak = modPow (modPow a 2 m) (k `div` 2) m

-- | Helps the smallestCoPrimeOf function by providing an additional parameter
-- | to help loop through the numbers from 2 onwards
smallestCoPrimeHelper :: Int -> Int -> Int
smallestCoPrimeHelper a n
        | gcd a n == 1 = n
        | otherwise = smallestCoPrimeHelper a (n + 1)

-- | Returns the smallest integer that is coprime with phi
smallestCoPrimeOf :: Int -> Int
smallestCoPrimeOf a = smallestCoPrimeHelper a 2

{-|
Generates keys pairs (public, private) = ((e, n), (d, n))
given two "large" distinct primes, p and q
-}
genKeys :: Int -> Int -> ((Int, Int), (Int, Int))
genKeys p q = ((e, n), (d, n))
        where
                n = p * q
                prod = (p - 1) * (q - 1)
                e = smallestCoPrimeOf prod
                d = inverse e prod

-- | This function performs RSA encryption
rsaEncrypt :: Int        -- ^ value to encrypt
           -> (Int, Int) -- ^ public key
           -> Int
rsaEncrypt x (e, n)= modPow x e n

-- | This function performs RSA decryption
rsaDecrypt :: Int        -- ^ value to decrypt
           -> (Int, Int) -- ^ public key
           -> Int
rsaDecrypt c (d, n) = modPow c d n

-------------------------------------------------------------------------------
-- PART 2 : symmetric encryption

-- | Returns position of a letter in the alphabet
toInt :: Char -> Int
toInt c = ord c - ord 'a'

-- | Returns the n^th letter
toChar :: Int -> Char
toChar n = chr (n `mod` (toInt 'z' + 1) + ord 'a')

-- | "adds" two letters
add :: Char -> Char -> Char
add a b = toChar (toInt a + toInt b)

-- | "subtracts" two letters
subtract :: Char -> Char -> Char
subtract a b = toChar (toInt a - toInt b)

-- the next functions present
-- 2 modes of operation for block ciphers : ECB and CBC
-- based on a symmetric encryption function e/d such as "add"

-- | ecb (electronic codebook) encryption with block size of a letter
ecbEncrypt :: Char -> [Char] -> [Char]
ecbEncrypt k = map (`add` k)

-- | ecb (electronic codebook) decryption with a block size of a letter
ecbDecrypt :: Char -> [Char] -> [Char]
ecbDecrypt k = map (`subtract` k)

-- | cbc (cipherblock chaining) encryption with block size of a letter
cbcEncrypt :: Char   -- ^ public key
           -> Char   -- ^ initialisation vector `iv`
           -> [Char] -- ^ message `m`
           -> [Char]
cbcEncrypt _ _ [] = []
cbcEncrypt k iv (m:ms) = ci : cbcEncrypt k ci ms
        where 
                ci = head (ecbEncrypt k [m `add` iv])

-- | cbc (cipherblock chaining) decryption with block size of a letter
cbcDecrypt :: Char   -- ^ private key
           -> Char   -- ^ initialisation vector `iv`
           -> [Char] -- ^ message `m`
           -> [Char]
cbcDecrypt _ _ [] = []
cbcDecrypt k iv (c:cs) = xi : cbcDecrypt k c cs
        where
                xi = head (ecbDecrypt k [c]) `subtract` iv
