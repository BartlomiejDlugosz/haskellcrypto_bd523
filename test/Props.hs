import Test.Tasty (defaultMain, TestTree, testGroup)

import Crypto

import Test.Tasty.QuickCheck ( testProperty, forAllShow, Property
                             , Gen, elements, listOf
                             , (==>)
                             , NonNegative(..)
                             , Arbitrary(..), shrinkList)

import Prelude hiding (subtract, gcd)

-- run with `cabal test --test-options="--color always"` for colour if desired
main :: IO ()
main = defaultMain props

{-
Property-Based Testing (OPTIONAL)
=================================

This testing file is using something called "property-based testing" (PBT). Unlike "unit testing",
which is seen in the other file and is normally what you'd be checked against, PBT does not require
you to specify specific concrete examples. Instead, you define properties that you expect to be
true of your program, and the test engine will generate examples automatically to try and disprove it.
Furthermore, it will often try and minimise the test-case for you, by shrinking any counter-examples.

This is a really powerful technique and, ideally, any counter-examples that it finds should be
turned into regular unit tests for the future. It's not important how this actually works to be
able to make use of it and these tests are UNASSESSED. You may find them useful for testing your
code, however!

I'll explain what's going on below for those interested, but you really don't need to understand
this! If you get confused, try taking another look at it again in a few weeks time :)
-}

-- like the other file, we can define individual test properties and give them a name
-- a property is usually a function from some values you want to define the property over
-- which returns a `Property`: quick-check will figure out how to fill these in, you don't
-- need to worry.
props :: TestTree
props = testGroup "crypto"
  [ testGroup "part 1"
      [ testProperty "RSA encrypt/decrypt should roundtrip" roundtripRSA ]
  , testGroup "part 2"
      [ testProperty "ECB encrypt/decrypt should roundtrip" roundtripECB
      , testProperty "ECB encryption is deterministic" deterministicECB
      , testProperty "CBC encrypt/decrypt should roundtrip" roundtripCBC
      ]
  ]


-------------------------------------------------------------------------------
-- PART 1 : asymmetric encryption

{-
This property is found in the specification for this exercise: given two distinct prime numbers
`p` and `q`, we expect that any value `x` that is less than their product will be the same after
it has been encoded and then decoded again: this is called a "round-trip" property.

We will generate the prime numbers internally in the property, but this takes a `NonNegative Int`
argument: this tells quick-check that we want it to find numbers that are `Int`s and also `> 0`.
If this property fails, you'll see something like `NonNegative {getNonNegative = 14}` say: just
read this as `x = 14`.

Within a property, we can use `forAll` to generate more values given a specific generator, or
`Gen`. The `forAllShow` function is a fancier version of `forAll` that also allows us to specify
how to print values obtained from the forall if it fails (this will make it easier for you to read
the counter-examples). The `\p ->` and `\q ->` are just defining functions in-place, which helps
readability of the property (these are called lambdas, you'll learn about them soon enough).
Inside these lambdas is what should happen with the generated values.

`==>` here means "implication". Basically, the property we want
to test is only valid when the two prime numbers `p` and `q` that we asked for are distinct from
each other, and the `x` we are going to encrypt is less than their product. We test for this with
`p /= q && x < p*q` and then `==>` says that what follows requires this condition holds. The
right-hand side of `==>` then actually describes the property itself.
-}
roundtripRSA :: NonNegative Int -> Property
roundtripRSA (NonNegative x) =
  forAllShow largePrimes showP (\p ->
    forAllShow largePrimes showQ (\q ->
      -- pick two distinct primes such that x is less than their product
      p /= q && x < p*q ==>
        -- this is just the property itself: generate the public and private keys
        -- then encrypt, decrypt, and then check nothing has changed
        let (pub, priv) = genKeys p q
        in rsaDecrypt (rsaEncrypt x pub) priv == x
  ))
  where
    showP p = "p = " ++ show p
    showQ q = "q = " ++ show q

-------------------------------------------------------------------------------
-- PART 2 : symmetric encryption

{-
Another simple roundtrip property, here `Message` should denote a string of
regular letters: how quick-check generates that is at the bottom of this file,
but it is using material from much later in the course, so don't worry about it.
-}
newtype Message = Message String
roundtripECB :: Message -> Property
roundtripECB (Message msg) =
  forAllShow letter showKey (\key ->
    ecbDecrypt key (ecbEncrypt key msg) == msg
  )
  where
    showKey k = "key = " ++ show k

{-
The spec says that one of the downsides of ECB encryption is that it is deterministic:
  "if the same block appears twice in the plain text, it will be encrypted into the
   same block in the ciphertext"
While this is certainly not a desirable property to have, it is a property nonetheless.
As such, we can test for it!

Take some arbitrary plain-text message, `msg`, and concatenate it with itself.
It should be the case that, for any key, if we split the encrypted message in half,
both halves should be the same.
-}
deterministicECB :: Message -> Property
deterministicECB (Message msg) =
  forAllShow letter showKey (\key ->
    -- this is only worth testing for a non-empty message
    not (null msg) ==>
      let enc = ecbEncrypt key msg'
          (enc1, enc2) = splitAt halfwayPoint enc
      in enc1 == enc2
  )
  where msg' = msg ++ msg
        halfwayPoint = length msg
        showKey k = "key = " ++ show k

roundtripCBC :: Message -> Property
roundtripCBC (Message msg) =
  forAllShow letter showKey (\key ->
    forAllShow letter showIV (\iv ->
      cbcDecrypt key iv (cbcEncrypt key iv msg) == msg
  ))
  where
    showKey k = "key = " ++ show k
    showIV iv = "initialisation vector = " ++ show iv

{-
This is called a "generator". Its job is to produce values, in this case, of type `Int`.

Here, we want a source of prime numbers. However, writing a prime number generator in the
form that quick-check requires would be really quite difficult without running into efficiency
problems, so this simple one will have to do.

All it does is that each time quick-check asks for a prime number, it will randomly choose one
of the primes I've defined in this list (this is what `elements` does). If you want you can
add more: once your code is all working, add a non-prime number here and see what happens ;)
-}
largePrimes :: Gen Int
largePrimes = elements [2, 3, 5, 7, 11, 101, 83, 401, 937, 613, 997]

letter :: Gen Char
letter = elements ['a' .. 'z']

{-
This all involves stuff you'll learn about much much later: ignore it for now.
-}
instance Arbitrary Message where
  arbitrary = fmap Message (listOf letter)
  shrink (Message msg) = map Message (shrinkList (const []) msg)
instance Show Message where
  show (Message msg) = "message = " ++ show msg
