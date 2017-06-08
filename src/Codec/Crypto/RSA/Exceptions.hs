module Codec.Crypto.RSA.Exceptions(
         RSAError(..)
       , HashInfo(..)
       -- * Keys and key generation
       , PrivateKey(..)
       , PublicKey(..)
       , generateKeyPair
       -- * High-level encryption and signature functions
       , encrypt
       , encryptOAEP
       , encryptPKCS
       , decrypt
       , decryptOAEP
       , decryptPKCS
       , sign
       , verify
       -- * Core routines for OAEP
       , MGF
       , generateMGF1
       , rsaes_oaep_encrypt
       , rsaes_oaep_decrypt
       -- * Core PSS routines
       -- $pss
       -- * Core PKCS1 (v1.5) Routines
       , rsaes_pkcs1_v1_5_encrypt
       , rsaes_pkcs1_v1_5_decrypt
       , rsassa_pkcs1_v1_5_sign
       , rsassa_pkcs1_v1_5_verify
       -- * Hashing algorithm declarations for use in RSA functions
       , hashSHA1
       , hashSHA224, hashSHA256, hashSHA384, hashSHA512
       -- * Other mathematical functions that are handy for implementing
       -- other RSA primitives.
       , largeRandomPrime
       , generatePQ
       , chunkify
       , os2ip, i2osp
       , rsa_dp, rsa_ep
       , rsa_vp1, rsa_sp1
       , modular_inverse
       , modular_exponentiation
       , randomBS, randomNZBS
       )
 where

import qualified Codec.Crypto.RSA.Pure as Pure
import Codec.Crypto.RSA.Pure(HashInfo,RSAError)
import Crypto.Random
import Crypto.Types.PubKey.RSA
import Data.ByteString.Lazy(ByteString)
import Data.Int

-- |Randomly generate a key pair of the given modules length (in bits) to use
-- in any of the following functions. Use of a good random number generator is
-- of considerable importance when using this function. The input
-- CryptoRandomGen should never be used again for any other purpose; either
-- use the output'd generator or throw it all away.
generateKeyPair :: CryptoRandomGen g =>
                   g -> Int ->
                   (PublicKey, PrivateKey, g)
generateKeyPair g sizeBits = throwLeft (Pure.generateKeyPair g sizeBits)

-- ----------------------------------------------------------------------------

-- |Compute a signature for the given ByteString, using the SHA256 algorithm
-- in the computation. This is currently defined as rsassa_pkcs1_v1_5_sign
-- hashSHA256. If you want to use a different function, simply use the PKCS
-- function, below; it will accept arbitrarily-length messages.
sign :: PrivateKey -> ByteString -> ByteString
sign pk bs = throwLeft (Pure.sign pk bs)

-- |Verify a signature for the given ByteString, using the SHA25 algorithm in
-- the computation. Again, if you'd like to use a different algorithm, use the
-- rsassa_pkcs1_v1_5_verify function.
verify :: PublicKey {- ^The key of the signer -} ->
          ByteString {- ^The message -} ->
          ByteString {- ^The purported signature -} ->
          Bool
verify pk m s = throwLeft (Pure.verify pk m s)

-- ----------------------------------------------------------------------------

-- |Encrypt an arbitrarily-sized message given the public key and reasonable
-- options. This is equivalent to calling encryptOAEP with SHA-256 as the
-- hash function, MGF1(SHA-256) as the mask generation function, and no label.
-- NOTE: This hash choice means that your key size must be 1024 bits or larger.
encrypt :: CryptoRandomGen g =>
           g -> PublicKey -> ByteString ->
           (ByteString, g)
encrypt g k m = throwLeft (Pure.encrypt g k m)

-- |Encrypt an arbitrarily-sized message using OAEP encoding. This is the
-- encouraged encoding for doing RSA encryption. Note that your key size
-- must be greater than (2 * hash length + 2) * 8. (For example, the
-- 'encrypt' convenience function uses a 256 bit / 32 byte hash function.
-- Thus, its key must be greater than (2 * 32 + 2) * 8 = 528 bits long,
-- and we suggest 1024 as a lower bound.)
encryptOAEP :: CryptoRandomGen g =>
               g ->
               (ByteString -> ByteString) {- ^The hash function to use -} ->
               MGF {- ^The mask generation function to use -} ->
               ByteString {- ^An optional label to include -} ->
               PublicKey {- ^The public key to encrypt with -} ->
               ByteString {- ^The message to encrypt -} ->
               (ByteString, g)
encryptOAEP g hash mgf l k m = throwLeft (Pure.encryptOAEP g hash mgf l k m)

-- |Encrypt an arbitrarily-sized message using PKCS1 v1.5 encoding. This
-- encoding is deprecated, and should only be used when interacting with
-- legacy software that cannot be modified.
encryptPKCS :: CryptoRandomGen g =>
               g -> PublicKey -> ByteString ->
               (ByteString, g)
encryptPKCS g k m = throwLeft (Pure.encryptPKCS g k m)

-- ----------------------------------------------------------------------------

-- |Decrypt an arbitrarily-sized message given the public key and reasonable
-- options. This is equivalent to calling encryptOAEP with SHA-256 as the
-- hash function, MGF1(SHA-256) as the mask generation function, and no label.
decrypt :: PrivateKey -> ByteString -> ByteString
decrypt k m = throwLeft (Pure.decrypt k m)

-- |Decrypt an arbitrarily-sized message using OAEP encoding. This is the
-- encouraged encoding for doing RSA encryption.
decryptOAEP :: (ByteString -> ByteString) {- ^The hash function to use -} ->
               MGF {- ^The mask generation function to use -} ->
               ByteString {- ^An optional label to include -} ->
               PrivateKey {- ^The public key to encrypt with -} ->
               ByteString {- ^The message to decrypt -} ->
               ByteString
decryptOAEP hash mgf l k m = throwLeft (Pure.decryptOAEP hash mgf l k m)

-- |Decrypt an arbitrarily-sized message using PKCS1 v1.5 encoding. This
-- encoding is deprecated, and should only be used when interacting with
-- legacy software that cannot be modified.
decryptPKCS :: PrivateKey -> ByteString -> ByteString
decryptPKCS k m = throwLeft (Pure.decryptPKCS k m)

-- ----------------------------------------------------------------------------

chunkify :: ByteString -> Int64 -> [ByteString]
chunkify = Pure.chunkify

-- ----------------------------------------------------------------------------

-- |The generalized implementation of RSAES-OAEP-ENCRYPT. Using the default
-- instantiontion of this, provided by the 'encrypt' function, is a pretty
-- good plan if this makes no sense to you, as it is instantiated with
-- reasonable defaults.
--
-- The message to be encrypted may not be longer then (k - 2*hLen - 2),
-- where k is the length of the RSA modulus in bytes and hLen is the length
-- of a hash in bytes. Passing in a larger message will generate an error,
-- represented by the Left constructor. Note that this means that OAEP
-- encryption cannot be used with keys smaller than 512 bits.
--
-- I have not put in a check for the length of the label, because I don't
-- expect you to use more than 2^32 bytes. So don't make me regret that, eh?
--
rsaes_oaep_encrypt :: CryptoRandomGen g =>
                      g ->
                      (ByteString->ByteString) {-^The hash function to use-} ->
                      MGF {- ^An appropriate mask genereation function -} ->
                      PublicKey {- ^The recipient's public key -} ->
                      ByteString {- ^A label to associate with the message
                                    (feel free to use BS.empty) -} ->
                      ByteString {- ^The message to encrypt -} ->
                      (ByteString, g)
rsaes_oaep_encrypt g hash mgf k l m =
  throwLeft (Pure.rsaes_oaep_encrypt g hash mgf k l m)

-- |The generalized implementation of RSAES-OAEP-DECRYPT. Again, 'decrypt'
-- initializes this with a pretty good set of defaults if you don't understand
-- what all of the arguments involve.
--
-- The ciphertext message passed to this function must be k bytes long, where
-- k is the size of the modulus in bytes. If it is not, this function will
-- generate an error, represented by the Left constructor.
--
-- Futher, k (the length of the ciphertext in bytes) must be greater than or
-- equal to (2 * hLen + 2), where hLen is the length of the output of the 
-- hash function in bytes. If this equation does not hold, a (different)
-- error will be generated.
--
-- Finally, there are any number of internal situations that may generate
-- an error indicating that decryption failed.
--
rsaes_oaep_decrypt :: (ByteString->ByteString) {-^The hash function to use-} ->
                      MGF {- ^A mask generation function -} ->
                      PrivateKey {- ^The private key to use -} ->
                      ByteString {- ^An optional label whose
                                     association with the message
                                     should be verified. -} ->
                      ByteString {- ^The ciphertext to decrypt -} ->
                      ByteString
rsaes_oaep_decrypt hash mgf k l c =
  throwLeft (Pure.rsaes_oaep_decrypt hash mgf k l c)

-- ----------------------------------------------------------------------------

-- |Implements RSAES-PKCS1-v1.5-Encrypt, for completeness and backward
-- compatibility. Also because I've already written everything else, so why not?
--
-- This encryption / padding mechanism has several known attacks, which are
-- described in the literature. So unless you absolutely need to use this
-- for some historical reason, you should avoid it.
--
-- The message to be encrypted must be less then or equal to (k - 11) bytes
-- long, where k is the length of the key modulus in bytes.
--
-- Because this function uses an unknown amount of randomly-generated data,
-- it takes an instance of RandomGen rather than taking a random number as
-- input, and returns the resultant generator as output. You should take care
-- that you (a) do not reuse the input generator, thus losing important
-- randomness, and (b) choose a decent instance of RandomGen for passing to
-- this function.
rsaes_pkcs1_v1_5_encrypt :: CryptoRandomGen g =>
                            g ->
                            PublicKey ->
                            ByteString ->
                            (ByteString, g)
rsaes_pkcs1_v1_5_encrypt g k m =
  throwLeft (Pure.rsaes_pkcs1_v1_5_encrypt g k m)

-- |Implements RSAES-PKCS1-v1.5-Decrypt, for completeness and possible backward
-- compatibility. Please see the notes for rsaes_pkcs_v1_5_encrypt regarding
-- use of this function in new applications without backwards compatibility
-- requirements.
--
-- The ciphertext message passed to this function must be of length k, where
-- k is the length of the key modulus in bytes.
rsaes_pkcs1_v1_5_decrypt :: PrivateKey -> ByteString -> ByteString
rsaes_pkcs1_v1_5_decrypt k c = throwLeft (Pure.rsaes_pkcs1_v1_5_decrypt k c)

-- ----------------------------------------------------------------------------

-- $pss
-- |RSASSA-PSS-Sign, RSASSA-PSS-Verify, and the related functions are not
-- included because they are covered by U.S. Patent 7036014, and it's not clear
-- what the restrictions on implementation are. Sorry.

-- ----------------------------------------------------------------------------

-- |Generate a signature for the given message using the given private key,
-- using the RSASSA-PKCS1-v1.5-Sign algorithm. Note that in researching the
-- requirements for this project, several independent sources suggested not
-- using the same key across sign/validate and encrypt/decrypt contexts. You've
-- been warned.
--
-- The output of this function is the signature only, not the message and
-- the signature.
--
-- SIZE CONSTRAINT: The size of the public key (in bytes) must be greater
-- than or equal to the length of the hash identifier plus the length of
-- a hash plus 1. Thus, for example, you cannot use a 256 bit RSA key with
-- MD5: 32 (the size of a 256-bit RSA key in bytes) is less than 18 (the
-- size of MD5's identier) + 16 (the size of an MD5 hash in bytes) + 1,
-- or 35.
--
-- Thus,
--   * for SHA1 and SHA256, use 512+ bit keys
--   * for SHA384 and SHA512, use 1024+ bit keys
--
rsassa_pkcs1_v1_5_sign :: HashInfo {- ^The hash function to use -} ->
                          PrivateKey {- ^The private key to sign with -} ->
                          ByteString {- ^The message to sign -} ->
                          ByteString -- ^ The signature
rsassa_pkcs1_v1_5_sign hi k m =
  throwLeft (Pure.rsassa_pkcs1_v1_5_sign hi k m)

-- |Validate a signature for the given message using the given public key. The
-- signature must be exactly k bytes long, where k is the size of the RSA
-- modulus IN BYTES.
rsassa_pkcs1_v1_5_verify :: HashInfo {- ^The hash function to use -} ->
                            PublicKey {-^The public key to validate against-} ->
                            ByteString {- ^The message that was signed -} ->
                            ByteString {- ^The purported signature -} ->
                            Bool
rsassa_pkcs1_v1_5_verify hi k m s =
  throwLeft (Pure.rsassa_pkcs1_v1_5_verify hi k m s)

-- ----------------------------------------------------------------------------

-- |A 'mask generation function'. The input is a bytestring, and the output
-- is a hash of the given length. Unless you know what you're doing, you 
-- should probably use a MGF1 formulation created with generate_MGF1.
type MGF = ByteString -> Int64 -> Either RSAError ByteString

-- |Generate a mask generation function for the rsaes_oaep_*. As 
-- suggested by the name, the generated function is an instance of the MGF1
-- function. The arguments are the underlying hash function to use and the 
-- size of a hash in bytes.
--
-- The bytestring passed to the generated function cannot be longer than
-- 2^32 * hLen, where hLen is the passed length of the hash. 
generateMGF1 :: (ByteString -> ByteString) -> MGF
generateMGF1 = Pure.generateMGF1

-- ----------------------------------------------------------------------------

-- "i2osp converts a nonnegative integer to an octet string of a specified
-- length" -- RFC 3447
i2osp :: Integral a => a -> Int -> ByteString
i2osp x len = throwLeft (Pure.i2osp x len)

-- "os2ip converts an octet string to a nonnegative integer" - RFC 3447
os2ip :: ByteString -> Integer
os2ip = Pure.os2ip

-- the RSA encryption function
rsa_ep :: Integer -> Integer -> Integer -> Integer
rsa_ep n e m = throwLeft (Pure.rsa_ep n e m)

-- the RSA decryption function
rsa_dp :: Integer -> Integer -> Integer -> Integer
rsa_dp n d c = throwLeft (Pure.rsa_dp n d c)

-- the RSA signature generation function
rsa_sp1 :: Integer -> Integer -> Integer -> Integer
rsa_sp1 n d m = throwLeft (Pure.rsa_sp1 n d m)

-- the RSA signature verification function
rsa_vp1 :: Integer -> Integer -> Integer -> Integer
rsa_vp1 n e s = throwLeft (Pure.rsa_vp1 n e s)

-- ----------------------------------------------------------------------------

-- Generate p and q. This is not necessarily the best way to do this, but it
-- appears to work. 
generatePQ :: CryptoRandomGen g =>
              g ->
              Int ->
              (Integer, Integer, g)
generatePQ g len = throwLeft (Pure.generatePQ g len)

-- |Generate a large random prime of a given length in bytes.
largeRandomPrime :: CryptoRandomGen g => g -> Int -> (Integer, g)
largeRandomPrime g len = throwLeft (Pure.largeRandomPrime g len)

-- |Generate a random ByteString of the given length
randomBS :: CryptoRandomGen g => g -> Int -> (ByteString, g)
randomBS g n = throwLeft (Pure.randomBS g n)

-- |Create a random bytestring of non-zero bytes of the given length.
randomNZBS :: CryptoRandomGen g => g -> Int -> (ByteString, g)
randomNZBS gen size = throwLeft (Pure.randomNZBS gen size)

-- |Computes a^b mod c using a moderately good algorithm.
modular_exponentiation :: Integer -> Integer -> Integer -> Integer
modular_exponentiation = Pure.modular_exponentiation

-- |Compute the modular inverse (d = e^-1 mod phi) via the extended euclidean
-- algorithm.
modular_inverse :: Integer {- ^e -} ->
                   Integer {- ^phi -} ->
                   Integer
modular_inverse = Pure.modular_inverse

-- ----------------------------------------------------------------------------

hashSHA1 :: HashInfo
hashSHA1 = Pure.hashSHA1

hashSHA224 :: HashInfo
hashSHA224 = Pure.hashSHA224

hashSHA256 :: HashInfo
hashSHA256 = Pure.hashSHA256

hashSHA384 :: HashInfo
hashSHA384 = Pure.hashSHA384

hashSHA512 :: HashInfo
hashSHA512 = Pure.hashSHA512
