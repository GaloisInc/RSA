{-# LANGUAGE DeriveDataTypeable #-}
{-# LANGUAGE MultiWayIf         #-}
module Codec.Crypto.RSA.Pure(
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


import Control.Exception
import Control.Monad
import Crypto.Random
import Crypto.Types.PubKey.RSA
import Data.Binary
import Data.Binary.Get
import Data.Binary.Put
import Data.Bits
import Data.ByteString.Lazy(ByteString)
import qualified Data.ByteString.Lazy as BS
import Data.Digest.Pure.SHA
import Data.Int
import Data.Typeable

data RSAError = RSAError String
              | RSAKeySizeTooSmall
              | RSAIntegerTooLargeToPack
              | RSAMessageRepOutOfRange
              | RSACipherRepOutOfRange
              | RSAMessageTooShort
              | RSAMessageTooLong
              | RSAMaskTooLong
              | RSAIncorrectSigSize
              | RSAIncorrectMsgSize
              | RSADecryptionError
              | RSAGenError GenError
 deriving (Eq, Show, Typeable)

instance Exception RSAError

data HashInfo = HashInfo {
    algorithmIdent :: ByteString -- ^The ASN.1 DER encoding of the hash function
                                 -- identifier.
  , hashFunction   :: ByteString -> ByteString -- ^The hash function
  }

instance Show SystemRandom where
  show _ = "SystemRandom"

class RSAKey a where
  genKeySize :: a -> Int

instance RSAKey PublicKey where
  genKeySize = public_size

instance RSAKey PrivateKey where
  genKeySize = private_size

instance Binary PublicKey where
  put pk = do sizeBS <- failOnError (i2osp (public_size pk) 8)
              nBS <- failOnError (i2osp (public_n pk) (public_size pk))
              putLazyByteString sizeBS
              putLazyByteString nBS
  get    = do len <- (fromIntegral . os2ip) `fmap` getLazyByteString 8
              n   <- os2ip `fmap` getLazyByteString len
              return (PublicKey (fromIntegral len) n 65537)

instance Binary PrivateKey where
  put pk = do put (private_pub pk)
              dBS <- failOnError (i2osp (private_d pk) (public_size (private_pub pk)))
              putLazyByteString dBS
  get    = do pub <- get
              d   <- os2ip `fmap` getLazyByteString (fromIntegral (public_size pub))
              return (PrivateKey pub d 0 0 0 0 0)

failOnError :: (Monad m, Show a) => Either a b -> m b
failOnError (Left e)  = error (show e)
failOnError (Right b) = return b

-- ----------------------------------------------------------------------------

-- |Randomly generate a key pair of the given modules length (in bits) to use
-- in any of the following functions. Use of a good random number generator is
-- of considerable importance when using this function. The input
-- CryptoRandomGen should never be used again for any other purpose; either
-- use the output'd generator or throw it all away.
generateKeyPair :: CryptoRandomGen g =>
                   g -> Int ->
                   Either RSAError (PublicKey, PrivateKey, g)
generateKeyPair g sizeBits = do
  let keyLength = fromIntegral (sizeBits `div` 8)
  (p, q, g') <- generatePQ g keyLength
  let n          = p * q
      phi        = (p - 1) * (q - 1)
      e          = 65537
      d          = modular_inverse e phi
  let publicKey  = PublicKey keyLength n e
      privateKey = PrivateKey publicKey d p q 0 0 0
  return (publicKey, privateKey, g')

-- ----------------------------------------------------------------------------

-- |Compute a signature for the given ByteString, using the SHA256 algorithm
-- in the computation. This is currently defined as rsassa_pkcs1_v1_5_sign
-- hashSHA256. If you want to use a different function, simply use the PKCS
-- function, below; it will accept arbitrarily-length messages.
sign :: PrivateKey -> ByteString -> Either RSAError ByteString
sign = rsassa_pkcs1_v1_5_sign hashSHA256

-- |Verify a signature for the given ByteString, using the SHA25 algorithm in
-- the computation. Again, if you'd like to use a different algorithm, use the
-- rsassa_pkcs1_v1_5_verify function.
verify :: PublicKey {- ^The key of the signer -} ->
          ByteString {- ^The message -} ->
          ByteString {- ^The purported signature -} ->
          Either RSAError Bool
verify = rsassa_pkcs1_v1_5_verify hashSHA256

-- ----------------------------------------------------------------------------

-- |Encrypt an arbitrarily-sized message given the public key and reasonable
-- options. This is equivalent to calling encryptOAEP with SHA-256 as the
-- hash function, MGF1(SHA-256) as the mask generation function, and no label.
-- NOTE: This hash choice means that your key size must be 1024 bits or larger.
encrypt :: CryptoRandomGen g =>
           g -> PublicKey -> ByteString ->
           Either RSAError (ByteString, g)
encrypt g k m = encryptOAEP g sha256' (generateMGF1 sha256') BS.empty k m
 where sha256' = bytestringDigest . sha256

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
               Either RSAError (ByteString, g)
encryptOAEP g hash mgf l k m =
  do unless ((keySize - (2 * hashLength) - 2) > 0) $ Left RSAKeySizeTooSmall
     let chunks = chunkBSForOAEP k hash m
     (chunks', g') <- mapM' g chunks (\ x -> rsaes_oaep_encrypt x hash mgf k l)
     return (BS.concat chunks', g')
 where
  keySize = public_size k
  hashLength = fromIntegral (BS.length (hash BS.empty))

-- |Encrypt an arbitrarily-sized message using PKCS1 v1.5 encoding. This
-- encoding is deprecated, and should only be used when interacting with
-- legacy software that cannot be modified.
encryptPKCS :: CryptoRandomGen g =>
               g -> PublicKey -> ByteString ->
               Either RSAError (ByteString, g)
encryptPKCS g k m =
  do let chunks = chunkBSForPKCS k m
     (chunks', g') <- mapM' g chunks (\ x -> rsaes_pkcs1_v1_5_encrypt x k)
     return (BS.concat chunks', g')

-- this is just handy
mapM' :: CryptoRandomGen g =>
         g -> [ByteString] ->
         (g -> ByteString -> Either RSAError (ByteString, g)) ->
         Either RSAError ([ByteString], g)
mapM' g []       _ = Right ([], g)
mapM' g (x:rest) f =
  do (x', g')     <- f g x
     (rest', g'') <- mapM' g' rest f
     return (x':rest', g'')

-- ----------------------------------------------------------------------------

-- |Decrypt an arbitrarily-sized message given the public key and reasonable
-- options. This is equivalent to calling encryptOAEP with SHA-256 as the
-- hash function, MGF1(SHA-256) as the mask generation function, and no label.
decrypt :: PrivateKey -> ByteString -> Either RSAError ByteString
decrypt k m = decryptOAEP sha256' (generateMGF1 sha256') BS.empty k m
 where sha256' = bytestringDigest . sha256

-- |Decrypt an arbitrarily-sized message using OAEP encoding. This is the
-- encouraged encoding for doing RSA encryption.
decryptOAEP :: (ByteString -> ByteString) {- ^The hash function to use -} ->
               MGF {- ^The mask generation function to use -} ->
               ByteString {- ^An optional label to include -} ->
               PrivateKey {- ^The public key to encrypt with -} ->
               ByteString {- ^The message to decrypt -} ->
               Either RSAError ByteString
decryptOAEP hash mgf l k m =
  do let chunks = chunkify m (fromIntegral (private_size k))
     chunks' <- forM chunks (rsaes_oaep_decrypt hash mgf k l)
     return (BS.concat chunks')

-- |Decrypt an arbitrarily-sized message using PKCS1 v1.5 encoding. This
-- encoding is deprecated, and should only be used when interacting with
-- legacy software that cannot be modified.
decryptPKCS :: PrivateKey -> ByteString -> Either RSAError ByteString
decryptPKCS k m =
  do let chunks = chunkify m (fromIntegral (private_size k))
     chunks' <- forM chunks (rsaes_pkcs1_v1_5_decrypt k)
     return (BS.concat chunks')

-- ----------------------------------------------------------------------------

-- |Chunk an aribitrarily-sized message into a series of chunks that can be
-- encrypted by an OAEP encryption / decryption function.
chunkBSForOAEP :: RSAKey k =>
                  k {- ^The key being used -} ->
                  (ByteString -> ByteString) {- ^The hash function in use -} ->
                  ByteString {- ^The ByteString to chunk -} ->
                  [ByteString]
chunkBSForOAEP k hash bs = chunkify bs chunkSize
 where
  chunkSize = fromIntegral (genKeySize k) - (2 * hashLen) - 2
  hashLen   = BS.length (hash BS.empty)

-- |Chunk an arbitrarily-sized message into a series of chunks that can be
-- encrypted by a PKCS1 1.5 encryption / decryption function.
chunkBSForPKCS :: RSAKey k => k -> ByteString -> [ByteString]
chunkBSForPKCS k bstr = chunkify bstr (fromIntegral (genKeySize k) - 11)

chunkify :: ByteString -> Int64 -> [ByteString]
chunkify bs size
  | BS.length bs == 0 = []
  | otherwise         = let (start, end) = BS.splitAt size bs
                        in start : chunkify end size

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
                      Either RSAError (ByteString, g)
rsaes_oaep_encrypt g hash mgf k l m =
  do let hashLength = fromIntegral (BS.length (hash BS.empty))
         keySize    = public_size k
         msgLength  = fromIntegral (BS.length m)
     -- WARNING: Step 1a is missing
     when (msgLength > (keySize - (2 * hashLength) - 2)) $            -- Step 1b
       Left RSAMessageTooLong
     let lHash = hash l                                               -- Step 2a
     let zeros = BS.repeat 0                                          -- Step 2b
         numZeros = keySize - msgLength - (2 * hashLength) - 2
         ps = BS.take (fromIntegral numZeros) zeros
     let db = BS.concat [lHash, ps, BS.singleton 1, m]                -- Step 2c
     (seed, g') <- randomBS g hashLength                              -- Step 2d
     dbMask <- mgf seed (fromIntegral (keySize - hashLength - 1))     -- Step 2e
     let maskedDB = db `xorBS` dbMask                                 -- Step 2f
     seedMask <- mgf maskedDB (fromIntegral hashLength)               -- Step 2g
     let maskedSeed = seed `xorBS` seedMask                           -- Step 2h
     let em = BS.concat [BS.singleton 0, maskedSeed, maskedDB]        -- Step 2i
     let m_i = os2ip em                                               -- Step 3a
     c_i <- rsa_ep (public_n k) (public_e k) m_i                      -- Step 3b
     c <- i2osp c_i (public_size k)                                   -- Step 3c
     return (c, g')

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
                      Either RSAError ByteString
rsaes_oaep_decrypt hash mgf k l c =
  do let hashLength = BS.length (hash BS.empty)
         keySize    = private_size k
     -- WARNING: Step 1a is missing!
     unless (BS.length c == fromIntegral keySize) $                -- Step 1b
       Left RSADecryptionError
     unless (fromIntegral keySize >= ((2 * hashLength) + 2)) $     -- Step 1c
       Left RSADecryptionError
     let c_ip = os2ip c                                            -- Step 2a
     m_ip <- rsa_dp (private_n k) (private_d k) c_ip               -- Step 2b
     em <- i2osp m_ip keySize                                      -- Step 2c
     let lHash = hash l                                            -- Step 3a
     let (y, seed_db) = BS.splitAt 1 em                            -- Step 3b
         (maskedSeed, maskedDB) = BS.splitAt (fromIntegral hashLength) seed_db
     seedMask <- mgf maskedDB hashLength                           -- Step 3c
     let seed     = maskedSeed `xorBS` seedMask                    -- Step 3d
     dbMask <- mgf seed (fromIntegral keySize - hashLength - 1)    -- Step 3e
     let db       = maskedDB `xorBS` dbMask                        -- Step 3f
     let (lHash', ps_o_m) = BS.splitAt hashLength db               -- Step 3g
         (ps, o_m)        = BS.span (== 0) ps_o_m
         (o, m)           = BS.splitAt 1 o_m
     unless (BS.unpack o == [1]) $ Left RSADecryptionError
     unless (lHash' == lHash)    $ Left RSADecryptionError
     unless (BS.unpack y == [0]) $ Left RSADecryptionError
     unless (BS.all (== 0) ps)   $ Left RSADecryptionError
     return m

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
                            Either RSAError (ByteString, g)
rsaes_pkcs1_v1_5_encrypt g k m =
  do unless (fromIntegral (BS.length m) <= (public_size k - 11)) $ -- Step 1
       Left RSAIncorrectMsgSize
     (ps, g') <- randomNZBS g (public_size k - fromIntegral (BS.length m) - 3)
     let em = BS.concat [BS.singleton 0, BS.singleton 2, ps, BS.singleton 0, m]
     let m' = os2ip em
     c_i <- rsa_ep (public_n k) (public_e k) m'
     res <- i2osp c_i (fromIntegral (public_size k))
     return (res, g')

-- |Implements RSAES-PKCS1-v1.5-Decrypt, for completeness and possible backward
-- compatibility. Please see the notes for rsaes_pkcs_v1_5_encrypt regarding
-- use of this function in new applications without backwards compatibility
-- requirements.
--
-- The ciphertext message passed to this function must be of length k, where
-- k is the length of the key modulus in bytes.
rsaes_pkcs1_v1_5_decrypt :: PrivateKey -> ByteString ->
                            Either RSAError ByteString
rsaes_pkcs1_v1_5_decrypt k c =
  do unless (fromIntegral (BS.length c) == private_size k) $    -- Step 1
       Left RSAIncorrectMsgSize
     let c_i = os2ip c                                          -- Step 2a
     m_i  <- rsa_dp (private_n k) (private_d k) c_i             -- Step 2b
     em   <- i2osp m_i (private_size k)                         -- Step 2c
     let (zt, ps_z_m) = BS.splitAt 2 em                         -- Step 3...
         (ps, z_m)    = BS.span (/= 0) ps_z_m
         (z, m)       = BS.splitAt 1 z_m
     when (BS.unpack zt /= [0,2]) $ Left RSADecryptionError
     when (BS.unpack z  /= [0])   $ Left RSADecryptionError
     when (BS.length ps <  8 )    $ Left RSADecryptionError
     return m

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
                          Either RSAError ByteString -- ^ The signature
rsassa_pkcs1_v1_5_sign hi k m =
  do em  <- emsa_pkcs1_v1_5_encode hi m (private_size k) -- Step 1
     let m_i = os2ip em                                  -- Step 2a
     s   <- rsa_sp1 (private_n k) (private_d k) m_i      -- Step 2b
     sig <- i2osp s (private_size k)                     -- Step 2c
     return sig

-- |Validate a signature for the given message using the given public key. The
-- signature must be exactly k bytes long, where k is the size of the RSA
-- modulus IN BYTES.
rsassa_pkcs1_v1_5_verify :: HashInfo {- ^The hash function to use -} ->
                            PublicKey {-^The public key to validate against-} ->
                            ByteString {- ^The message that was signed -} ->
                            ByteString {- ^The purported signature -} ->
                            Either RSAError Bool
rsassa_pkcs1_v1_5_verify hi k m s
  | BS.length s /= fromIntegral (public_size k)  = Left RSAIncorrectSigSize
  | otherwise                                    =
      do let s_i = os2ip s                                  -- Step 2a
         m_i <- rsa_vp1 (public_n k) (public_e k) s_i       -- Step 2b
         em  <- i2osp m_i (public_size k)                   -- Step 2c
         em' <- emsa_pkcs1_v1_5_encode hi m (public_size k) -- Step 3
         return (em == em')

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
generateMGF1 hash mgfSeed maskLen
  | BS.length mgfSeed > ((2 ^ (32::Integer)) * hLen) = Left RSAMaskTooLong
  | otherwise                                        = loop BS.empty 0
 where
  hLen       = BS.length (hash BS.empty)
  endCounter = (maskLen `divCeil` hLen) - 1
  loop t counter
    | counter > endCounter = Right (BS.take maskLen t)
    | otherwise            = do c <- i2osp counter 4
                                let bs = mgfSeed `BS.append` c
                                    t' = t `BS.append` hash bs
                                loop t' (counter + 1)

-- ----------------------------------------------------------------------------

-- "i2osp converts a nonnegative integer to an octet string of a specified
-- length" -- RFC 3447
i2osp :: Integral a => a -> Int -> Either RSAError ByteString
i2osp x len | isTooLarge = Left RSAIntegerTooLargeToPack
            | otherwise  = Right (padding `BS.append` digits)
 where
  isTooLarge  = (fromIntegral x :: Integer) >=
                (256 ^ (fromIntegral len :: Integer))
  padding     = BS.replicate (fromIntegral len - BS.length digits) 0
  digits      = BS.reverse (BS.unfoldr digitize x)
  digitize 0  = Nothing
  digitize v  = let (q, r) = divMod v 256
                in Just (fromIntegral r, q)

-- "os2ip converts an octet string to a nonnegative integer" - RFC 3447
os2ip :: ByteString -> Integer
os2ip = BS.foldl (\ a b -> (256 * a) + (fromIntegral b)) 0

-- the RSA encryption function
rsa_ep :: Integer -> Integer -> Integer -> Either RSAError Integer
rsa_ep n _ m | (m < 0) || (m >= n) = Left RSAMessageRepOutOfRange
rsa_ep n e m                       = Right (modular_exponentiation m e n)

-- the RSA decryption function
rsa_dp :: Integer -> Integer -> Integer -> Either RSAError Integer
rsa_dp n _ c | (c < 0) || (c >= n) = Left RSACipherRepOutOfRange
rsa_dp n d c                       = Right (modular_exponentiation c d n)

-- the RSA signature generation function
rsa_sp1 :: Integer -> Integer -> Integer -> Either RSAError Integer
rsa_sp1 n _ m | (m < 0) || (m >= n) = Left RSAMessageRepOutOfRange
rsa_sp1 n d m                       = Right (modular_exponentiation m d n)

-- the RSA signature verification function
rsa_vp1 :: Integer -> Integer -> Integer -> Either RSAError Integer
rsa_vp1 n _ s | (s < 0) || (s >= n) = Left RSACipherRepOutOfRange
rsa_vp1 n e s                       = Right (modular_exponentiation s e n)

-- EMSA PKCS1 1.5 encoding
emsa_pkcs1_v1_5_encode :: HashInfo -> ByteString -> Int ->
                          Either RSAError ByteString
emsa_pkcs1_v1_5_encode (HashInfo ident hash) m emLen
  | fromIntegral emLen < (tLen + 1) = Left RSAMessageTooShort
  | otherwise                       = Right em
 where
  h = hash m
  t = ident `BS.append` h
  tLen = BS.length t
  ps = BS.replicate (fromIntegral emLen - tLen - 3) 0xFF
  em = BS.concat [BS.singleton 0x00,BS.singleton 0x01,ps,BS.singleton 0x00,t]

-- ----------------------------------------------------------------------------

-- Perform pair-wise xor of all the bytes in a bytestring
xorBS :: ByteString -> ByteString -> ByteString
xorBS a b = BS.pack (BS.zipWith xor a b)

-- Divide a by b, rounding towards positive infinity
divCeil :: Integral a => a -> a -> a
divCeil a b = let (q, r) = divMod a b
              in if r /= 0 then (q + 1) else q

-- Generate p and q. This is not necessarily the best way to do this, but it
-- appears to work.
generatePQ :: CryptoRandomGen g =>
              g ->
              Int ->
              Either RSAError (Integer, Integer, g)
generatePQ g len
  | len < 2   = Left RSAKeySizeTooSmall
  | otherwise = do (baseP, g')  <- largeRandomPrime g  (len `div` 2)
                   (baseQ, g'') <- largeRandomPrime g' (len - (len `div` 2))
                   case () of
                     () | baseP == baseQ -> generatePQ g'' len
                        | baseP <  baseQ -> return (baseQ, baseP, g'')
                        | otherwise      -> return (baseP, baseQ, g'')

-- |Generate a large random prime of a given length in bytes.
largeRandomPrime :: CryptoRandomGen g =>
                    g -> Int ->
                    Either RSAError (Integer, g)
largeRandomPrime g len =
  do (h_t, g')            <- randomBS g 2
     let [startH, startT]  = BS.unpack h_t
     (startMids, g'')     <- randomBS g' (len - 2)
     let bstr              = BS.concat [BS.singleton (startH .|. 0xc0),
                                        startMids, BS.singleton (startT .|. 1)]
     findNextPrime g'' (os2ip bstr)

-- |Generate a random ByteString of the given length
randomBS :: CryptoRandomGen g => g -> Int -> Either RSAError (ByteString, g)
randomBS g n =
  case genBytes n g of
    Left e -> Left (RSAGenError e)
    Right (bs, g') -> Right (BS.fromChunks [bs], g')

-- |Create a random bytestring of non-zero bytes of the given length.
randomNZBS :: CryptoRandomGen g => g -> Int -> Either RSAError (ByteString, g)
randomNZBS gen 0    = return (BS.empty, gen)
randomNZBS gen size =
  do (bstr, gen') <- randomBS gen size
     let nzbstr = BS.filter (/= 0) bstr
     (rest, gen'') <- randomNZBS gen' (size - fromIntegral (BS.length nzbstr))
     return (nzbstr `BS.append` rest, gen'')

-- |Given a number, probabalistically find the first prime number that occurs
-- after it.
findNextPrime :: CryptoRandomGen g =>
                 g -> Integer ->
                 Either RSAError (Integer, g)
findNextPrime g n
  | even n             = findNextPrime g (n + 1)
  | n `mod` 65537 == 1 = findNextPrime g (n + 2)
  | otherwise          = case isProbablyPrime g n of
                           Left e            -> Left e
                           Right (True,  g') -> Right (n, g')
                           Right (False, g') -> findNextPrime g' (n + 2)

-- |Probabilistically test whether or not a given number is prime by first
-- checking some obvious factors and then defaulting to the Miller-Rabin
-- test. Should save time for numbers that are trivially composite.
isProbablyPrime :: CryptoRandomGen g =>
                   g {- ^a good random number generator -} ->
                   Integer {- ^the number to test -} ->
                   Either RSAError (Bool, g)
isProbablyPrime g n
  | n < 541                                  = Right (n `elem` small_primes, g)
  | any (\ x -> n `mod` x == 0) small_primes = Right (False, g)
  | otherwise                                = millerRabin g n 100

-- the first 200 prime numbers
small_primes :: [Integer]
small_primes = [
      2,     3,     5,     7,    11,    13,    17,    19,    23,    29,
     31,    37,    41,    43,    47,    53,    59,    61,    67,    71,
     73,    79,    83,    89,    97,   101,   103,   107,   109,   113,
    127,   131,   137,   139,   149,   151,   157,   163,   167,   173,
    179,   181,   191,   193,   197,   199,   211,   223,   227,   229,
    233,   239,   241,   251,   257,   263,   269,   271,   277,   281,
    283,   293,   307,   311,   313,   317,   331,   337,   347,   349,
    353,   359,   367,   373,   379,   383,   389,   397,   401,   409,
    419,   421,   431,   433,   439,   443,   449,   457,   461,   463,
    467,   479,   487,   491,   499,   503,   509,   521,   523,   541,
    547,   557,   563,   569,   571,   577,   587,   593,   599,   601,
    607,   613,   617,   619,   631,   641,   643,   647,   653,   659,
    661,   673,   677,   683,   691,   701,   709,   719,   727,   733,
    739,   743,   751,   757,   761,   769,   773,   787,   797,   809,
    811,   821,   823,   827,   829,   839,   853,   857,   859,   863,
    877,   881,   883,   887,   907,   911,   919,   929,   937,   941,
    947,   953,   967,   971,   977,   983,   991,   997,  1009,  1013,
   1019,  1021,  1031,  1033,  1039,  1049,  1051,  1061,  1063,  1069,
   1087,  1091,  1093,  1097,  1103,  1109,  1117,  1123,  1129,  1151,
   1153,  1163,  1171,  1181,  1187,  1193,  1201,  1213,  1217,  1223
  ]

-- |Probabilistically test whether or not a given number is prime using
-- the Miller-Rabin test.
millerRabin :: CryptoRandomGen g =>
               g {- ^a good random number generator -} ->
               Integer {- ^the number to test -} ->
               Int {- ^the accuracy of the test -} ->
               Either RSAError (Bool, g)
millerRabin g n k
  | n <= 0    = Left (RSAError "Primality test on negative number or 0.")
  | n == 1    = Right (False, g)
  | n == 2    = Right (True, g)
  | n == 3    = Right (True, g)
  | otherwise =
     -- write (n-1) as 2^s*d with d odd by factoring powers of 2 from n-1
     let (s, d) = oddify 0 (n - 1)
     in checkLoop g s d k
 where
  generateSize = bitsize (n - 2) 8 `div` 8
  -- k times, pick a random integer in [2, n-2] and see if you can find
  -- a witness suggesting that it's not prime.
  checkLoop :: CryptoRandomGen g =>
               g -> Integer -> Integer -> Int ->
               Either RSAError (Bool, g)
  checkLoop g' _ _ 0 = Right (True, g')
  checkLoop g' s d c =
    case genBytes generateSize g' of
      Left e -> Left (RSAGenError e)
      Right (bstr, g'') ->
        let a = os2ip (BS.fromStrict bstr)
            x = modular_exponentiation a d n
        in if | (a < 2)       -> checkLoop g'' s d c
              | (a > (n - 2)) -> checkLoop g'' s d c
              | x == 1        -> checkLoop g'' s d (c - 1)
              | x == (n - 1)  -> checkLoop g'' s d (c - 1)
              | otherwise     -> checkWitnesses g'' s d x c (s - 1)
  -- s times, where n-1 = 2^s*d, check to see if the given number is a
  -- witness of something not being prime.
  checkWitnesses g'' _ _ _ _  0  = Right (False, g'')
  checkWitnesses g'' s d x c1 c2 =
    case (x * x) `mod` n of
       1                -> Right (False, g'')
       y | y == (n - 1) -> checkLoop g'' s d (c1 - 1)
       _                -> checkWitnesses g'' s d x c1 (c2 - 1)
  -- given n, compute s and d such that 2^s*d = n.
  oddify s x | testBit x 0 = (s, x)
             | otherwise   = oddify (s + 1) (x `shiftR` 1)
  -- given n, compute the number of bits required to hold it.
  bitsize v x | (1 `shiftL` x) > v = x
              | otherwise          = bitsize v (x + 8)

-- |Computes a^b mod c using a moderately good algorithm.
modular_exponentiation :: Integer -> Integer -> Integer -> Integer
modular_exponentiation x y m = m_e_loop x y 1
 where
  m_e_loop _ 0 result = result
  m_e_loop b e result = m_e_loop b' e' result'
   where
    b'      = (b * b) `mod` m
    e'      = e `shiftR` 1
    result' = if testBit e 0 then (result * b) `mod` m else result

-- |Compute the modular inverse (d = e^-1 mod phi) via the extended euclidean
-- algorithm.
modular_inverse :: Integer {- ^e -} ->
                   Integer  {- ^phi -} ->
                   Integer
modular_inverse e phi = x `mod` phi
 where (_, x, _) = extended_euclidean e phi

-- Compute the extended euclidean algorithm
extended_euclidean :: Integer -> Integer -> (Integer, Integer, Integer)
extended_euclidean a b | d < 0     = (-d, -x, -y)
                       | otherwise = (d, x, y)
 where
  (d, x, y) = egcd a b

egcd :: Integer -> Integer -> (Integer, Integer, Integer)
egcd 0 b = (b, 0, 1)
egcd a b = let (g, y, x) = egcd (b `mod` a) a
           in (g, x - ((b `div` a) * y), y)

-- ----------------------------------------------------------------------------

hashSHA1 :: HashInfo
hashSHA1 = HashInfo {
   algorithmIdent = BS.pack [0x30,0x21,0x30,0x09,0x06,0x05,0x2b,0x0e,0x03,
                             0x02,0x1a,0x05,0x00,0x04,0x14]
 , hashFunction   = bytestringDigest . sha1
 }

hashSHA224 :: HashInfo
hashSHA224 = HashInfo {
   algorithmIdent = BS.pack [0x30,0x2d,0x30,0x0d,0x06,0x09,0x60,0x86,0x48,
                             0x01,0x65,0x03,0x04,0x02,0x04,0x05,0x00,0x04,
                             0x1c]
 , hashFunction   = bytestringDigest . sha224
 }

hashSHA256 :: HashInfo
hashSHA256 = HashInfo {
   algorithmIdent = BS.pack [0x30,0x31,0x30,0x0d,0x06,0x09,0x60,0x86,0x48,
                             0x01,0x65,0x03,0x04,0x02,0x01,0x05,0x00,0x04,
                             0x20]
 , hashFunction   = bytestringDigest . sha256
 }

hashSHA384 :: HashInfo
hashSHA384 = HashInfo {
   algorithmIdent = BS.pack [0x30,0x41,0x30,0x0d,0x06,0x09,0x60,0x86,0x48,
                             0x01,0x65,0x03,0x04,0x02,0x02,0x05,0x00,0x04,
                             0x30]
 , hashFunction   = bytestringDigest . sha384
 }

hashSHA512 :: HashInfo
hashSHA512 = HashInfo {
   algorithmIdent  = BS.pack [0x30,0x51,0x30,0x0d,0x06,0x09,0x60,0x86,0x48,
                              0x01,0x65,0x03,0x04,0x02,0x03,0x05,0x00,0x04,
                              0x40]
 , hashFunction   = bytestringDigest . sha512
 }
