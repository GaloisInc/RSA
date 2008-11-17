-- |An implementation of RSA (PKCS #1) Cryptography, as described by the
-- RSA standard and RFC 3447.
module Codec.Crypto.RSA(
       -- * Keys and key generations
         PublicKey(..), PrivateKey(..)
       , generateKeyPair
       -- * High-level encryption and signing functions
       , encrypt
       , decrypt
       , sign
       , verify
       , EncryptionOptions(..)
       , encrypt'
       , decrypt'
       -- * Core OAEP Routines
       , MGF
       , rsaes_oaep_encrypt
       , rsaes_oaep_decrypt
       , generate_MGF1
       -- * Core PSS Routines
       -- $pss

       -- * Core PKCS1 (v1.5) Routines
       , rsaes_pkcs1_v1_5_encrypt 
       , rsaes_pkcs1_v1_5_decrypt 
       , rsassa_pkcs1_v1_5_sign
       , rsassa_pkcs1_v1_5_verify
       -- * Hashing algorithm declarations for use in RSA functions
       , HashFunction
       , HashInfo(..)
#ifdef INCLUDE_MD5
       , ha_MD5
#endif
       , ha_SHA1, ha_SHA256, ha_SHA384, ha_SHA512
#ifdef RSA_TEST
       , large_random_prime
       , generate_pq
       , chunkify
       , os2ip, i2osp
       , rsa_dp, rsa_ep
       , rsa_vp1, rsa_sp1
       , modular_inverse
       , modular_exponentiation
#endif
       )
 where

import Data.Bits
import Data.ByteString.Lazy(ByteString)
import qualified Data.ByteString.Lazy as BS
import Data.Digest.Pure.SHA
import Data.Int
import Data.Word
import System.Random

#ifdef USE_BINARY
import Data.Binary
import Data.Binary.Put
import Data.Binary.Get
#endif

#ifdef INCLUDE_MD5
import Data.Digest.Pure.MD5
#endif

data PublicKey = PublicKey { 
    public_size :: Int64   -- ^The size of the RSA modulus, in bytes.
  , public_n    :: Integer -- ^The RSA modulus.
  , public_e    :: Integer -- ^The public exponent.
  }
 deriving (Show)

data PrivateKey = PrivateKey {
    private_size :: Int64   -- ^The size of the RSA modulus, in bytes.
  , private_n    :: Integer -- ^The RSA modulus.
  , private_d    :: Integer -- ^The private exponent.
  }
 deriving (Show)

#ifdef USE_BINARY
instance Binary PublicKey where
  put pk = do putLazyByteString $ i2osp (public_size pk) 8
              putLazyByteString $ i2osp (public_n pk)    (public_size pk)
  get    = do len <- (fromIntegral . os2ip) `fmap` getLazyByteString 8
              n   <- os2ip `fmap` getLazyByteString len
              return $ PublicKey len n 65537 

instance Binary PrivateKey where
  put pk = do putLazyByteString $ i2osp (private_size pk) 8
              putLazyByteString $ i2osp (private_n pk)    (private_size pk)
              putLazyByteString $ i2osp (private_d pk)    (private_size pk)
  get    = do len <- (fromIntegral . os2ip) `fmap` getLazyByteString 8
              n   <- os2ip `fmap` getLazyByteString len
              d   <- os2ip `fmap` getLazyByteString len
              return $ PrivateKey len n d            
#endif

type HashFunction = ByteString -> ByteString
data HashInfo     = HashInfo {
                      algorithmIdent :: ByteString   -- ^The ASN.1 DER encoding
                                                     -- of the hash function
                                                     -- identifier.
                    , hashFunction   :: HashFunction -- ^The hash function.
                    }

-- |A 'mask generation function'. The input is a bytestring, and the output
-- is a hash of the given length. Unless you know what you're doing, you 
-- should probably use a MGF1 formulation created with generate_MGF1.
type MGF          = ByteString -> Int64 -> ByteString

-- --------------------------------------------------------------------------
--
--                      EASY TO USE PUBLIC FUNCTIONS
--
-- --------------------------------------------------------------------------

-- |Randomly generate a key pair of the given modulus length (in bits) to
-- use in any of the following functions. Use of a good random number 
-- generator is of considerable importance when using this function; the 
-- input RandomGen should never be used again for any other purpose.
generateKeyPair :: RandomGen g => g -> Int -> (PublicKey, PrivateKey, g)
generateKeyPair g sizeBits = (PublicKey kLen n e, PrivateKey kLen n d, g')
 where
  kLen       = fromIntegral $ sizeBits `div` 8
  (p, q, g') = generate_pq g kLen
  n          = p * q
  phi        = (p - 1) * (q - 1)
  e          = 65537
  d          = modular_inverse e phi 

data EncryptionOptions = 
    UseOAEP {
      -- |The hash function to use.
      oaep_hash  :: HashFunction 
      -- |The mask generation function to use.
    , oaep_mgf   :: MGF
      -- |The label to annotate items with.
    , oaep_label :: ByteString
    }
  | UsePKCS1_v1_5 

instance Show EncryptionOptions where
  show opt@UseOAEP{} = "<rsa/OAEP hashLen=" ++ show hashLen ++ ">"
   where hashLen = BS.length $ oaep_hash opt BS.empty
  show UsePKCS1_v1_5 = "<rsa/PKCS1_v1.5>"

-- |Encrypt an arbitrarily-sized message using the defaults for RSA 
-- encryption (specifically, using MGF1, SHA-256 as the hash 
-- function, and not adding a label). If the message is longer than the 
-- underlying encryption function can support, it is broken up into parts
-- and each part is encrypted.
encrypt :: RandomGen g => g -> PublicKey -> ByteString -> (ByteString, g)
encrypt = encrypt' (UseOAEP sha256' (generate_MGF1 sha256') BS.empty)

-- |Decrypt an arbitrarily-sized message using the defaults for RSA
-- decryption (specifically, using MGF1, SHA-256 as the hash function,
-- and not adding a label). If the message is longer than the underlying
-- decryption function supports, it is assumed that the message was
-- generated by concatenating a series of blocks.
--
-- While the encryption function, above, can take an arbitrarily-sized
-- message, this function cannot. The message passed must be a multiple
-- of the modulus length.
decrypt :: PrivateKey -> ByteString -> ByteString
decrypt = decrypt' (UseOAEP sha256' (generate_MGF1 sha256') BS.empty)

-- |Compute a signature for the given ByteString, using the SHA256 algorithm
-- in the computation. This is currently defined as rsassa_pkcs1_v1_5_sign 
-- ha_SHA256. If you want to use a different function, simply use the pkcs
-- function, below; it will accept arbitrary-length messages.
sign :: PrivateKey -> ByteString -> ByteString
sign = rsassa_pkcs1_v1_5_sign ha_SHA256

-- |Verity a signature for the given ByteString, using the SHA256 algorithm
-- in the computation. Again, if you'd like to use a different algorithm, 
-- use the rsassa_pkcs1_v1_5_verify function.
--
-- The first bytestring is the message, the second is the signature to check.
verify :: PublicKey -> ByteString -> ByteString -> Bool
verify = rsassa_pkcs1_v1_5_verify ha_SHA256

-- |Encrypt an arbitrarily-sized message using the given options.
encrypt' :: RandomGen g => 
            EncryptionOptions -> g -> PublicKey -> ByteString -> 
            (ByteString, g)
encrypt' (UseOAEP hash mgf l) gen pub m = foldl enc1 (BS.empty, gen) chunks
 where
  hLen              = BS.length $ hash BS.empty
  chunkSize         = public_size pub - (2 * hLen) - 2
  chunks            = chunkify chunkSize m
  enc1 (!res, !g) !cur = let (seed, g') = random g
                             !newc = rsaes_oaep_encrypt hash mgf pub seed l cur
                         in (res `BS.append` newc, g')
encrypt' UsePKCS1_v1_5        gen pub m = foldl enc1 (BS.empty, gen) chunks
 where
  chunkSize         = public_size pub - 11
  chunks            = chunkify chunkSize m
  enc1 (!res, !g) !cur = let (!newc, g')=rsaes_pkcs1_v1_5_encrypt g pub cur
                         in (res `BS.append` newc, g')

-- |Decrypt an arbitrarily-sized message using the given options. Well, sort
-- of arbitrarily sized; the message should be a multiple of the modulus
-- length.
decrypt' :: EncryptionOptions -> PrivateKey -> ByteString -> ByteString
decrypt' opts priv cipher = BS.concat $ map decryptor chunks
 where
  chunks = chunkify (private_size priv) cipher
  decryptor = case opts of
                UseOAEP hash mgf l -> rsaes_oaep_decrypt hash mgf priv l
                UsePKCS1_v1_5      -> rsaes_pkcs1_v1_5_decrypt priv

-- --------------------------------------------------------------------------
--
--                      EXPORTED FUNCTIONS FROM THE SPEC
--
-- --------------------------------------------------------------------------

-- |The generalized implementation of RSAES-OAEP-ENCRYPT. Using the default
-- instantiontion of this, provided by the 'encrypt' function, is a pretty
-- good plan if this makes no sense to you, as it is instantiated with 
-- reasonable defaults.
--
-- The arguments to this function are, in order: the hash function to use,
-- the mask generation function (MGF), the recipient's RSA public key, a
-- random seed, a label to associate with the message, and the message to
-- be encrypted.
--
-- The message to be encrypted may not be longer then (k - 2*hLen - 2), 
-- where k is the length of the RSA modulus in bytes and hLen is the length
-- of a hash in bytes. Passing in a larger message will generate an error.
--
-- I have not put in a check for the length of the label, because I don't
-- expect you to use more than 2^32 bytes. So don't make me regret that, eh?
--
rsaes_oaep_encrypt :: HashFunction -> MGF -> 
                      PublicKey -> Integer -> ByteString -> ByteString ->
                      ByteString
rsaes_oaep_encrypt hash mgf k seed_int l m
  | message_too_long = error "message too long (rsaes_oaep_encrypt)"
  | otherwise        = c
 where
  mLen = BS.length m -- Int64
  hLen = BS.length $ hash BS.empty -- Int64
  kLen = public_size k
  seed = i2osp seed_int hLen
  -- Step 1
  message_too_long = mLen > (kLen - (2 * hLen) - 2)
  -- Step 2
  lHash      = hash l
  ps         = BS.take (kLen - mLen - (2 * hLen) - 2) (BS.repeat 0)
  db         = BS.concat [lHash, ps, BS.singleton 1, m]
  dbMask     = mgf seed (kLen - hLen - 1)
  maskedDB   = db `xorBS` dbMask
  seedMask   = mgf maskedDB hLen
  maskedSeed = seed `xorBS` seedMask
  em         = BS.concat [BS.singleton 0, maskedSeed, maskedDB]
  -- Step 3
  m_ip       = os2ip em
  c_ip       = rsa_ep (public_n k) (public_e k) m_ip
  c          = i2osp c_ip kLen

-- |The generalized implementation of RSAES-OAEP-DECRYPT. Again, 'decrypt'
-- initializes this with a pretty good set of defaults if you don't understand
-- what all of the arguments involve.
--
-- The ciphertext message passed to this function must be k bytes long, where
-- k is the size of the modulus in bytes. If it is not, this function will
-- generate an error.
--
-- Futher, k (the length of the ciphertext in bytes) must be greater than or
-- equal to (2 * hLen + 2), where hLen is the length of the output of the 
-- hash function in bytes. If this equation does not hold, a (different)
-- error will be generated.
--
-- Finally, there are any number of internal situations that may generate
-- an error indicating that decryption failed.
--
-- The arguments to this function are the hash function to use, the mask
-- generation function (MGF), the recipient's private key, the optional
-- label whose association with this message should be verified, and the
-- ciphertext message.
--
rsaes_oaep_decrypt :: HashFunction -> MGF ->
                      PrivateKey -> ByteString -> ByteString ->
                      ByteString
rsaes_oaep_decrypt hash mgf k l c 
  | bad_message_len = error "message too short"
  | bad_hash_len    = error "bad hash length"
  | signal_error    = error $ "decryption error " ++ (show $ BS.any (/= 1) one) ++ " " ++ (show $ lHash /= lHash') ++ " " ++ (show $ BS.any (/= 0) y)
  | otherwise       = m
 where
  hLen = BS.length $ hash BS.empty
  kLen = private_size k
  -- Step 1
  bad_message_len = BS.length c /= kLen
  bad_hash_len    = kLen < ((2 * hLen) + 2)
  -- Step 2
  c_ip            = os2ip c
  m_ip            = rsa_dp (private_n k) (private_d k) c_ip
  em              = i2osp m_ip kLen
  -- Step 3
  lHash                  = hash l
  (y, msandmdb)          = BS.splitAt 1 em
  (maskedSeed, maskedDB) = BS.splitAt hLen msandmdb
  seedMask               = mgf maskedDB hLen
  seed                   = maskedSeed `xorBS` seedMask
  dbMask                 = mgf seed (kLen - hLen - 1)
  db                     = maskedDB `xorBS` dbMask
  (lHash', ps1m)         = BS.splitAt hLen db
  one_m                  = BS.dropWhile (== 0) ps1m
  (one, m)               = BS.splitAt 1 one_m
  -- Error Checking
  signal_error = (BS.any (/= 1) one) || (lHash /= lHash') || (BS.any (/= 0) y)

-- |Implements RSAES-PKCS1-v1.5-Encrypt, as defined by the spec, for
-- completeness and possible backward compatibility. Also because I've already
-- written everything else, so why not?
--
-- This encryption / padding mechanism has several known attacks, which are
-- described in the literature. So unless you absolutely need to use this
-- for some historical reason, you shouldn't.
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
--
rsaes_pkcs1_v1_5_encrypt :: RandomGen g => 
                            g -> PublicKey -> ByteString -> 
                            (ByteString, g)
rsaes_pkcs1_v1_5_encrypt rGen k m 
  | message_too_long = error "message too long"
  | otherwise        = (c, rGen')
 where
  mLen = BS.length m
  kLen = public_size k
  -- Step 1
  message_too_long = mLen > (kLen - 11)
  --  Step2
  (ps, rGen') = generate_random_bytestring rGen (kLen - mLen - 3)
  em          = BS.concat [BS.singleton 0, BS.singleton 2, ps,
                           BS.singleton 0, m]
  m'          = os2ip em
  c_i         = rsa_ep (public_n k) (public_e k) m'
  c           = i2osp c_i kLen 
  
-- |Implements RSAES-PKCS1-v1.5-Decrypt, as defined by the spec, for
-- completeness and possible backward compatibility. Please see the notes
-- for rsaes_pkcs1_v1_5_encrypt regarding use of this function in new 
-- applications without historical algorithm requirements
--
-- The ciphertext message passed to this function must be of length k,
-- where k is the length of the key modulus in bytes.
--
rsaes_pkcs1_v1_5_decrypt :: PrivateKey -> ByteString -> ByteString
rsaes_pkcs1_v1_5_decrypt k c 
  | wrong_size   = error "message size incorrect"
  | signal_error = error "decryption error"
  | otherwise    = m
 where
  mLen = BS.length c
  kLen = private_size k
  -- Step 1
  wrong_size = mLen /= kLen
  -- Step 2
  c_i = os2ip c
  m_i = rsa_dp (private_n k) (private_d k) c_i
  em  = i2osp m_i kLen
  -- Step 3
  (zt, ps0m) = BS.splitAt 2 em
  (ps, zm)   = BS.span (/= 0) ps0m
  (z, m)     = BS.splitAt 1 zm
  -- Step 4
  signal_error = (BS.unpack zt /= [0, 2]) || (BS.unpack z /= [0]) ||
                 (BS.length ps < 8)


-- $pss
-- |RSASSA-PSS-Sign, RSASSA-PSS-Verify, and the related functions are not
-- included because they are covered by U.S. Patent 7036014, and it's not
-- clear what the restrictions on implementations are.

-- |Generates a signature for the given message using the given private
-- key. This is obviously based on RSASSA-PKCS1-v1.5-Sign from the 
-- specification. Note that in researching what was required for this
-- project, several independent sources suggested not using the same
-- key across sign/validate and encrypt/decrypt contexts.
--
-- The output of this function is the signature only, not the message and
-- signature.
--
rsassa_pkcs1_v1_5_sign :: HashInfo -> PrivateKey -> ByteString -> ByteString
rsassa_pkcs1_v1_5_sign hi k m = sig
 where
   kLen = private_size k
   --
   em  = emsa_pkcs1_v1_5_encode hi m kLen
   m_i = os2ip em
   s   = rsa_sp1 (private_n k) (private_d k)  m_i
   sig = i2osp s kLen
    
-- |Validates a signature for the given message using the given public
-- key. The arguments are, in order: the hash function to use, the public key,
-- the message, and the signature. The signature must be exactly k bytes long,
-- where k is the size of the RSA modulus in bytes.
rsassa_pkcs1_v1_5_verify :: HashInfo -> PublicKey -> 
                            ByteString -> ByteString -> 
                            Bool
rsassa_pkcs1_v1_5_verify hi k m s 
   | bad_size  = False
   | otherwise = res
 where
  kLen = public_size k
  -- Step 1
  bad_size = BS.length s /= kLen
  -- Step 2
  s_i = os2ip s
  m_i = rsa_vp1 (public_n k) (public_e k) s_i
  em  = i2osp m_i kLen
  -- Step 3
  em' = emsa_pkcs1_v1_5_encode hi m kLen
  -- Step 4
  res = em == em'
   
-- |Generate a mask generation function for the rsaes_oaep_*. As 
-- suggested by the name, the generated function is an instance of the MGF1
-- function. The arguments are the underlying hash function to use and the 
-- size of a hash in bytes.
--
-- The bytestring passed to the generated function cannot be longer than
-- 2^32 * hLen, where hLen is the passed length of the hash. 
generate_MGF1 :: HashFunction -> MGF
generate_MGF1 hash mgfSeed maskLen 
 | BS.length mgfSeed > ((2 ^ (32::Int64)) * hLen) = error "mask too long"
 | otherwise                                      = loop BS.empty 0
 where
  hLen        = BS.length $ hash BS.empty
  end_counter = (maskLen `divCeil` hLen) - 1
  loop t counter 
    | counter > end_counter = BS.take maskLen t
    | otherwise             = let c = i2osp counter 4
                                  bs = mgfSeed `BS.append` c
                                  t' = t `BS.append` hash bs
                              in loop t' (counter + 1)

-- --------------------------------------------------------------------------
--
--                       HASH FUNCTIONS AND IDENTIFIERS
--
-- --------------------------------------------------------------------------

#ifdef INCLUDE_MD5
ha_MD5 :: HashInfo
ha_MD5 = HashInfo {
   algorithmIdent = BS.pack [0x30,0x20,0x30,0x0c,0x06,0x08,0x2a,0x86,0x48,
                             0x86,0xf7,0x0d,0x02,0x05,0x05,0x00,0x04,0x10]
 , hashFunction   = encode . md5
 }
#endif

ha_SHA1 :: HashInfo
ha_SHA1 = HashInfo {
   algorithmIdent = BS.pack [0x30,0x21,0x30,0x09,0x06,0x05,0x2b,0x0e,0x03,
                             0x02,0x1a,0x05,0x00,0x04,0x14]
 , hashFunction   = bytestringDigest . sha1
 }

ha_SHA256 :: HashInfo
ha_SHA256 = HashInfo {
   algorithmIdent = BS.pack [0x30,0x31,0x30,0x0d,0x06,0x09,0x60,0x86,0x48,
                             0x01,0x65,0x03,0x04,0x02,0x01,0x05,0x00,0x04,
                             0x20]
 , hashFunction   = bytestringDigest . sha256
 }

ha_SHA384 :: HashInfo
ha_SHA384 = HashInfo {
   algorithmIdent = BS.pack [0x30,0x41,0x30,0x0d,0x06,0x09,0x60,0x86,0x48,
                             0x01,0x65,0x03,0x04,0x02,0x02,0x05,0x00,0x04,
                             0x30]
 , hashFunction   = bytestringDigest . sha384
 }

ha_SHA512 :: HashInfo
ha_SHA512 = HashInfo {
   algorithmIdent  = BS.pack [0x30,0x51,0x30,0x0d,0x06,0x09,0x60,0x86,0x48,
                              0x01,0x65,0x03,0x04,0x02,0x03,0x05,0x00,0x04,
                              0x40]
 , hashFunction   = bytestringDigest . sha512
 }

sha256' :: HashFunction
sha256' = bytestringDigest . sha256

-- --------------------------------------------------------------------------
--
--                      INTERNAL FUNCTIONS FROM THE SPEC
--
-- --------------------------------------------------------------------------

-- "i2osp converts a nonnegative integer to an octet string of a specified
-- length" -- RFC 3447
i2osp :: Integral a => a -> Int64 -> ByteString
i2osp x len | x >= (256 ^ len) = error "RSA internal error: integer too large"
            | otherwise = padding `BS.append` digits
 where
  padding = BS.replicate (len - BS.length digits) 0
  digits = BS.pack $ reverse $ digits256 x
  digits256 v 
    | v <= 255 = [fromIntegral v]
    | otherwise = (fromIntegral $ v `mod` 256) : (digits256 $ v `div` 256)

-- 'osp2i converts an octet string to a nonnegative integer' - RFC 3447
os2ip :: ByteString -> Integer
os2ip x = BS.foldl (\ a b -> (256 * a) + (fromIntegral b)) 0 x

-- the RSA encryption function
rsa_ep :: Integer -> Integer -> Integer -> Integer
rsa_ep n _ m | (m < 0) || (m >= n) = error "message representative out of range"
rsa_ep n e m = modular_exponentiation m e n -- (m ^ e) `mod` n

-- the RSA decryption function
rsa_dp :: Integer -> Integer -> Integer -> Integer
rsa_dp n _ c | (c < 0) || (c >= n) = error "ciphertext rep out of range"
rsa_dp n d c = modular_exponentiation c d n -- (c ^ d) `mod` n

-- the rsa signature generation function
rsa_sp1 :: Integer -> Integer -> Integer -> Integer
rsa_sp1 n d m 
  | (m < 0) || (m >= n) = error "message representative out of range"
  | otherwise           = modular_exponentiation m d n -- (m ^ d) `mod` n
  
-- the rsa signature verification function
rsa_vp1 :: Integer -> Integer -> Integer -> Integer
rsa_vp1 n e s 
 | (s < 0) || (s >= n) = error "signature representative out of range"
 | otherwise           = modular_exponentiation s e n -- (s ^ e) `mod` n
 
emsa_pkcs1_v1_5_encode :: HashInfo -> ByteString -> Int64 -> ByteString
emsa_pkcs1_v1_5_encode (HashInfo hash_ident hash) m emLen 
  | emLen < (tLen + 1) = error "intended encoded message length too short"
  | otherwise          = em
 where
  h = hash m
  t = hash_ident `BS.append` h
  tLen = BS.length t
  ps = BS.replicate (emLen - tLen - 3) 0xFF
  em = BS.concat [BS.singleton 0x00, BS.singleton 0x01, ps,
                  BS.singleton 0x00, t] 

-- --------------------------------------------------------------------------
--
--                      HANDY HELPER FUNCTIONS
--
-- --------------------------------------------------------------------------

-- Perform XOR on every byte in the two bytestrings.
xorBS :: ByteString -> ByteString -> ByteString
xorBS bs1 bs2 = BS.pack $ BS.zipWith xor bs1 bs2

-- Split a ByteString into chunks of this size or less.
chunkify :: Int64 -> ByteString -> [ByteString]
chunkify len bstr 
  | BS.length bstr <= len = [bstr]
  | otherwise             = (BS.take len bstr):(chunkify len $ BS.drop len bstr)
 
instance Random Word8 where
  randomR (a,b) g = let aI::Int = fromIntegral a 
                        bI::Int = fromIntegral b
                        (x, g') = randomR (aI, bI) g
                    in (fromIntegral x, g')
  random          = randomR (minBound, maxBound)

generate_random_bytestring :: RandomGen g => g -> Int64 -> (ByteString, g)
generate_random_bytestring g 0 = (BS.empty, g)
generate_random_bytestring g x = (BS.cons' first rest, g'')
 where
  (rest, g')   = generate_random_bytestring g (x - 1)
  (first, g'') = randomR (1,255) g' 

-- Divide a by b, rounding towards positive infinity.
divCeil :: Integral a => a -> a -> a
divCeil a b = 
  let (q, r) = divMod a b
  in if r /= 0 then (q + 1) else q

-- Generate p and q. This is not necessarily the best way to do this, but the
-- ANSI standard dealing with this cost money, and I was in a hurry.
generate_pq :: RandomGen g => g -> Int64 -> (Integer, Integer, g)
generate_pq g len 
  | len < 2   = error "length to short for generate_pq"
  | p == q    = generate_pq g'' len
  | otherwise = (p, q, g'')
 where
  (baseP, g')  = large_random_prime g  (len `div` 2)
  (baseQ, g'') = large_random_prime g' (len - (len `div` 2))
  (p, q)       = if baseP < baseQ then (baseQ, baseP) else (baseP, baseQ)

large_random_prime :: RandomGen g => g -> Int64 -> (Integer, g)
large_random_prime g len = (prime, g''')
 where
  ([startH, startT], g') = random8s g 2
  (startMids, g'')       = random8s g' (len - 2)
  start_ls               = [startH .|. 0xc0] ++ startMids ++ [startT .|. 1]
  start                  = os2ip $ BS.pack start_ls
  (prime, g''')          = find_next_prime g'' start 
  
random8s :: RandomGen g => g -> Int64 -> ([Word8], g)
random8s g 0 = ([], g)
random8s g x = 
  let (rest, g') = random8s g (x - 1)
      (next8, g'') = random g'
  in (next8:rest, g'')

find_next_prime :: RandomGen g => g -> Integer -> (Integer, g)
find_next_prime g n
  | even n             = error "Even number sent to find_next_prime"
  | n `mod` 65537 == 1 = find_next_prime g (n + 2)
  | got_a_prime        = (n, g')
  | otherwise          = find_next_prime g' (n + 2)
 where
  (got_a_prime, g') = is_probably_prime g n

is_probably_prime :: RandomGen g => g -> Integer -> (Bool, g)
is_probably_prime !g !n 
  | any (\ x -> n `mod` x == 0) small_primes = (False, g)
  | otherwise                                = miller_rabin g n 20
 where
  small_primes = [   2,    3,    5,    7,   11,   13,   17,   19,   23,   29,
                    31,   37,   41,   43,   47,   53,   59,   61,   67,   71,
                    73,   79,   83,   89,   97,  101,  103,  107,  109,  113,
                   127,  131,  137,  139,  149,  151,  157,  163,  167,  173,
                   179,  181,  191,  193,  197,  199,  211,  223,  227,  229,
                   233,  239,  241,  251,  257,  263,  269,  271,  277,  281,
                   283,  293,  307,  311,  313,  317,  331,  337,  347,  349,
                   353,  359,  367,  373,  379,  383,  389,  397,  401,  409,
                   419,  421,  431,  433,  439,  443,  449,  457,  461,  463,
                   467,  479,  487,  491,  499,  503,  509,  521,  523,  541,
                   547,  557,  563,  569,  571,  577,  587,  593,  599,  601,
                   607,  613,  617,  619,  631,  641,  643,  647,  653,  659,
                   661,  673,  677,  683,  691,  701,  709,  719,  727,  733,
                   739,  743,  751,  757,  761,  769,  773,  787,  797,  809,
                   811,  821,  823,  827,  829,  839,  853,  857,  859,  863,
                   877,  881,  883,  887,  907,  911,  919,  929,  937,  941,
                   947,  953,  967,  971,  977,  983,  991,  997, 1009, 1013  ]

miller_rabin :: RandomGen g => g -> Integer -> Int -> (Bool, g)
miller_rabin g _ 0             = (True, g)
miller_rabin g n k | test a n  = (False, g')
                   | otherwise = miller_rabin g' n (k - 1)
 where
  (a, g') = randomR (2, n - 2) g
  base_b = tail $ reverse $ toBinary (n - 1) 
  -- 
  test a' n' = pow base_b a
   where
    pow   _  1 = False
    pow  []  _ = True 
    pow !xs !d = pow' xs d $ (d * d) `mod` n'
     where
      pow' _          !d1 !d2 | d2==1 && d1 /= (n'-1) = True
      pow' (False:ys)   _ !d2                         = pow ys d2
      pow' (True :ys)   _ !d2                         = pow ys $ (d2*a')`mod`n'
      pow' _            _   _                         = error "bad case"
  -- 
  toBinary 0 = []
  toBinary x = (testBit x 0) : (toBinary $ x `shiftR` 1)

modular_exponentiation :: Integer -> Integer -> Integer -> Integer
modular_exponentiation x y m = m_e_loop x y 1
 where
  m_e_loop _   0 !result = result
  m_e_loop !b !e !result = m_e_loop b' e' result'
   where
    !b'      = (b * b) `mod` m
    !e'      = e `shiftR` 1
    !result' = if testBit e 0 then (result * b) `mod` m else result

-- Compute the modular inverse (d = e^-1 mod phi) via the extended 
-- euclidean algorithm. And if you think I understand the math behind this,
-- I have a bridge to sell you.
modular_inverse :: Integer -> Integer -> Integer
modular_inverse e phi = x `mod` phi
 where
  (_, x, _) = gcde e phi

gcde :: Integer -> Integer -> (Integer, Integer, Integer)
gcde a b | d < 0     = (-d, -x, -y)
         | otherwise = (d, x, y)
 where
  (d, x, y) = gcd_f (a,1,0) (b,0,1)
  gcd_f (r1, x1, y1) (r2, x2, y2) 
    | r2 == 0   = (r1, x1, y1)
    | otherwise = let (q, r) = r1 `divMod` r2
                  in gcd_f (r2, x2, y2) (r, x1 - (q * x2), y1 - (q * y2))
