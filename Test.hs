import Codec.Crypto.RSA.Pure
import Control.Monad
import Data.Binary
import Data.ByteString.Lazy(ByteString)
import qualified Data.ByteString.Lazy as BS
import Data.Digest.Pure.SHA
import System.IO
import Test.QuickCheck
import Crypto.Random

import Test.Framework (defaultMain, testGroup)
import Test.Framework.Providers.QuickCheck2 (testProperty)

type KeyPairs = [(PublicKey, PrivateKey)]

numRandomKeyPairs :: Int
numRandomKeyPairs = length keySizes * 2

keySizes :: [Int]
keySizes = [128,256,512,1024,2048,4096]

main :: IO ()
main = do
  putStr   "Generating testing keys ... "
  hFlush   stdout
  g :: SystemRandom <- newGenIO
  let (keys, g') = buildRandomKeyPairs g (cycle keySizes) numRandomKeyPairs
  unless (all ((> 5) . public_n . fst) keys) $ fail "Something odd."
  putStrLn "done!"
  defaultMain
    [ testGroup "Random functions" [
        testProperty "RandomBS generates the right length" (prop_randomBSLen g')
      , testProperty "RandomNZBS generates good data" (prop_randomNZBS g')
      ]
    , testGroup "Testing basic helper functions" [
        testProperty "ByteString chunking works"    prop_chunkifyWorks
      , testProperty "Modular exponentiation works" prop_modExpWorks
      , testProperty "Modular inversion works"      (prop_modInvWorks g')
      ]
    , testGroup "Testing RSA core functions" [
        testProperty "Can roundtrip from Integer to BS and back" prop_i2o2iIdent
      , testProperty "Can roundtrip from BS to Integer and back" prop_o2i2oIdent
      , testProperty "Can roundtrip RSA's EP and DP functions"
                     (prop_epDpIdent keys)
      , testProperty "Can roundtrip RSA's SP and VP functions"
                     (prop_spVpIdent keys)
      ]
    , testGroup "Testing fixed-width RSA functions" [
        testProperty "RSA PKCS sign/verify works"
                     (prop_pkcsSignVerifies keys)
      , testProperty "RSA PKCS encrypt/decrypt works" (prop_pkcsInverts keys g)
      , testProperty "RSA OAEP encrypt/decrypt works" (prop_oaepInverts keys g)
      ]
    , testGroup "Testing top-level, arbitrary-width RSA functions" [
        testProperty "Checking encrypt/decrypt roundtrips" (prop_encDec keys g)
      , testProperty "Checking OAEP encrypt/decrypt roundtrips"
                     (prop_encDecO keys g)
      , testProperty "Checking PKCS encrypt/decrypt roundtrips"
                     (prop_encDecP keys g)
      , testProperty "Checking verify verifies sign" (propSignVerifies keys)
      ]
    ]

buildRandomKeyPairs :: CryptoRandomGen g => g -> [Int] -> Int -> (KeyPairs, g)
buildRandomKeyPairs g _              0 = ([], g)
buildRandomKeyPairs _ []             _ = error "The world has gone insane."
buildRandomKeyPairs g (keySize:rest) x =
  case generateKeyPair g keySize of
    Left _ -> error "Couldn't generate initial random key pairs! (1)"
    Right (pub, priv, g') ->
      let (acc, g'') = buildRandomKeyPairs g' rest (x - 1)
      in ((pub, priv) : acc, g'')

-- --------------------------------------------------------------------------

instance Arbitrary ByteString where
    arbitrary = BS.pack `fmap` arbitrary

instance Show HashInfo where
  show (HashInfo ident _)
    | ident == algorithmIdent hashSHA1   = "<SHA1>"
    | ident == algorithmIdent hashSHA224 = "<SHA224>"
    | ident == algorithmIdent hashSHA256 = "<SHA256>"
    | ident == algorithmIdent hashSHA384 = "<SHA384>"
    | ident == algorithmIdent hashSHA512 = "<SHA512>"
    | otherwise                          = "<unknownHASH>"

instance Arbitrary HashInfo where
  arbitrary = elements [hashSHA1, hashSHA224,
                       hashSHA256, hashSHA384, hashSHA512]

data KeyPairIdx = KPI Int
 deriving (Show)

instance Arbitrary KeyPairIdx where
  arbitrary = KPI `fmap` choose (0, numRandomKeyPairs - 1)

data HashFun = HF String (ByteString -> ByteString)

instance Show HashFun where
  show (HF s _) = "<" ++ s ++ ">"

instance Arbitrary HashFun where
  arbitrary = elements [HF "SHA1" (bytestringDigest . sha1),
                        HF "SHA256" (bytestringDigest . sha256),
                        HF "SHA384" (bytestringDigest . sha384),
                        HF "SHA512" (bytestringDigest . sha512)]

prop_randomBSLen :: CryptoRandomGen g => g -> Positive Word16 -> Bool
prop_randomBSLen g x =
  case randomBS g (fromIntegral (getPositive x)) of
    Left _ -> False
    Right (bstr, _) -> fromIntegral (BS.length bstr) == getPositive x

prop_randomNZBS :: CryptoRandomGen g => g -> Positive Word16 -> Bool
prop_randomNZBS g x =
  case randomNZBS g (fromIntegral (getPositive x)) of
    Left _ -> False
    Right (bstr, _) ->
      (fromIntegral (BS.length bstr) == getPositive x) && BS.all (/= 0) bstr

prop_chunkifyWorks :: ByteString -> Positive Integer -> Bool
prop_chunkifyWorks x l = all (\ bs -> BS.length bs <= l') chunks &&
                         (sum (map BS.length chunks) == BS.length x)
 where
  l' = fromIntegral (getPositive l)
  chunks = chunkify x (fromIntegral l')

prop_modExpWorks :: Positive Integer -> Positive Integer -> Positive Integer ->
                    Bool
prop_modExpWorks b e m = ((b' ^ e') `mod` m') == modular_exponentiation b' e' m'
 where
  b' = getPositive b
  e' = getPositive e
  m' = getPositive m

prop_modInvWorks :: CryptoRandomGen g => g -> Word16 -> Bool
prop_modInvWorks g0 x =
  let (p, g1) = primeGen (x `mod` 512) g0
      (q, _)  = primeGen (x `mod` 512) g1
      e       = 65537
      phi     = (p - 1) * (q - 1)
      d       = modular_inverse e phi
  in (e * d) `mod` phi == 1
 where
  primeGen pre g =
    case randomBS g (fromIntegral pre) of
      Left e -> error ("Error prefetching bytestring:" ++ show e)
      Right (_, g') ->
        case largeRandomPrime g' 64 of
          Left  _   -> error "Large prime generation failure."
          Right res -> res

prop_i2o2iIdent :: Positive Integer -> Bool
prop_i2o2iIdent px =
  case i2osp x l of
    Left _ -> False
    Right x' -> os2ip x' == x
 where
  x = getPositive px
  l = findLen 1 256
  --
  findLen b t | t > x     = b
              | otherwise = findLen (b + 1) (t * 256)

prop_o2i2oIdent :: ByteString -> Bool
prop_o2i2oIdent bs =
  case i2osp (os2ip bs) (fromIntegral (BS.length bs)) of
    Left _    -> False
    Right bs' -> bs == bs'

prop_epDpIdent :: KeyPairs -> KeyPairIdx ->
                  Positive Integer ->
                  Bool
prop_epDpIdent kps (KPI idx) x = fromEither $
  do let n = public_n pub
         e = public_e pub
         d = private_d priv
         m = getPositive x `mod` n
     ep <- rsa_ep n e m
     m' <- rsa_dp n d ep
     return (m == m')
 where (pub, priv) = kps !! idx

prop_spVpIdent :: KeyPairs -> KeyPairIdx ->
                  Positive Integer ->
                  Bool
prop_spVpIdent kps (KPI idx) x = fromEither $
  do let n = public_n pub
         e = public_e pub
         d = private_d priv
         m = getPositive x `mod` n
     sp <- rsa_sp1 n d m
     m' <- rsa_vp1 n e sp
     return (m == m')
 where (pub, priv) = kps !! idx

prop_oaepInverts :: CryptoRandomGen g =>
                    KeyPairs -> g ->
                    HashFun -> KeyPairIdx ->
                    ByteString -> ByteString ->
                    Property
prop_oaepInverts kps g (HF _ hash) (KPI idx) l m = wellSized ==> fromEither $
  do let mgf = generateMGF1 hash
     (enc,_) <- rsaes_oaep_encrypt g hash mgf pub l m
     m'      <- rsaes_oaep_decrypt hash mgf priv l enc
     return (m == m')
 where
  (pub, priv) = kps !! idx
  hashLength  = fromIntegral (BS.length (hash BS.empty))
  keySize     = public_size pub
  msgLength   = fromIntegral (BS.length m)
  wellSized   = (msgLength <= (keySize - (2 * hashLength) - 2)) && (msgLength>0)

prop_pkcsInverts :: CryptoRandomGen g =>
                    KeyPairs -> g -> KeyPairIdx ->
                    ByteString ->
                    Property
prop_pkcsInverts kps g (KPI idx) m = wellSized ==> fromEither $
  do (enc,_) <- rsaes_pkcs1_v1_5_encrypt g pub m
     m'      <- rsaes_pkcs1_v1_5_decrypt priv enc
     return (m == m')
 where
  (pub, priv) = kps !! idx
  wellSized   = (fromIntegral (BS.length m) < (public_size pub - 11)) &&
                (BS.length m > 0)

prop_pkcsSignVerifies :: KeyPairs -> KeyPairIdx ->
                         HashInfo -> ByteString ->
                         Property
prop_pkcsSignVerifies kps (KPI idx) hash m = wellSized ==> fromEither $
  do sig <- rsassa_pkcs1_v1_5_sign hash priv m
     rsassa_pkcs1_v1_5_verify hash pub m sig
 where
  (pub, priv) = kps !! idx
  wellSized = fromIntegral (public_size pub) > (algSize + hashLen + 1)
  algSize   = BS.length (algorithmIdent hash)
  hashLen   = BS.length (hashFunction hash BS.empty)

prop_encDec :: CryptoRandomGen g =>
               KeyPairs -> g ->
               KeyPairIdx -> ByteString ->
               Bool
prop_encDec kps g (KPI idx) m = fromEither $
  do (c, _) <- encrypt g pub m
     m' <- decrypt priv c
     return (m == m')
 where (pub, priv) = findKeySized 66 kps idx

prop_encDecO :: CryptoRandomGen g =>
                KeyPairs -> g ->
                HashFun -> KeyPairIdx -> ByteString -> ByteString ->
                Property
prop_encDecO kps g (HF _ hash) (KPI idx) l m = wellSized ==> fromEither $
  do (c, _) <- encryptOAEP g hash (generateMGF1 hash) l pub m
     m' <- decryptOAEP hash (generateMGF1 hash) l priv c
     return (m == m')
 where
  (pub, priv) = kps !! idx
  hashLength  = fromIntegral (BS.length (hash BS.empty))
  keySize     = public_size pub
  wellSized   = (keySize - (2 * hashLength) - 2) > 0

prop_encDecP :: CryptoRandomGen g =>
                KeyPairs -> g -> KeyPairIdx -> ByteString ->
                Bool
prop_encDecP kps g (KPI idx) m = fromEither $
  do (c, _) <- encryptPKCS g pub m
     m' <- decryptPKCS priv c
     return (m == m')
 where (pub, priv) = findKeySized 11 kps idx

propSignVerifies :: KeyPairs -> KeyPairIdx -> ByteString -> Bool
propSignVerifies kps (KPI idx) m = fromEither $
  do sig <- sign priv m
     verify pub m sig
 where (pub, priv) = findKeySized 64 kps idx

findKeySized :: Int -> KeyPairs -> Int -> (PublicKey, PrivateKey)
findKeySized size kps idx =
  let pair@(pub, _) = kps !! idx
  in if public_size pub >= size
       then pair
       else findKeySized size kps ((idx + 1) `mod` length kps)

-- --------------------------------------------------------------------------

fromEither :: Either a Bool -> Bool
fromEither (Left _) = False
fromEither (Right res) = res
