import Codec.Crypto.RSA.Pure
import Control.Monad
import Data.Binary
import Data.ByteString.Lazy(ByteString)
import qualified Data.ByteString.Lazy as BS
import qualified Data.ByteString.Lazy.Char8 as BSC
import Data.Digest.Pure.SHA
import System.IO
import Test.QuickCheck
import Crypto.Random

import Test.Framework (defaultMain, testGroup)
import Test.Framework.Providers.HUnit (testCase)
import Test.Framework.Providers.QuickCheck2 (testProperty)
import Test.HUnit.Base (Assertion, assertEqual)

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
    , testGroup "Fixed Test Vectors" [
        testCase "GitHub Bug #19 / Implicit Null Allowance" githubBug19
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

githubBug19 :: Assertion
githubBug19 =
  do -- just to make sure we're in the right universe
     assertEqual "Signing computation sane" (Right s) (rsa_sp1 n d i)
     -- make sure it works just as a normal computation
     let Right basicSig = rsassa_pkcs1_v1_5_sign hashSHA256 priv m
     assertEqual "Basic signing works" (Right True) (rsassa_pkcs1_v1_5_verify hashSHA256 pub m basicSig)
     -- check the provided signature, too
     let Right customSig = rsassa_pkcs1_v1_5_sign customHash priv m
     assertEqual "Custom signing scheme works" s_bytes customSig
     assertEqual "Provided signature works" (Right True) (rsassa_pkcs1_v1_5_verify customHash pub m s_bytes)
 where
  n = 0xE932AC92252F585B3A80A4DD76A897C8B7652952FE788F6EC8DD640587A1EE5647670A8AD4C2BE0F9FA6E49C605ADF77B5174230AF7BD50E5D6D6D6D28CCF0A886A514CC72E51D209CC772A52EF419F6A953F3135929588EBE9B351FCA61CED78F346FE00DBB6306E5C2A4C6DFC3779AF85AB417371CF34D8387B9B30AE46D7A5FF5A655B8D8455F1B94AE736989D60A6F2FD5CADBFFBD504C5A756A2E6BB5CECC13BCA7503F6DF8B52ACE5C410997E98809DB4DC30D943DE4E812A47553DCE54844A78E36401D13F77DC650619FED88D8B3926E3D8E319C80C744779AC5D6ABE252896950917476ECE5E8FC27D5F053D6018D91B502C4787558A002B9283DA7
  d = 0x009b771db6c374e59227006de8f9c5ba85cf98c63754505f9f30939803afc1498eda44b1b1e32c7eb51519edbd9591ea4fce0f8175ca528e09939e48f37088a07059c36332f74368c06884f718c9f8114f1b8d4cb790c63b09d46778bfdc41348fb4cd9feab3d24204992c6dd9ea824fbca591cd64cf68a233ad0526775c9848fafa31528177e1f8df9181a8b945081106fd58bd3d73799b229575c4f3b29101a03ee1f05472b3615784d9244ce0ed639c77e8e212ab52abddf4a928224b6b6f74b7114786dd6071bd9113d7870c6b52c0bc8b9c102cfe321dac357e030ed6c580040ca41c13d6b4967811807ef2a225983ea9f88d67faa42620f42a4f5bdbe03b
  e = 3
  m = BSC.pack "hello world!"
  i = 0x0001ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff00302f300b060960864801650304020104207509e5bda0c762d2bac7f90d758b5b2263fa01ccbc542ab5e3df163be08e6ca9
  s = 0xa0073057133ff3758e7e111b4d7441f1d8cbe4b2dd5ee4316a14264290dee5ed7f175716639bd9bb43a14e4f9fcb9e84dedd35e2205caac04828b2c053f68176d971ea88534dd2eeec903043c3469fc69c206b2a8694fd262488441ed8852280c3d4994e9d42bd1d575c7024095f1a20665925c2175e089c0d731471f6cc145404edf5559fd2276e45e448086f71c78d0cc6628fad394a34e51e8c10bc39bfe09ed2f5f742cc68bee899d0a41e4c75b7b80afd1c321d89ccd9fe8197c44624d91cc935dfa48de3c201099b5b417be748aef29248527e8bbb173cab76b48478d4177b338fe1f1244e64d7d23f07add560d5ad50b68d6649a49d7bc3db686daaa7
  Right s_bytes = i2osp s 256
  customHash = HashInfo {
    algorithmIdent = BS.pack [
      0x30,0x2f,0x30,0x0b,0x06,0x09,0x60,0x86,
      0x48,0x01,0x65,0x03,0x04,0x02,0x01,0x04,
      0x20
    ],
    hashFunction = bytestringDigest . sha256
  }
  pub = PublicKey { public_size = 256, public_n = n, public_e = e }
  priv = PrivateKey {
    private_pub = pub,
    private_d = d,
    private_p = 0, private_q = 0,
    private_dP = 0, private_dQ = 0,
    private_qinv = 0
  }

-- --------------------------------------------------------------------------

fromEither :: Either a Bool -> Bool
fromEither (Left _) = False
fromEither (Right res) = res
