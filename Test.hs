import Codec.Crypto.RSA
import Control.Monad
import Data.ByteString.Lazy(ByteString)
import qualified Data.ByteString.Lazy as BS
import Data.Digest.Pure.SHA
import Data.Word
import System.Random
import Test.QuickCheck

import Test.Framework (defaultMain, testGroup, Test)
#ifdef QUICKCHECK1
import Test.Framework.Providers.QuickCheck (testProperty)
#else
import Test.Framework.Providers.QuickCheck2 (testProperty)
#endif

-- --------------------------------------------------------------------------

data KeyPair     = KP1K PublicKey PrivateKey
 deriving (Show)

data KeyPair2048 = KP2K PublicKey PrivateKey
 deriving (Show)

getRNGSeed :: Gen StdGen
#ifdef QUICKCHECK1
getRNGSeed  = rand
#else
getRNGSeed  = fmap mkStdGen arbitrary
#endif

instance Arbitrary KeyPair where
  arbitrary   = do g <- getRNGSeed
                   let (pub, priv, _) = generateKeyPair g 1024
                   return $ KP1K pub priv
#ifdef QUICKCHECK1
  coarbitrary = undefined
#endif

instance Arbitrary KeyPair2048 where
  arbitrary   = do g <- getRNGSeed
                   let (pub, priv, _) = generateKeyPair g 2048
                   return $ KP2K pub priv
#ifdef QUICKCHECK1
  coarbitrary = undefined
#endif

-- --------------------------------------------------------------------------

newtype LargePrime = LP Integer

instance Show LargePrime where
  show (LP x) = show x

instance Arbitrary LargePrime where
  arbitrary   = do g <- getRNGSeed
                   let (res, _) = large_random_prime g 64
                   return (LP res)
#ifdef QUICKCHECK1
  coarbitrary = undefined
#endif

-- --------------------------------------------------------------------------

newtype PositiveInteger = PI Integer

instance Show PositiveInteger where
  show (PI x) = show x

instance Arbitrary PositiveInteger where
  arbitrary   = (PI . (+1) . abs) `fmap` arbitrary
#ifdef QUICKCHECK1
  coarbitrary = undefined
#endif

-- --------------------------------------------------------------------------

newtype NonEmptyByteString = NEBS ByteString

instance Show NonEmptyByteString where
  show (NEBS x) = show x

instance Arbitrary Word8 where
  arbitrary   = fromIntegral `fmap` (arbitrary::(Gen Int))
#ifdef QUICKCHECK1
  coarbitrary = undefined
#endif

instance Arbitrary ByteString where
  arbitrary   = BS.pack `fmap` arbitrary
#ifdef QUICKCHECK1
  coarbitrary = undefined
#endif

instance Arbitrary NonEmptyByteString where
  arbitrary   = (NEBS . BS.pack) `fmap` (return(:)`ap`arbitrary`ap`arbitrary)
#ifdef QUICKCHECK1
  coarbitrary = undefined
#endif

-- --------------------------------------------------------------------------

instance Arbitrary EncryptionOptions where
  arbitrary   = arbitrary >>= \ lbl -> elements [
                  UsePKCS1_v1_5
                , UseOAEP sha1'   (generate_MGF1 sha1') lbl
                , UseOAEP sha256' (generate_MGF1 sha256') lbl
                , UseOAEP sha384' (generate_MGF1 sha384') lbl
                , UseOAEP sha512' (generate_MGF1 sha512') lbl
                ]
   where
    sha1'   = bytestringDigest . sha1
    sha256' = bytestringDigest . sha256
    sha384' = bytestringDigest . sha384
    sha512' = bytestringDigest . sha512
#ifdef QUICKCHECK1
  coarbitrary = undefined
#endif

instance Show HashInfo where
  show h = "<hash: len=" ++ (show $ BS.length $ hashFunction h BS.empty) ++ ">"

instance Arbitrary HashInfo where
  arbitrary   = elements [ha_SHA1, ha_SHA256, ha_SHA384, ha_SHA512]
#ifdef QUICKCHECK1
  coarbitrary = undefined
#endif

-- --------------------------------------------------------------------------

prop_chunkify_works :: NonEmptyByteString -> PositiveInteger -> Bool
prop_chunkify_works (NEBS x) (PI l) =
  all (\ bs -> BS.length bs <= (fromIntegral l)) (chunkify (fromIntegral l) x)

prop_mod_exp_works :: PositiveInteger -> PositiveInteger -> PositiveInteger ->
                      Bool
prop_mod_exp_works (PI b) (PI e) (PI m) =
  ((b ^ e) `mod` m) == (modular_exponentiation b e m)

prop_mod_inv_works :: LargePrime -> LargePrime -> Bool
prop_mod_inv_works (LP p) (LP q) = (e * d) `mod` phi == 1
 where 
  e   = 65537
  phi = (p - 1) * (q - 1)
  d   = modular_inverse e phi

-- --------------------------------------------------------------------------

prop_i2o2i_identity :: PositiveInteger -> Bool
prop_i2o2i_identity (PI x) = x == (os2ip $ i2osp x 16)

prop_o2i2o_identity :: NonEmptyByteString -> Bool
prop_o2i2o_identity (NEBS x) = x == (i2osp (os2ip x) (BS.length x))

prop_ep_dp_identity :: KeyPair -> PositiveInteger -> Bool
prop_ep_dp_identity (KP1K pub priv) (PI x) = m == m'
 where
  n  = public_n pub
  e  = public_e pub
  d  = private_d priv
  m  = x `mod` n
  m' = rsa_dp n d $ rsa_ep n e m

prop_sp_vp_identity :: KeyPair -> PositiveInteger -> Bool
prop_sp_vp_identity (KP1K pub priv) (PI x) = m == m'
 where
  n  = public_n pub
  e  = public_e pub
  d  = private_d priv
  m  = x `mod` n
  m' = rsa_vp1 n e $ rsa_sp1 n d m

-- --------------------------------------------------------------------------

prop_oaep_inverts :: HashInfo -> KeyPair2048 -> PositiveInteger -> 
                     ByteString -> NonEmptyByteString -> 
                     Bool
prop_oaep_inverts hi (KP2K pub priv) (PI seed) l (NEBS x) = m == m'
 where
  hash = hashFunction hi
  kLen = public_size pub
  hLen = BS.length $ hash BS.empty
  mgf  = generate_MGF1 hash
  m    = BS.take (kLen - (2 * hLen) - 2) x
  c    = rsaes_oaep_encrypt hash mgf pub  seed l m
  m'   = rsaes_oaep_decrypt hash mgf priv      l c

prop_pkcs_inverts :: RandomGen g => g -> KeyPair -> NonEmptyByteString -> Bool
prop_pkcs_inverts g (KP1K pub priv) (NEBS x) = m == m'
 where
  kLen  = public_size pub
  m     = BS.take (kLen - 11) x
  (c,_) = rsaes_pkcs1_v1_5_encrypt g pub  m
  m'    = rsaes_pkcs1_v1_5_decrypt   priv c

prop_sign_works :: HashInfo -> KeyPair -> NonEmptyByteString -> Bool
prop_sign_works hi (KP1K pub priv) (NEBS m) = 
  rsassa_pkcs1_v1_5_verify hi pub m $ rsassa_pkcs1_v1_5_sign hi priv m

-- --------------------------------------------------------------------------

prop_encrypt_inverts :: RandomGen g => 
                        g -> KeyPair2048 -> NonEmptyByteString -> 
                        Bool
prop_encrypt_inverts g (KP2K pub priv) (NEBS m) =
  m == decrypt priv (fst $ encrypt g pub m)

prop_encrypt_plus_inverts :: RandomGen g =>
                             g -> EncryptionOptions -> KeyPair2048 -> 
                             NonEmptyByteString ->
                             Bool
prop_encrypt_plus_inverts g opts (KP2K pub priv) (NEBS m) =
  m == decrypt' opts priv (fst $ encrypt' opts g pub m)

-- --------------------------------------------------------------------------

main :: IO ()
main = do
  putStrLn "\nWARNING WARNING WARNING"
  putStrLn "This test suite takes a very long time to run. If you're in a "
  putStrLn "hurry, Control-C is your friend."
  putStrLn "WARNING WARNING WARNING\n"

  g <- getStdGen
  defaultMain $ tests g

tests :: StdGen -> [Test]
tests g = [
  testGroup "Testing basic helper functions" [
     testProperty "prop_chunkify_works"         prop_chunkify_works,
     testProperty "prop_mod_exp_works"          prop_mod_exp_works,
     testProperty "prop_mod_inv_works"          prop_mod_inv_works
     ],
  testGroup "Testing RSA core functions" [
    testProperty "prop_i2o2i_identity"         prop_i2o2i_identity,
    testProperty "prop_o2i2o_identity"         prop_o2i2o_identity,
    testProperty "prop_ep_dp_identity"         prop_ep_dp_identity,
    testProperty "prop_sp_vp_identity"         prop_sp_vp_identity
    ],
  testGroup "Testing fixed-width RSA padding functions" [
    testProperty "prop_oaep_inverts"           prop_oaep_inverts,
    testProperty "prop_pkcs_inverts"         $ prop_pkcs_inverts g,
    testProperty "prop_sign_works"             prop_sign_works
    ],
  testGroup "Testing top-level functions" [
    testProperty "prop_encrypt_inverts"      $ prop_encrypt_inverts      g,
    testProperty "prop_encrypt_plus_inverts" $ prop_encrypt_plus_inverts g
    ]
  ]