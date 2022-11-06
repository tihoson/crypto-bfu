import Crypto.PubKey.DH
import Crypto.Random ( MonadRandom(..) ) 
import Data.ByteArray as A ( unpack ) 
import qualified Data.ByteString as B
import qualified Data.ByteString.Builder as B


generateKeyPair :: MonadRandom m => Params -> m (PrivateNumber, PublicNumber)
generateKeyPair p = do
    private <- generatePrivate p
    let public = calculatePublic p private
    return (private, public)

generateShared :: Params -> PrivateNumber -> PublicNumber -> SharedKey
generateShared = getShared

keyVerification :: SharedKey -> SharedKey -> Bool
keyVerification k1 k2 = k1 == k2

main :: IO ()
main = do
    params <- generateParams 256 2
    print params

    (privateAlice, publicAlice) <- generateKeyPair params
    (privateBob, publicBob) <- generateKeyPair params

    putStrLn $ "Alice: " ++ show  privateAlice ++ " " ++ show publicAlice
    putStrLn $ "Bob: " ++ show privateBob ++ " " ++ show publicBob

    let secretAlice = generateShared params privateAlice publicBob
        secretBob =  generateShared params privateBob publicAlice

    print $ B.toLazyByteString . B.byteStringHex . B.pack . A.unpack $ secretAlice
    print $ B.toLazyByteString . B.byteStringHex . B.pack . A.unpack $ secretBob

    print $ keyVerification secretAlice secretBob
    randomKey <- getRandomBytes 256 
    print $ keyVerification secretAlice (SharedKey randomKey)