import Distribution.PackageDescription
import Distribution.Simple
import Distribution.Simple.LocalBuildInfo
import System.Cmd
import System.FilePath

main :: IO ()
main = defaultMainWithHooks rsaUserHooks
 where  
  rsaUserHooks = simpleUserHooks { 
    runTests = runLMTests
  , instHook = filter_test $ instHook defaultUserHooks 
  }

type Hook a = PackageDescription -> LocalBuildInfo -> UserHooks -> a -> IO ()

filter_test :: Hook a -> Hook a
filter_test f pd lbi uhs x = f pd' lbi uhs x
 where
  pd'  = pd { executables = [] }

runLMTests :: Args -> Bool -> PackageDescription -> LocalBuildInfo -> IO ()
runLMTests _args _unknown descr _lbi = system test_exe >> return ()
 where
  test_exe = "dist" </> "build" </> "test_rsa" </> (exeName $ head $ executables descr)
