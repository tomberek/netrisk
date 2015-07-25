module Main  where

import Netrisk.Core
import Data.Attoparsec.ByteString.Char8 hiding (take)
import qualified Data.ByteString as B
import System.Environment (getArgs)
import Paths_netrisk

-- | The main entry point. Duplicates data to obtain 1 million rows. Executes in ~ .25s on 8 cores.
main :: IO ()
main = do
    args <- getArgs
    file <- case args of
    	[] -> getDataFileName "testdata.txt"
    	(f:_) -> return f
    flow <- B.readFile file
    
    let Right results =  parseOnly flowParser flow
    print $ totalRisk ruleset results
    print "Now duplicating up to 1 million rows of data"
    print $ totalRisk ruleset $ take 1000000 $ cycle results