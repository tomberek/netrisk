{-# LANGUAGE OverloadedStrings #-}
module Main where
import Test.Tasty
import Test.Tasty.HUnit
import Test.Hspec
import Netrisk.Core
import Data.Attoparsec.ByteString.Char8 as BC hiding (take)
import Data.ByteString.Char8 (pack,ByteString(..))
import Data.IP.RouteTable  as RT

main :: IO ()
main = let Right results = parseOnly flowParser test_data in do
	print $ take 5 results
	defaultMain $ testGroup "Tests" [
		testCase "Initial Test" $   assertEqual "Error in first entry" (totalRisk rules (take 1 results)) 0
		, testCase "Whitelist" $ assertEqual "Should ignore first Targeted" (totalRisk rules (take 5 results)) 0
		, testCase "Targeted" $ assertEqual "Should have some risk" (totalRisk rules results) 5
			]

-- | Defined ruleset in code. Can obtain via a DSL or config file if needed.
rules :: RuleSet
rules = RuleSet
            (RT.fromList [("70.139.33.91",0)])           -- Whitelisted IP source has risk 0.
            (RT.fromList [("201.245.68.1/24",(5,1.1))])  -- Targeted IP range destinations start at risk 5, multiplied by 1.1 for subsequent occurances
            (RT.fromList [("152.70.197.76",2)])          -- Critical IP range sources multiply risk by 2.

-- | Small bit of sample data.
test_data :: ByteString
test_data = pack $ unlines ([ "1333462875\t237.138.224.101\t60.67.159.30",
	"1333462875\t201.210.60.17\t42.191.206.14",
	"1333462875\t175.31.193.20\t185.222.127.117",
	"1333462875\t201.245.68.87\t232.160.236.49",
	"1333462875\t70.139.33.91\t201.245.68.87",
	"1333462875\t171.137.198.31\t250.81.34.31",
	"1333462875\t70.139.33.91\t15.117.211.17",
	"1333462875\t232.160.236.49\t124.141.163.118",
	"1333462875\t237.138.224.101\t70.139.33.91",
	"1333462875\t169.205.36.8\t169.227.145.64",
	"1333462875\t152.70.197.76\t7.244.129.105",
	"1333462875\t171.137.198.31\t232.160.236.49",
	"1333462875\t201.210.60.17\t201.245.68.87",
	"1333462875\t74.112.55.8\t124.141.163.118",
	"1333462875\t1.27.47.96\t169.227.145.64"] :: [String])