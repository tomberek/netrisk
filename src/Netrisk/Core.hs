{-# LANGUAGE RankNTypes #-}
{-# LANGUAGE Arrows #-}
{-# LANGUAGE ViewPatterns #-}
{-# LANGUAGE GADTs #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE StandaloneDeriving #-}

module Netrisk.Core (totalRisk,flowParser,RuleSet(..),ruleset) where

import Data.IP.RouteTable as RT
import Data.IP
import Data.Time.Clock.POSIX
import Data.Attoparsec.ByteString.Char8 hiding (take)
import qualified Data.ByteString as B
import Control.Applicative
import Data.HashMap.Strict as H hiding (map,foldl')
import Data.List (foldl')
import Data.Function (on)
import System.Environment (getArgs)
import Control.Parallel.Strategies
import Data.List.Split
import Control.Monad
import GHC.Generics (Generic)
import Data.Hashable

data FlowType = Baseline !Netflow | Targeted !Netflow !(Base,BaseMod) | Critical !FlowType !BaseMod
    deriving (Eq,Ord,Generic)
instance NFData FlowType
instance NFData Netflow
instance NFData IPv4
netflow :: FlowType -> Netflow
netflow (Baseline n) = n
netflow (Targeted n _) = n
netflow (Critical f _) = netflow f

-- | A RuleAuto is an Auto that takes a table from IPv4s to an output, and uses that to convert a FlowType
type Flow= FlowType -> Maybe FlowType
type RuleFlow output = IPRTable IPv4 output -> Flow

{-# INLINE ruleProcessor #-}
-- | Utility to create rules systematically.
ruleProcessor :: (Netflow -> IPv4)          -- ^ selector: picks `source` or `destination`
  -> (FlowType -> Maybe FlowType)           -- ^ bypass: `Just` continues flow, `Nothing` short-ciruits
  -> (FlowType -> output -> Maybe FlowType) -- ^ processor: same as bypass
  -> RuleFlow output
ruleProcessor selector bypass processor table = \flow@(selector . netflow-> selected) -> maybe (bypass flow) (processor flow) (look selected)
  where look selected= RT.lookup (form selected ) table
        form selected = makeAddrRange selected 32

-- | These define the rule precedence and flow through the classify Flow.
whitelist , critical :: RuleFlow Base
targeted :: RuleFlow (Base,BaseMod)
whitelist= ruleProcessor source      Just            (const . const Nothing) 
targeted = ruleProcessor destination (const Nothing) (\flow -> Just . Targeted (netflow flow)) 
critical = ruleProcessor source      Just            (\flow -> Just . Critical flow) 

-- | Takes a ruleset and uses it to analyze categorize a flow.
-- Will shorcircuit on a `Nothing`
classify :: RuleSet -> Flow
classify (RuleSet w t c) = critical c <=< targeted t <=< whitelist w

-- | Uses the output of `counting` to calculate a risk score and sums it.
calcScore :: H.HashMap FlowType Int -> Risk
calcScore flowmap = H.foldlWithKey' (\acc f c -> acc + score f c) 0 flowmap
    where score (Targeted _ (base,basemod)) counter = base * (basemod ^ (counter-1))
          score (Critical flow critmod) counter =  critmod * score flow counter

-- |  Concerts a list of Netflows into  risk with a RuleSet
-- Performs in parallel by splitting up flow into chuncks of 10000
-- to split `map` among cores. `reduce` is done via efficient union
totalRisk :: RuleSet -> [Netflow] -> Risk
totalRisk rules results = calcScore $ foldl' (H.unionWith (+)) H.empty $ parallelFlow results
    where parallelFlow = (withStrategy (parList rdeepseq) 
                       . map (counting . map (classify rules . Baseline))) 
                       . chunksOf 10000

-- | Counts IP Pair occurances. Helper for `totalAuto`
counting :: [Maybe FlowType] -> H.HashMap FlowType Int
counting = foldl' score H.empty
    where
      score state (Just flowtype) = H.insertWith (+) flowtype 1 state
      score state _ = state

-- | Defined ruleset in code. Can obtain via a DSL or config file if needed.
ruleset :: RuleSet
ruleset = RuleSet 
            (RT.fromList [("70.139.33.91",0)])           -- Whitelisted IP source has risk 0.
            (RT.fromList [("201.245.68.1/24",(5,1.1))])  -- Targeted IP range destinations start at risk 5, multiplied by 1.1 for subsequent occurances
            (RT.fromList [("152.70.197.76",2)])          -- Critical IP range sources multiply risk by 2.

-- | There are several kinds of rules;
-- Base is the baseline risk for all traffic.
-- Targeted traffic TO known malware C&C subnets with a baseline risk and modification to additional counts.
-- Critical traffic FROM a crictical host with a modification to risk.
-- Whitelisted traffic FROM a source with a baseline risk.
type Risk       = Double
type Base       = Double
type BaseMod    = Double
type Whitelist  = IPRTable IPv4 Base
type Targeted   = IPRTable IPv4 (Base,BaseMod)
type Critical   = IPRTable IPv4 BaseMod
data RuleSet = RuleSet Whitelist Targeted Critical

data Netflow =
    Netflow { -- time :: !POSIXTime,    NOTE: time not needed for risk calc.
             source :: !IPv4,
             destination :: !IPv4
             } deriving (Show,Eq,Ord,Generic)

-- | Utility and class instances for Netflow
instance Hashable Netflow
instance Hashable IPv4
instance Hashable FlowType

-- *****************************************************
-- Several Parsers for various elements of the log file.
-- *****************************************************
timeParser :: Parser POSIXTime
timeParser = fromIntegral <$> (decimal :: Parser Integer)

ipParser :: Parser IPv4
ipParser = toIPv4 <$> sepBy1 decimal (char '.')

flowParser :: Parser [Netflow]
flowParser = many $ Netflow <$> 
                            ((timeParser <* skipSpace) *> (ipParser <* skipSpace))
                            <*> (ipParser <* endOfLine)