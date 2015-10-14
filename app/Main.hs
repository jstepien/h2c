module Main where

import System.Environment
import Lib

main :: IO ()
main = do (host:_) <- getArgs
          talkHTTP2 host
