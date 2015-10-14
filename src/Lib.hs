module Lib
    ( talkHTTP2
    ) where

import Prelude hiding ( id )
import Data.Binary
import Data.Char
import Data.Default.Class
import qualified Data.ByteString.Char8 as BC
import qualified Data.ByteString.Lazy.Char8 as BL
import Control.Exception
import Control.Monad
import Network.Socket ( Family( AF_INET )
                      , SocketType( Stream )
                      , SockAddr( SockAddrInet )
                      , defaultProtocol
                      , getAddrInfo
                      , addrAddress
                      , socket
                      , connect
                      )
import Network.TLS
import Network.TLS.Extra.Cipher
import System.X509

tlsParams host port store = params { clientSupported = supported
                                   , clientShared = shared
                                   , clientHooks = hooks
                                   }
  where portString = BC.pack $ show port
        supported = def {supportedCiphers = ciphersuite_strong}
        params = defaultParamsClient host portString
        shared = def { sharedCAStore = store }
        hooks = def { onSuggestALPN = suggest }
        suggest = return $ Just [BC.pack "h2"]

preface = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"

type StreamId = Word32

data Frame = Settings [(Setting, Word32)]
           deriving Show

data Setting = HeaderTableSize
             | EnablePush
             | MaxConcurrentStreams
             | InitialWindowSize
             | MaxFrameSize
             | MaxHeaderListSize
             deriving Show

instance Binary Setting where
    put _ = undefined
    get = do id <- get :: Get Word16
             case fromId id of
               Just setting -> return setting
               Nothing      -> fail $ "invalid setting: " ++ show id
        where fromId 3 = Just MaxConcurrentStreams
              fromId 4 = Just InitialWindowSize
              fromId 5 = Just MaxFrameSize
              fromId _ = Nothing

data StreamFrame = StreamFrame StreamId Frame
                 deriving Show

getFrame 4 len = settings len []
    where settings 0    kvs = return $ Settings kvs
          settings left kvs = do k <- get
                                 v <- get
                                 settings (left - 6) $ (k, v):kvs
getFrame ty _  = fail $ "invalid frame type: " ++ show ty

instance Binary StreamFrame where
    put _ = undefined
    get = do len <- getWord24
             fType <- getWord8
             -- Ignore flags as per the spec
             _ <- getWord8
             streamId <- get
             frame <- getFrame fType len
             return $ StreamFrame streamId frame
        where getWord24 = liftM3 (\a b c -> ((a * 0x100) + b) * 0x100 + c)
                                 getW8asW32 getW8asW32 getW8asW32
              getW8asW32 = fromIntegral `fmap` getWord8 :: Get Word32

talkHTTP2 :: String -> IO ()
talkHTTP2 hostname = do
    (addrInfo:_) <- getAddrInfo Nothing (Just hostname) Nothing
    store <- getSystemCertificateStore
    let (SockAddrInet _ host) = addrAddress addrInfo
        port = 443
        addr = SockAddrInet port host
        params = tlsParams hostname port store
    rawSock <- socket AF_INET Stream defaultProtocol
    connect rawSock addr
    tlsCtx <- contextNew rawSock params
    handshake tlsCtx
    sendData tlsCtx $ BL.pack preface
    _ <- forever $ catch (receive tlsCtx) (\e -> print (e :: SomeException))
    bye tlsCtx
    where receive ctx = do frame <- recvData ctx
                           print $ length $ BC.unpack frame
                           print $ map ord $ BC.unpack frame
                           print (decode (BL.fromStrict frame) :: StreamFrame)
