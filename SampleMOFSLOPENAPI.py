from MOFSLOPENAPI import MOFSLOPENAPI
ApiKey = "NULL" 
userid = "" 
password = ""   
Two_FA = ""
vendorinfo = ""
clientcode = None 
SourceID = "Desktop"            
browsername = "chrome"      
browserversion = "104"      
totp = ""
Base_Url = "https://uatopenapi.motilaloswal.com"
Mofsl = MOFSLOPENAPI(ApiKey, Base_Url, clientcode, SourceID, browsername, browserversion)
Mofsl.login(userid, password, Two_FA, totp, vendorinfo)
 
def Broadcast_on_open(ws1):
    Mofsl.Register("NSE", "CASH", 11536)

def Broadcast_on_message(ws1, message_type, message):
    if message_type == "Index":
        print(message)
    elif(message_type == "LTP"):
        print(message)
    elif(message_type == "MarketDepth"):
        print(message)
    elif(message_type == "DayOHLC"):
        print(message)
    elif(message_type == "DPR"):
        print(message)
    elif(message_type == "OpenInterest"):
        print(message)
    else:
        print(message)

def Broadcast_on_close(ws1, close_status_code, close_msg):
    print("Close Message : %s" %(close_msg))
    print("Close Message Code : %s" %(close_status_code)) 

def TradeStatus_on_open(ws2):
    Mofsl.Tradelogin()
    Mofsl.OrderSubscribe()
    Mofsl.TradeSubscribe()

def TradeStatus_on_message(ws2, message_type, message):
    if message_type == "TradeStatus":
        print(message)
    
def TradeStatus_on_close(ws2, close_status_code, close_msg):
    print("Close Message : %s" %(close_msg))
    print("Close Message Code : %s" %(close_status_code)) 

Mofsl._Broadcast_on_open = Broadcast_on_open
Mofsl._Broadcast_on_message = Broadcast_on_message
Mofsl._Broadcast_on_close = Broadcast_on_close

Mofsl._TradeStatus_on_open = TradeStatus_on_open
Mofsl._TradeStatus_on_message = TradeStatus_on_message
Mofsl._TradeStatus_on_close = TradeStatus_on_close


Mofsl.TradeStatus_connect()
Mofsl.Broadcast_connect()
